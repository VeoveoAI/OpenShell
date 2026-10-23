// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The sandbox's last network activity, recorded from the supervisor's
//! periodic activity summaries into `SandboxStatus.last_activity_time`.
//!
//! The supervisor reports allowed and denied network events in windows of
//! ten seconds. The gateway stores the time of the latest window that held
//! allowed traffic, so a client can tell how long a sandbox has been idle
//! across gateway restarts. A record younger than [`ACTIVITY_RECORD_INTERVAL`]
//! is kept, which bounds the store writes of a busy sandbox to one a minute.
//! The record is best effort: a failure is logged and never fails the report.

use crate::ServerState;
use crate::compute::MutationScope;
use crate::persistence::{ObjectId, ObjectWorkspace};
use openshell_core::GetResourceVersion;
use openshell_core::proto::{NetworkActivitySummary, Sandbox};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tracing::debug;

/// The precision of a recorded activity time.
pub(super) const ACTIVITY_RECORD_INTERVAL: Duration = Duration::from_mins(1);

/// Whether a report holds allowed traffic: a proxied connection that opened or
/// an L7 request that was forwarded. Denied attempts do not count, so a
/// workload that keeps retrying a blocked destination still reads as idle.
pub(super) fn reports_activity(summaries: &[NetworkActivitySummary]) -> bool {
    summaries
        .iter()
        .any(|summary| summary.network_activity_count > summary.denied_action_count)
}

/// Whether the sandbox holds a record younger than the record interval. A
/// record from the future, after a clock step back, also counts as recent so
/// that it is replaced once the clock passes it.
fn recorded_since(sandbox: &Sandbox, now: SystemTime) -> bool {
    let Some(recorded) = sandbox
        .status
        .as_ref()
        .and_then(|status| status.last_activity_time.as_ref())
        .and_then(|time| openshell_core::time::system_time_from_timestamp(time).ok())
    else {
        return false;
    };
    now.duration_since(recorded)
        .map_or(true, |age| age < ACTIVITY_RECORD_INTERVAL)
}

/// Record `now` as the sandbox's last activity unless a recent record exists.
pub(super) async fn record_activity(state: &Arc<ServerState>, sandbox: &Sandbox, now: SystemTime) {
    if sandbox.status.is_none() || recorded_since(sandbox, now) {
        return;
    }
    let sandbox_id = sandbox.object_id();
    let Ok(time) = openshell_core::time::timestamp_from_system_time(now) else {
        return;
    };
    // A supervisor report is a sandbox mutation like any other and takes the
    // sandbox's guard, so it never races a lifecycle write.
    let _guard = match state
        .compute
        .mutation_guard(MutationScope::sandbox(
            sandbox.object_workspace(),
            sandbox_id,
        ))
        .await
    {
        Ok(guard) => guard,
        Err(error) => {
            debug!(sandbox_id, %error, "Skipped sandbox activity record: mutation lock");
            return;
        }
    };
    let current = match state.store.get_message::<Sandbox>(sandbox_id).await {
        Ok(Some(current)) => current,
        Ok(None) => return,
        Err(error) => {
            debug!(sandbox_id, %error, "Skipped sandbox activity record: read");
            return;
        }
    };
    if current.status.is_none() || recorded_since(&current, now) {
        return;
    }
    match state
        .store
        .update_message_cas::<Sandbox, _>(sandbox_id, current.get_resource_version(), |sandbox| {
            if let Some(status) = sandbox.status.as_mut() {
                status.last_activity_time = Some(time);
            }
        })
        .await
    {
        Ok(updated) => {
            state.sandbox_index.update_from_sandbox(&updated);
            state.sandbox_watch_bus.notify(sandbox_id);
        }
        Err(error) => debug!(sandbox_id, %error, "Skipped sandbox activity record: write"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(allowed: u32, denied: u32) -> NetworkActivitySummary {
        NetworkActivitySummary {
            network_activity_count: allowed + denied,
            denied_action_count: denied,
            denials_by_group: Vec::new(),
        }
    }

    #[test]
    fn only_allowed_traffic_is_activity() {
        assert!(reports_activity(&[summary(1, 0)]));
        assert!(reports_activity(&[summary(0, 4), summary(2, 1)]));
        assert!(!reports_activity(&[summary(0, 3)]));
        assert!(!reports_activity(&[]));
    }

    #[test]
    fn a_record_is_recent_for_one_interval() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_hours(500_000);
        let mut sandbox = Sandbox::default();
        sandbox.set_phase(1);
        assert!(!recorded_since(&sandbox, now));
        let record =
            |at: SystemTime| Some(openshell_core::time::timestamp_from_system_time(at).unwrap());
        let status = sandbox.status.as_mut().unwrap();
        status.last_activity_time = record(now - ACTIVITY_RECORD_INTERVAL + Duration::from_secs(1));
        assert!(recorded_since(&sandbox, now));
        sandbox.status.as_mut().unwrap().last_activity_time =
            record(now - ACTIVITY_RECORD_INTERVAL);
        assert!(!recorded_since(&sandbox, now));
        sandbox.status.as_mut().unwrap().last_activity_time = record(now + Duration::from_secs(5));
        assert!(recorded_since(&sandbox, now));
    }
}
