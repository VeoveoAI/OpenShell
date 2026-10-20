// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Durable sandbox intent, independent of the driver's transient runtime objects.

use std::collections::HashMap;

use openshell_core::proto::{Sandbox, SandboxCondition, SandboxPhase};
use openshell_core::{ObjectId, ObjectName};
use tonic::{Code, Request, Status};

use super::{
    ComputeRuntime, SandboxLifecycleGuard, provisioning_operation, sandbox_resource_version,
    upsert_ready_condition,
};
use openshell_core::proto::compute::v1::StopSandboxRequest;

pub const RETENTION_ANNOTATION: &str = "openshell.nvidia.com/retention";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SandboxRetention {
    #[default]
    Ordinary,
    Ephemeral,
    Persistent,
}

impl SandboxRetention {
    pub(crate) fn parse(annotations: &HashMap<String, String>) -> Result<Self, Status> {
        match annotations.get(RETENTION_ANNOTATION).map(String::as_str) {
            None => Ok(Self::Ordinary),
            Some("ephemeral") => Ok(Self::Ephemeral),
            Some("persistent") => Ok(Self::Persistent),
            Some(_) => Err(Status::invalid_argument(
                "openshell.nvidia.com/retention must be ephemeral or persistent when supplied",
            )),
        }
    }

    pub(super) fn of(sandbox: &Sandbox) -> Result<Self, Status> {
        sandbox
            .metadata
            .as_ref()
            .map_or(Ok(Self::Ordinary), |metadata| {
                Self::parse(&metadata.annotations)
            })
    }
}

pub(super) fn is_persistent(sandbox: &Sandbox) -> bool {
    matches!(
        SandboxRetention::of(sandbox),
        Ok(SandboxRetention::Persistent)
    )
}

pub(super) fn retained_create_failed(sandbox: &Sandbox) -> bool {
    is_persistent(sandbox) && has_error_reason(sandbox, "ProvisioningFailed")
}

/// Explicit Start may retry persistent infrastructure errors, including an
/// asynchronous driver provisioning failure reported after Create accepted.
/// Canonical process exits and deadline reclamation retain their own paths.
pub(super) fn retained_infrastructure_error(sandbox: &Sandbox) -> bool {
    is_persistent(sandbox)
        && super::has_specific_infrastructure_error(sandbox)
        && !super::is_failed_main_process_result(sandbox)
        && !super::provisioning_deadline::timed_out(sandbox)
}

pub(super) fn retained_runtime_missing(sandbox: &Sandbox) -> bool {
    is_persistent(sandbox) && has_error_reason(sandbox, "ComputeResourceMissing")
}

fn has_error_reason(sandbox: &Sandbox, reason: &str) -> bool {
    sandbox.phase() == i32::from(SandboxPhase::Error)
        && sandbox.status.as_ref().is_some_and(|status| {
            status
                .conditions
                .iter()
                .any(|condition| condition.r#type == "Ready" && condition.reason == reason)
        })
}

impl ComputeRuntime {
    /// Only a known `NotFound` permits recovery Create. The first Start
    /// operation has settled; the CAS below checks its exact identity and claims
    /// recovery Create together, fencing cross-replica retries before dispatch.
    pub(super) async fn recreate_missing_persistent_sandbox(
        &self,
        lifecycle_guard: &SandboxLifecycleGuard,
        settled: &Sandbox,
        authority: Option<&crate::auth::sandbox_jwt::SandboxSessionJwtAuthority>,
    ) -> Result<
        (
            tonic::Response<openshell_core::proto::compute::v1::StartSandboxResponse>,
            Box<Sandbox>,
        ),
        provisioning_operation::ProvisioningOperationError,
    > {
        use provisioning_operation::ProvisioningOperationError;
        let sandbox_guard = self.lock_sandbox_for_lifecycle(lifecycle_guard).await;
        let current = self
            .store
            .get_message::<Sandbox>(settled.object_id())
            .await
            .map_err(|error| {
                ProvisioningOperationError::Monitor(Status::internal(error.to_string()))
            })?
            .ok_or_else(|| {
                ProvisioningOperationError::Monitor(Status::not_found(
                    "sandbox removed before recovery Create",
                ))
            })?;
        provisioning_operation::ensure_current_result(&current, settled)
            .map_err(ProvisioningOperationError::Monitor)?;
        if current.phase() != i32::from(SandboxPhase::Starting) || !is_persistent(&current) {
            return Err(ProvisioningOperationError::Monitor(Status::aborted(
                "sandbox lifecycle changed before recovery Create",
            )));
        }
        let version = sandbox_resource_version(&current);
        let identity =
            super::next_runtime_identity(&current).map_err(ProvisioningOperationError::Monitor)?;
        let mut armed = current.clone();
        let metadata = armed.metadata.as_mut().ok_or_else(|| {
            ProvisioningOperationError::Monitor(Status::failed_precondition(
                "sandbox metadata missing",
            ))
        })?;
        identity.write(&mut metadata.annotations);
        let authentication = authority
            .map(|authority| authority.mint_persisted_launch(armed.object_id(), &identity))
            .transpose()
            .map_err(ProvisioningOperationError::Monitor)?;
        // Match native Create: the driver bootstrap file carries the gateway
        // token from this exact launch bundle, never a public Sandbox field.
        let sandbox_token = authentication.as_ref().map(|authentication| {
            authentication
                .supervisor
                .gateway_token
                .expose_secret()
                .to_string()
        });
        let launch = if let Some(authentication) = authentication {
            self.encode_launch_authentication(&armed, authentication)
                .await
                .map_err(ProvisioningOperationError::Monitor)?
        } else {
            Vec::new()
        };
        let mut driver_sandbox = self
            .driver_sandbox_for_launch(&armed)
            .map_err(ProvisioningOperationError::Monitor)?;
        if let Some(spec) = driver_sandbox.spec.as_mut() {
            spec.launch_authentication = launch;
            spec.sandbox_token = sandbox_token.unwrap_or_default();
        }
        let claimed = self
            .store
            .update_message_cas::<Sandbox, _>(current.object_id(), version, move |sandbox| {
                if let Some(metadata) = sandbox.metadata.as_mut() {
                    identity.write(&mut metadata.annotations);
                }
                provisioning_operation::claim_record(sandbox);
            })
            .await
            .map_err(|error| {
                ProvisioningOperationError::Monitor(crate::grpc::persistence_error_to_status(
                    error,
                    "claim recovery Create",
                ))
            })?;
        self.sandbox_index.update_from_sandbox(&claimed);
        self.sandbox_watch_bus.notify(claimed.object_id());
        drop(sandbox_guard);
        let driver = self.driver.clone();
        let id = claimed.object_id().to_string();
        self.await_claimed_provisioning_operation(&claimed, async move {
            driver
                .call_owned(
                    openshell_otel::rpc::CREATE_SANDBOX,
                    Some(&id),
                    move |driver| async move {
                        let response = driver
                            .create_sandbox(Request::new(
                                openshell_core::proto::compute::v1::CreateSandboxRequest {
                                    sandbox: Some(driver_sandbox),
                                },
                            ))
                            .await?;
                        Ok(tonic::Response::new(
                            openshell_core::proto::compute::v1::StartSandboxResponse {
                                runtime_identity: response.into_inner().runtime_identity,
                            },
                        ))
                    },
                )
                .await
        })
        .await
    }

    /// Called under the sandbox mutation lock. A missing runtime is not deletion
    /// intent. Preserve the row, SSH identity, settings and stable data identity;
    /// only disconnect sessions belonging to the vanished runtime.
    pub(super) async fn retain_missing_runtime_locked(
        &self,
        sandbox: &Sandbox,
    ) -> Result<(), String> {
        self.cleanup_stopped_sandbox_sessions(sandbox).await?;
        let phase = SandboxPhase::try_from(sandbox.phase()).unwrap_or(SandboxPhase::Unknown);
        if matches!(phase, SandboxPhase::Stopped | SandboxPhase::Completed)
            || retained_create_failed(sandbox)
            || retained_runtime_missing(sandbox)
        {
            return Ok(());
        }
        let updated = self.store.update_message_cas::<Sandbox, _>(
            sandbox.object_id(), sandbox_resource_version(sandbox), |sandbox| {
                // Absence completes a concurrent Stop, rather than reviving its
                // prior running intent. Deleting never enters this helper.
                let phase = if phase == SandboxPhase::Stopping { SandboxPhase::Stopped } else { SandboxPhase::Error };
                sandbox.set_phase(i32::from(phase));
                upsert_ready_condition(&mut sandbox.status, SandboxCondition {
                    r#type: "Ready".to_string(), status: "False".to_string(),
                    reason: "ComputeResourceMissing".to_string(),
                    message: "The persistent sandbox runtime is missing; start recreates it using the retained sandbox identity and specification".to_string(),
                    transition_time: None,
                });
            }
        ).await.map_err(|error| error.to_string())?;
        self.sandbox_index.update_from_sandbox(&updated);
        self.sandbox_watch_bus.notify(sandbox.object_id());
        Ok(())
    }

    pub(super) async fn retain_failed_create(
        &self,
        created: &Sandbox,
        _lifecycle_guard: SandboxLifecycleGuard,
        sandbox_guard: super::LocalMutationGuard,
        original: Status,
    ) -> Status {
        let result = async {
            let current = self.store.get_message::<Sandbox>(created.object_id()).await
                .map_err(|error| Status::internal(format!("fetch persistent sandbox: {error}")))?
                .ok_or_else(|| Status::not_found("sandbox removed during create"))?;
            provisioning_operation::ensure_current_result(&current, created)?;
            if !matches!(SandboxPhase::try_from(current.phase()), Ok(SandboxPhase::Provisioning | SandboxPhase::Ready | SandboxPhase::Starting)) {
                return Err(Status::aborted("sandbox lifecycle changed before failed-create cleanup"));
            }
            let failed = self.store.update_message_cas::<Sandbox, _>(
                current.object_id(), sandbox_resource_version(&current), |sandbox| {
                    sandbox.set_phase(i32::from(SandboxPhase::Error));
                    upsert_ready_condition(&mut sandbox.status, SandboxCondition {
                        r#type: "Ready".to_string(), status: "False".to_string(),
                        reason: "ProvisioningFailed".to_string(),
                        message: "Persistent sandbox creation failed; start retries with the retained identity and specification".to_string(),
                        transition_time: None,
                    });
                    // Claim compensation together with its phase. A different
                    // replica cannot start/delete while Stop is still pending.
                    provisioning_operation::claim_record(sandbox);
                }
            ).await.map_err(|error| Status::internal(format!("retain persistent sandbox: {error}")))?;
            self.sandbox_index.update_from_sandbox(&failed);
            self.sandbox_watch_bus.notify(failed.object_id());
            Ok(failed)
        }.await;
        drop(sandbox_guard);
        let failed = match result {
            Ok(failed) => failed,
            Err(error) => return error,
        };
        let driver = self.driver.clone();
        let sandbox_id = failed.object_id().to_string();
        let sandbox_name = failed.object_name().to_string();
        let request_id = sandbox_id.clone();
        // Bound the caller's wait without canceling the actual Stop. The
        // native owned worker survives this future and keeps its durable claim
        // until the unfenced remote operation really returns.
        let cleanup = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            self.await_claimed_provisioning_operation(&failed, async move {
                let result = driver
                    .call_owned(
                        openshell_otel::rpc::STOP_SANDBOX,
                        Some(&sandbox_id),
                        move |driver| async move {
                            driver
                                .stop_sandbox(Request::new(StopSandboxRequest {
                                    sandbox_id: request_id,
                                    name: sandbox_name,
                                }))
                                .await
                        },
                    )
                    .await;
                match result {
                    Ok(_) => Ok(()),
                    Err(error) if error.code() == Code::NotFound => Ok(()),
                    Err(error) => Err(error),
                }
            }),
        )
        .await;
        match cleanup {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                let error: Status = error.into();
                return Status::new(
                    original.code(),
                    format!(
                        "{}; persistent sandbox retained; stop cleanup requires retry: {}",
                        original.message(),
                        error.message(),
                    ),
                );
            }
            Err(_) => {
                return Status::new(
                    original.code(),
                    format!(
                        "{}; persistent sandbox cleanup is still pending; retry remains blocked until driver settlement",
                        original.message(),
                    ),
                );
            }
        }
        original
    }
}
