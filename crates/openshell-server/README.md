<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# OpenShell gateway server

The server owns control-plane RPCs, authentication, provider credential delivery,
and sandbox lifecycle orchestration. The `openshell-gateway` crate composes the
server with selected compute drivers.

## Sandbox launch identity

A new start, including an automatic restart, commits a fresh runtime generation
and an incremented authorization epoch before invoking the compute driver.
The launch session ID is derived from the durable sandbox ID and generation.
Retries reuse that generation and session, including after gateway restart.
Credential renewal retains both; credentials for an older launch cannot
authorize the new one.

## Runtime restart policy

Besides canonical main-process exits, `Always` and `OnFailure` may replace a
narrowly driver-reported terminated admitted runtime without a canonical result.
For Kubernetes, this requires a live terminal supervisor observation with the
admitted Pod identities and enforcement fences intact. The gateway uses the
existing fenced Stop/Start path with a fresh generation and paired credentials;
it does not infer a command exit code. `Never`, explicit Stop/Delete and recorded
canonical terminal results are not revived by this infrastructure-loss path.
Generic missing runtimes remain distinct: retained missing compute is reported
as `Error/ComputeResourceMissing` and requires explicit Start as described below.

## Persistent sandbox intent

Native create requests may set `openshell.nvidia.com/retention=persistent` in
`annotations`. This retains the durable sandbox ID, specification, settings and
SSH identity when the compute watch or reconciliation sweep observes a missing
runtime. Stopped/Completed intent stays stopped/terminal; other runtime loss is
reported as `Error` with `Ready=False/ComputeResourceMissing`. Start recreates
missing compute using the retained specification and a fresh runtime generation.
Each new Start rotates the runtime generation and native credentials, including
when restarting the same stopped container. An authoritative missing-runtime
response claims recovery Create with a new generation atomically. The gateway
does not automatically relaunch a user-stopped sandbox.

A failed create retains `Error/ProvisioningFailed` and uses owned Stop compensation
instead of deletion. Explicit Start also retries asynchronous driver infrastructure
errors (such as image/container preparation failures) without changing their
reported diagnostic. A retry quiesces leftovers before starting/recreating compute.
Unresolved driver operations remain fail-closed under existing provisioning
ownership; no lease expiry or missing runtime establishes that an external request
has settled. Explicit `Deleting` remains authoritative and releases owned backing
resources. A missing row by itself does not authorize persistent-data deletion.

`DeleteSandbox` with `keep_workspace` keeps the workspace volume for the next
sandbox of the same name in the same workspace. The gateway refuses it with
`FAILED_PRECONDITION` before any change when the driver does not report
`supports_workspace_keep`, records the choice with the durable `Deleting` phase
so that a reasserted delete keeps the volume too, and refuses a second delete
that would decide differently while the first is pending.

Retention does not provide durable storage. For Docker, also enable the native
`persistent_workspace` option; see the Docker driver README. Runtime labels prove
backing-resource ownership, not desired lifecycle. Ordinary and ephemeral sandbox
semantics remain unchanged. Workload-template annotations are not inherited by a
create request.

## Native forwarding readiness

`ForwardTcp` returns a successful RPC response only after the supervisor has
connected the requested loopback/SSH target and claimed the existing native relay.
The relay claim keeps its ten-second open deadline. Authorization, target-open
failure, timeout and cancellation release the per-connection guard; a successful
stream retains it until forwarding ends. Dropping the response cancels both scoped
transfer directions even when the target remains idle. Request EOF half-closes
the target's input while retaining its pending response. No application data or
health endpoint is needed to establish TCP connectivity. This does not establish application
protocol health, and `SandboxPhase::Ready` alone still describes sandbox readiness.

## Operator credential export

`GetProviderCredentials` exports selected profile-declared runtime environment
keys from one provider in an explicitly named workspace. It requires the distinct
`Principal::Operator`, established only from a verified TLS leaf certificate with
`OU=operator` when `mtls_auth.operator_enabled` is enabled. The TLS listener supplies
its certificate fingerprint separately from user identity; the ordinary
identity-only serving path cannot establish an operator.

Operators explicitly inherit user/platform-admin permissions, but not sandbox or
peer identities. Descriptor authorization and a handler guard both protect the
export RPC. Operator mutation admission uses a separate caller namespace from
ordinary mTLS users with the same certificate subject. Credential responses never
enter durable mutation replay or generic interceptor routing.

The export resolver validates the entire selection before minting, resolves only
selected credential handles, and fences provider revisions, refresh epochs, and
profile declarations before delivery. Driver expiration and provider expiration
combine using the earlier timestamp. OAuth minting inputs, broker-only keys, and
supervisor-bound dynamic grants are not exportable. A failed response can still
have committed refresh effects. Missing refresh-owned stored outputs trigger
refresh-on-read; missing static outputs and other credential-backend errors fail
closed without falling back to inline values.

## Refresh coordination

Explicit rotation, background refresh, and operator refresh-on-read share the
same refresh coordination:

- A process-local weak keyed mutex coalesces waiters without retaining deleted
  providers indefinitely.
- A bounded admission queue and executor pool limit detached refresh work.
- PostgreSQL deployments also take a dedicated per-provider/per-credential
  advisory lock; SQLite uses the local mutex. Worker secret cleanup takes the
  same locks and reloads state before changing its resource version.
- A durable `refresh_in_progress` marker precedes upstream minting. A
  `refresh_committing` marker protects the interval between grant persistence
  and provider-handle persistence. Only a completed provider commit publishes
  `refreshed` state, with a unique completed-mint identity in metadata
  annotations. Waiters coalesce against that identity, not bookkeeping changes
  to the resource version.
- Automatic callers recheck live recovery and retry deadlines under both locks.
  A failed mint blocks queued automatic exchanges without disabling scheduled
  worker retries or a separately requested manual rotation.
- Detached refresh tasks complete despite request cancellation, preserving
  replacement refresh tokens returned by the issuer.
- Existing generation/CAS fencing remains active for deletion and
  reconfiguration. An ambiguous rotating-token exchange is parked for recovery
  rather than automatically consuming the grant again.

A crash or lost database-lock session can leave a parked marker. Reconfigure or
reauthorize the refresh grant after investigating its issuer state. Changing a
marker directly is not a supported recovery workflow.

## Sandbox activity

`SandboxStatus.last_activity_time` is the latest time the supervisor reported
allowed network traffic from the sandbox. The supervisor's activity aggregator
counts every proxied connection and L7 request, allowed or denied, and sends a
`NetworkActivitySummary` every 10 seconds when the count is not zero. A report
whose count exceeds its denials is activity; denied attempts alone are not, so a
workload retrying a blocked destination still reads as idle. A long-lived
connection counts once, when it opens, and inbound traffic through forwards or
services does not count.

The record is gateway-owned durable state, like the restart fields: driver
snapshots carry it over, and it survives gateway restarts. A record younger than
one minute is kept, so a busy sandbox writes at most once a minute. The write
takes the sandbox's mutation guard and is best effort: a lock timeout, a
concurrent change or a deleted sandbox skips it, and the report still succeeds.
Clients use it with their own traffic to decide how long a sandbox has been idle.

## Focused verification

```shell
cargo test -p openshell-server --features test-support,prebuilt-z3
cargo clippy -p openshell-server --all-targets --features test-support,prebuilt-z3 -- -D warnings
```

The ignored `postgres_refresh_locks_coordinate_independent_replica_sessions` test
runs under `mise run test:rust:postgres` (see `TESTING.md`) and still accepts
`OPENSHELL_REFRESH_TEST_DATABASE_URL` pointing to a disposable PostgreSQL database.
It exercises independent sessions without the local mutex. Do not point this
fixture at an existing deployment database.
