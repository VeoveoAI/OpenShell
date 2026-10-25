# openshell-driver-kubernetes

Kubernetes-backed compute driver for OpenShell cluster deployments.

Caller driver config is disabled by default. External resource references need
administrator-controlled approval labels in every workspace mode, including
before restart and scheduling-gate release. GPU devices are temporarily exempt.
Image-pull Secrets are operator-selected gateway configuration rather than caller
attachments. Managed mode stages an immutable copy for each sandbox runtime
generation.
See [resource admission configuration](../../docs/how-it-works/gateways/configuration.mdx#external-resource-admission).

Caller PVC mounts cannot overlap the driver-managed `/.openshell` control tree
or `/run`, including nested `subPath` mounts. Resource approval labels do not
permit mounting over these paths. Use data paths such as `/data` or a directory
below `/sandbox`.

The driver uses the Kubernetes API to create, delete, fetch, and watch sandbox
custom resources. It runs in-process with the gateway server and supports three
workspace namespace modes via `workspace_mode`:

- **Shared** (default): All sandboxes render into a single static namespace.
  Resource names use `{workspace}--{name}` for collision avoidance.
- **Managed**: The driver auto-creates/deletes a K8s namespace per workspace
  (`openshell-{gateway_id}-{workspace_name}`) and creates a ServiceAccount in
  each. On OpenShift, it leaves SCC annotations to the namespace allocator and
  waits for the namespace's own MCS, UID-range, and supplemental-group
  annotations before provisioning sandbox resources. An existing namespace with
  a UID range but no MCS must be recreated so OpenShift can allocate a complete
  set of SCC annotations.
- **Operator**: Workspace names map 1:1 to pre-provisioned namespaces discovered
  through exactly one source: either a label selector
  (`operator_namespace_label`) or a drop-in allowlist file
  (`operator_namespace_file`). Sandbox creation fails closed if the workspace
  namespace is not in the current allowlist. With a label selector, workspace
  checks that run before the watcher's first namespace listing wait up to 10
  seconds for it and then return `Unavailable`, so a gateway restart does not
  reject labeled workspaces as unknown. Workspace deletion only removes
  gateway state; it never deletes or otherwise accesses the operator-managed
  Kubernetes namespace.

When the gateway configures `[openshell.gateway.otlp]`, Kubernetes
compute-driver spans export to the same OTLP/gRPC collector with the service
name `openshell-driver-kubernetes`. The driver preserves the gateway trace
context and uses the same compute-driver RPC span names in its in-process and
standalone forms. Standalone deployments set `--gateway-name` or
`OPENSHELL_GATEWAY_NAME` so exported spans carry the same
`openshell.gateway.name` resource attribute as gateway spans.

When it creates an Agent Sandbox resource, the driver serializes the active W3C
trace context into the controller-reserved `opentelemetry.io/trace-context`
annotation. An OTLP-enabled Agent Sandbox controller can therefore attach its
asynchronous reconciliation spans to the originating OpenShell create trace.

Workspace namespace modes assume exclusive control of the sandbox identity
resource chain. In shared and managed modes, only the driver and its trusted
Agent Sandbox controller may administer the sandbox namespace, Sandbox CRs,
sandbox pods, or configured sandbox ServiceAccount. In operator mode, the
platform operator owns namespace lifecycle but must prevent other principals
from creating or mutating Sandbox CRs, creating sandbox pods with fabricated
owner references, or using the configured sandbox ServiceAccount. Treat adding
a namespace to the operator allowlist as granting this trust; the allowlist is
not a tenant isolation boundary.

## Runtime Model

The gateway stores platform state and delegates sandbox workload creation to
this driver. Kubernetes owns scheduling and pod lifecycle. The workload Pod
stages the statically linked musl `openshell-sandbox` binary from
`sandbox_runtime_image`, while a directly managed Pod runs the dynamically
linked glibc `openshell-supervisor` from `supervisor_image`.

The sandbox owns the agent process, applies Landlock and child seccomp filters,
identifies the binary behind each network syscall, and relays mediated streams
to the supervisor. The supervisor authenticates to the gateway with a JWT,
loads policy and provider state, performs destination and L7 authorization, and
opens upstream connections. The workload receives no gateway credential,
provider identity socket, or corporate-proxy credential.

Both Pods run as the namespace-resolved non-root UID/GID with
`allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, and the runtime
default seccomp profile. The sandbox installs a nested seccomp user-notification
filter without requesting a capability in the Pod spec. Startup fails closed
when the runtime blocks the required seccomp or Landlock operations.

The supervisor Pod has a direct, non-controller owner reference to the Sandbox
resource. This links its garbage-collection lifecycle to the sandbox without
competing with the Agent Sandbox controller for workload-Pod ownership.

When the gateway exports OTLP traces, the driver sets
`OPENSHELL_OTLP_ENDPOINT` on the supervisor Pod to the gateway's endpoint and
`TRACEPARENT` to the trace context of the operation that created the Pod. The
supervisor exports its spans there and parents its startup span on that
context. The endpoint is not configurable in driver TOML.

The driver creates one namespace-wide `NetworkPolicy` before it releases any
workload Pod. It selects every OpenShell workload, denies all workload egress,
and permits OpenShell supervisor Pods to reach the sandbox TLS port. The
authenticated Sandbox Protocol binds each connection to the exact sandbox and
supervisor Pod identities. Supervisors have normal egress for gateway, DNS,
and policy-approved upstream connections unless an operator policy restricts
them. The cluster CNI must enforce ingress and egress `NetworkPolicy` for every
sandbox namespace. Kubernetes accepts policy objects without confirming
enforcement, so operators must verify CNI support before running sandboxes.

Each sandbox generation uses two immutable bootstrap Secrets. A trusted init
container stages the sandbox bootstrap into memory, and the sandbox removes it
before starting untrusted code. The other Secret is mounted only by the
supervisor; when `proxy_ca_bundle` is configured it also carries the operator's
corporate proxy CA bundle, which the gateway reads from its own filesystem so
the anchor stays in the gateway's trust domain rather than the sandbox
namespace. The TLS channel binds the namespace, Sandbox CR, workload Pod,
supervisor Pod, and shared network-policy identities. Stop deletes the workload
and supervisor Pods. Start rotates both Secrets and creates a new supervisor
Pod before releasing a new workload Pod. It also renders the trusted init
container again from gateway config, so a sandbox created by an older gateway
starts with the current sandbox runtime image. The shared network fence
remains for the lifetime of the namespace.

Kubernetes policies are additive, and the API does not attest that the CNI
enforces them. Keep sandbox namespaces administrative: untrusted principals
must not create permissive policies, create Pods, read bootstrap Secrets, or
spoof the OpenShell role labels. Exact supervisor-to-sandbox authorization is
still enforced by TLS, JWT claims, session generation, and recorded Pod UIDs.

## Sandbox Resource

The driver works with the `agents.x-k8s.io` `Sandbox` custom resource. It
detects the served Sandbox API at runtime, caches the selected API version for
the gateway process, and uses `v1beta1` when available before falling back to
`v1alpha1`. Restart the gateway after an in-place Agent Sandbox upgrade so the
driver can detect served API versions again. Driver events map Kubernetes object
state and platform events into the shared compute-driver protobuf surface used
by the gateway.

Kubernetes API calls use explicit timeouts so gRPC handlers do not block
indefinitely when the API server is slow or unavailable. The request client's
timeout starts when each request is sent, so time a pooled connection spends
idle does not shorten it. Resource and Event
watches recover in place with API-friendly backoff after transient watcher
errors, avoiding a gateway-side watch restart and its associated watch gap.

## Runtime Recovery

Workload and supervisor Pods use `restartPolicy: Never`: their bootstrap belongs
only to the admitted runtime generation. A same-UID supervisor in `Pending` or
unready `Running` is reconciling, so readiness remains unavailable without
changing desired running intent. If the admitted supervisor becomes terminal
(`Failed` or `Succeeded`), with the exact workload/supervisor UIDs and namespace
fence generation still present, the driver publishes `SandboxRuntimeTerminated`
instead of suspending the Sandbox. The gateway applies its existing
`Always`/`OnFailure` policy and fenced STOP → fresh paired credentials → START
sequence. This infrastructure loss has no inferred canonical process exit code.
Before loss publication, the same verified terminal generation projects as
`DependenciesNotReady`; stale v1beta1 `Suspended` status cannot overwrite its
still-running desired intent.

Missing/deleting Pods, changed identities and missing or altered enforcement
fences retain their fail-closed paths. Explicit Stop/Delete, `Never`, and a
recorded canonical command completion are not revived by infrastructure
recovery. A queued old terminal observation is re-read under the gateway's
lifecycle gate before scheduling replacement. Replacement Pods and runtime
identities change; retained workspace claims are reused. These source semantics
still require deployed reboot qualification.

## Workspace Persistence

Sandbox pods use a PVC-backed `/sandbox` workspace. An init container seeds the
PVC from the image's original `/sandbox` contents on first start and writes a
sentinel so subsequent starts skip the copy.

This is a stopgap persistence model. It preserves user files across pod
rescheduling but duplicates the base workspace and does not automatically apply
image updates to existing PVCs. Future snapshotting should replace it.

Stop preserves the Agent Sandbox resource and workspace PVC while stopping
its pod. The driver sets `spec.operatingMode: Suspended` for `v1beta1` or
`spec.replicas: 0` for `v1alpha1`. Start sets `Running` or one replica for the
same resource, so the replacement pod mounts the existing claim. Delete is the
only lifecycle operation that removes the Sandbox resource and its owned
storage. The driver confirms the stop from both the published `Suspended`
condition and deletion of the backing pod. Legacy `v1alpha1` controllers omit
a usable stopped condition, so pod deletion alone confirms their stop.

A delete with `keep_workspace` keeps the workspace PVC instead. Before deleting
the Sandbox resource, the driver removes the resource's controller reference
from the claim `workspace-<resource name>` and moves the Agent Sandbox tracking
label `agents.x-k8s.io/sandbox-name-hash` into `openshell.ai/kept-workspace`,
so garbage collection leaves the claim and no controller adopts it meanwhile.
Creating the next sandbox of the same name in the same workspace restores the
label before creating its Sandbox resource; the Agent Sandbox controller then
adopts the unowned claim, and the seed init container skips it by its sentinel,
so the files are untouched. A claim controlled by another resource is never
taken. An ordinary delete still removes the claim. In managed mode, deleting the
workspace removes any kept claim with its namespace; in shared and operator
modes a kept claim stays until an operator removes it. The gateway needs `get`
and `patch` on `persistentvolumeclaims` in sandbox namespaces.

Until the adopting create completes, a restored claim still holds the data a
delete kept, and the restore marks it with `openshell.ai/kept-workspace-adoption`.
Whatever deletes that create's Sandbox resource first puts the claim back in the
kept state, detached, without the tracking label and marked kept, exactly as a
delete keeping the workspace leaves it: the create's rollback, the reaper of a
create a gateway restart interrupted, and any delete, also an ordinary one,
while the create's bootstrap is unfinished. A claim restored but not yet adopted
is kept the same way, and a conflict with the controller adopting it is read
again. When the claim cannot be kept, the resource is not deleted and the reaper
tries again. A claim the failed create made new goes with its resource. Before
this, on 2026-10-23, a create that failed after adopting a kept home rolled back
by deleting its resource, and garbage collection removed the claim it owned.

Sandbox resources are deleted with foreground propagation: the resource remains,
marked deleting, until garbage collection has removed its blocking dependents,
the workload Pod and a claim the resource still owns. The gateway therefore
reports the sandbox `Deleting` until its Pod is gone, and a client that waits
for a deleted sandbox to disappear can create the next sandbox of the name
without meeting the old Pod, which takes the resource's name. A kept claim has no
owner and does not hold the delete back. A create also refuses, before any
change, while a Pod of the resource's name still exists, with
`FAILED_PRECONDITION` and reason `PREVIOUS_SANDBOX_TERMINATING`; it is
retryable once that Pod is gone. Before this, a delete removed the resource at
once while its Pod ran out a 30-second termination grace, the gateway reported
the sandbox gone, and the next create of the name met the old Pod.

The workspace PVC size defaults to `workspace_default_storage_size`. Set
`workspace_storage_class` to pin the PVC to a specific `StorageClass`; an empty
value omits `storageClassName` so the cluster's default `StorageClass` applies.
Clusters with no default `StorageClass` must set this, otherwise the PVC stays
`Pending` and the sandbox never starts. Both fields can also be supplied at
runtime via `OPENSHELL_K8S_WORKSPACE_DEFAULT_STORAGE_SIZE` and
`OPENSHELL_K8S_WORKSPACE_STORAGE_CLASS`. Both apply only to the workspace PVC
that OpenShell provisions automatically; they have no effect when a `driver_config`
mount attaches an existing PVC under `/sandbox`, which skips the default PVC.

## Credentials, TLS, and Relay

Both Pods set `automountServiceAccountToken: false`. The supervisor receives an
explicit audience-bound projected token for the one-shot `IssueSandboxToken`
exchange. The driver verifies that token and returns an opaque runtime identity
derived from the namespace, immutable Sandbox resource UID, and supervisor Pod
UID. Restart requires exactly one matching Sandbox resource and preserves its
namespace and UID while rotating the supervisor Pod UID. The gateway requires
the authenticated identity to match the durable binding before returning the
generation-bound session JWT used by the supervisor. The sandbox Pod receives
neither token. For HTTPS gateway connections, the supervisor reads only the
CA from the configured TLS Secret. Shared mode projects `ca.crt` directly;
managed and operator modes stage only the CA into the supervisor bootstrap
Secret. User client certificates and private keys are not mounted into either Pod.

The gateway uses the supervisor relay for connect, exec, logs, and file sync.
Sandbox Pods do not need direct external ingress for SSH.

The driver sends the canonical main-process specification only to the
supervisor. The supervisor passes admitted launch state over the protected
channel. Provider environment updates apply to future exec sessions.

## Container Security Context

The sandbox, trusted bootstrap init container, and supervisor request no added
Linux capability. They run as the same numeric non-root identity, disable
privilege escalation, drop all capabilities, and inherit `RuntimeDefault`
seccomp. The sandbox and agent must use the same complete UID, GID, and
supplementary-group identity because the capability-free sandbox cannot change
credentials after launch and must inspect its same-identity descendants.

The workload Pod does not share host network, PID, IPC, or process namespaces.
The driver uses a scheduling gate to inspect the admitted Pod and bind its UID
into the bootstrap claims before kubelet starts it.

Lifecycle RPCs and runtime reconciliation share a per-sandbox mutation gate
across clones of the driver. Reconciliation skips busy sandboxes and refreshes
the Sandbox CR under that gate before cleanup, so a stopped or stopping LIST
snapshot cannot delete a supervisor created by a concurrent restart in the same
driver instance. The gate preserves concurrency across sandboxes; it does not
provide distributed exclusion between separate gateway or driver processes.

## GPU Support

When a sandbox requests GPU support, the driver checks node allocatable capacity
for `nvidia.com/gpu` and requests the configured GPU count in the workload spec.
When no count is set, the driver requests one GPU resource. The sandbox image
must provide the user-space libraries needed by the agent workload.

The driver derives the trusted `openshell.gpu` boundary claim from the admitted
agent container's positive integer `nvidia.com/gpu` limit on both creation and
restart. The shared sandbox runtime then admits the GPU device filesystem paths
visible in that workload. A RuntimeClass, environment variable or caller metadata
alone does not grant device access. This path accepts the native renderer's
unsigned decimal GPU counts; unsupported quantity spellings fail provisioning.
After upgrading this provisioning behavior, use native Stop/Start to create a
fresh runtime generation. Existing immutable bootstrap material is not rewritten.

## Driver Config

Following RFC 0006, this driver accepts the selected
`SandboxTemplate.driver_config.kubernetes` block as
`DriverSandboxTemplate.driver_config`. The Kubernetes driver owns the
nested schema and currently accepts:

- `pod.node_selector`
- `pod.tolerations`
- `pod.runtime_class_name`
- `pod.priority_class_name`
- `containers.agent.resources.requests`
- `containers.agent.resources.limits`
- `containers.agent.volume_mounts[].name`
- `containers.agent.volume_mounts[].mount_path`
- `containers.agent.volume_mounts[].sub_path`
- `containers.agent.volume_mounts[].read_only`
- `volumes[].name`
- `volumes[].persistent_volume_claim.claim_name`
- `volumes[].persistent_volume_claim.read_only`
- `volumes[].image.reference`
- `volumes[].image.pull_policy`

Nested keys inside the `kubernetes` block use snake_case. The top-level
`driver_config` envelope is keyed by driver names, so `kubernetes` is not part
of the nested schema.

Set this through the CLI with the public driver-keyed envelope. The gateway
forwards only the `kubernetes` object to this driver:

```shell
openshell sandbox create \
  --driver-config-json '{"kubernetes":{"pod":{"runtime_class_name":"kata-containers","node_selector":{"pool":"gpu"}}}}' \
  -- claude
```

Resource keys use native Kubernetes resource names and quantity strings. The
parser renders the keys listed above and rejects unknown fields.
`pod.runtime_class_name` maps to PodSpec `runtimeClassName` and overrides the
driver's configured `default_runtime_class_name`; the typed public
`SandboxTemplate.runtime_class_name` still takes precedence when set. Use the
public `--gpu` flag for the default GPU request, pass a count to `--gpu` for
counted GPU requests, and use `driver_config` only for additional driver-owned
resource details.

Use PVC volumes to mount existing Kubernetes PersistentVolumeClaims into the
agent container. PVC volumes and mounts default to read-only unless
`read_only: false` is set explicitly. Read-write access requires
`read_only: false` on both the PVC volume and each writable mount. The driver
rejects duplicate volume names, invalid DNS-1123 volume labels or PVC claim
subdomain names, mounts that reference unknown volumes, non-normalized or
protected mount paths, and absolute or parent-traversing `sub_path` values.

Use image volumes to mount an OCI image's filesystem read-only into the agent
container. Each volume sets exactly one of `persistent_volume_claim` or `image`.
`image.reference` must follow the distribution reference grammar, with a
`sha256` or `sha512` digest when it names one, and `image.pull_policy` is
`always`, `if_not_present` or `never` when set. Image volume mounts must stay
read-only and cannot set `sub_path`. The driver renders the volume as JSON,
because the `v1_29` Kubernetes API types it builds against have no image volume
source, and rechecks saved image mounts, references and pull policies before a
restart or release, as it does saved PVC mount destinations. Resource admission
refuses image volumes, so they require disabling it.

Any explicit driver-config mount under `/sandbox` disables the driver's
default `/sandbox` workspace PVC injection for that sandbox. Only the explicit
mount paths persist through the external PVC; other `/sandbox` paths come from
the current sandbox image.

```shell
openshell sandbox create \
  --driver-config-json '{
    "kubernetes": {
      "volumes": [{
        "name": "user-data",
        "persistent_volume_claim": {
          "claim_name": "pvc-user-data-123",
          "read_only": false
        }
      }],
      "containers": {
        "agent": {
          "volume_mounts": [
            {
              "name": "user-data",
              "mount_path": "/sandbox/.openshell/workspace",
              "sub_path": "workspace",
              "read_only": false
            },
            {
              "name": "user-data",
              "mount_path": "/sandbox/.openshell/memory",
              "sub_path": "memory",
              "read_only": false
            }
          ]
        }
      }
    }
  }' \
  -- claude
```
