# Network supervisor

This crate forbids unsafe code, including its local tests. Typed socket APIs
provide original-destination lookup for transparent proxying.

Socket attribution tests pass a duplicate connected socket as a spawned child's
stdin. Re-executing the test binary checks multiple holders with the same binary
identity; executing a different binary checks ambiguous shared-socket identity.
The fixture kills and reaps the child when the parent test ends.

The manual proxy performance baseline still counts allocations. Its test-only
global allocator uses `openshell-driver-vm::allocation_tracking`; the unsafe
allocator implementation belongs to the VM crate. The VM dependency disables
default features, so this instrumentation does not
require the compute runtime or Unix-only sandbox library. It is a development
dependency only.

## Sandbox instance inputs

`run_networking` takes a `SandboxInstanceNetwork` with the sandbox identity,
the sandbox instance's `GatewayEndpoint`, the SPIFFE Workload API socket for
provider token grants, the `policy.local` denial source, and proxy CA files.
None of these are read from the process environment, so one process can run
several sandbox instances. Each instance owns its provider token cache and
HTTP client; a token acquired for one sandbox is never served to another.
Without a Workload API socket, token grants fail closed. A process hosting
several instances serves `/v1/denials` from a per-instance
`SandboxInstanceDenialLog` instead of the shared shorthand log files.

Each instance also owns a `RequestScopedCredentials` cache for static
credentials whose binding carries request-scope metadata. The shared inspected
request preparation (`prepare_inspected_request`, used by HTTP/1, the forward
proxy, and HTTP/2) renders the scope after endpoint scoping and before
placeholder rewriting, then swaps the credential's value in that request's
resolver view only. Tokens come from `MintScopedProviderCredential` with the
instance's gateway credentials, are cached per attachment, credential identity,
and scope until expiry minus `refresh_before` (at most 1,024, expired entries
evicted first, then the oldest), and are minted once per key at a time.

## Strict credential bindings

A static credential binding endpoint can be strict. The endpoint-scoped resolver
from `ProviderCredentialState::resolver_and_body_classifier_for_endpoint` then
carries a `StrictCredentialBinding` built from the credentials bound at that
request endpoint: their environment keys and the request position each
credential's profile placement declares, plus `Authorization`.
`SecretResolver::check_strict_binding` runs before any placeholder rewriting in
`rewrite_http_header_block` (inspected HTTP/1, passthrough with credentials, and
HTTP/2) and in the forward proxy's `rewrite_forward_request`. It reads only
placeholder syntax and environment keys, never a secret, and returns a
placeholder-required error that the relay and the forward proxy answer with 403
`credential_placeholder_required`, a denied HTTP activity event, and an
`openshell.provider_credential.placeholder_required` finding. An origin-form
request without `Host` keeps a credential-free view of a strict endpoint, so its
positions are still checked.
