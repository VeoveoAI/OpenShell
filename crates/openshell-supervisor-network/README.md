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

## Connections without inspection

Before the supervisor forwards a connection it cannot inspect (`tls: skip`, transparent TCP, h2c, unsupported tunnels, SQL passthrough), `uninspectable_traffic_gate` checks the matching middleware chain. Any `fail_closed` entry denies the connection, and an all-`fail_open` chain relays it with a bypass finding. For `tls: skip`, the gate runs before `200 Connection Established`, so a denial is a `403`.

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

The gateway delivers each provider environment with its strict credential
endpoints (`StrictCredentialEndpoint`): host, port, path, the environment keys
of the credentials bound there, and their placements. They arrive whether or
not the credential values do, and `ProviderCredentialState` keeps them across
revocation until a valid replacement set is installed. When one matches a
request, the endpoint-scoped resolver from
`ProviderCredentialState::resolver_and_body_classifier_for_endpoint` carries a
`StrictCredentialBinding`: the matched keys and those of any other credential
bound there, and the matched placements plus `Authorization`. With no
credential value installed, the resolver is an empty view that only checks.
`SecretResolver::check_strict_binding` runs before any placeholder rewriting in
`rewrite_http_header_block` (inspected HTTP/1, passthrough with credentials, and
HTTP/2) and in the forward proxy's `rewrite_forward_request`. It reads only
placeholder syntax and environment keys, never a secret, and returns a
placeholder-required error that the relay and the forward proxy answer with 403
`credential_placeholder_required`, a denied HTTP activity event, and an
`openshell.provider_credential.placeholder_required` finding. An origin-form
request without `Host` keeps a credential-free view of a strict endpoint, so its
positions are still checked.

## Reserved destinations

`preauthorize_transparent_open` matches a staged TCP open against the reserved
OTLP relay address (`openshell_core::sandbox_env::OTLP_RELAY_ADDR`) before host
mapping, policy evaluation, and SSRF checks. The address is an unroutable
label, so the proxy never dials it. When `run_networking` receives a
`ReservedDestination`, the proxy hands the workload stream to its
`ReservedStreamHandler`; a handler that refuses, for example at its connection
cap, turns the open into a resource-exhausted denial. Without a handler, the
proxy denies the open at once. It logs the first attempt at warn and later ones
at debug, and emits no OCSF denial event: a standard OpenTelemetry SDK retries
for the life of the agent, and one event per retry would flood the OCSF log.
The supervisor installs its OTLP relay receiver as the handler while the agent
trace relay is active.

## Static credential placement

Substitution checks the declared request location before writing upstream.
Credentials without placement metadata default to the Authorization header. HTTP placement violations return a safe 403 response;
WebSocket violations close the connection with policy denial. Both paths emit a
domain event and a detection finding without credential values or placeholders.
Explicit body and WebSocket
rewrite flags authorize those locations for ordinary static credentials. SigV4
signing retains the endpoint-scoped resolver's existing trusted access.

## HTTP enforcement correlation

Each inspected HTTP request has one UUID shared by middleware, OCSF
`metadata.correlation_uid`, and the protected `x-openshell-request-id` response
header. Application correlation must use another header. The receipt is only a
join key: it does not establish identity, authorization or complete delivery.
L4 and passthrough traffic do not provide this header guarantee.

The emission hook adds request correlation to every OCSF class in the current
request scope, including findings. Policy, middleware, token-grant and finding
records are individual events with their own timestamps and classification.
`unmapped.http_event_kind` identifies decisions, findings, connection events,
middleware invocations and token grants. Middleware invocations use
`unmapped.middleware_phase` for request, response and WebSocket phases.
`unmapped.request_sequence` starts at 1 per request and describes local emission
order, not downstream delivery order. Count policy outcomes by selecting the
actual policy/firewall control record within a receipt group, not every
`decision` record.

Request IDs and audit outcomes do not depend on OpenTelemetry, sampling or
collector availability. Inspected requests have a supervisor-owned request span
and children around stages that actually run, with valid workload W3C context
only as an untrusted link. Their records never create an extra denial-only span,
even if the request span is disabled or unsampled. Uninspected HTTP denials use
bounded `supervisor.egress.deny` spans. The ambient HTTP audit scope ends before
protocol-start validation; one-shot attribution joins the existing upgrade
handoff record to the handshake and releases the request span before frames.
Later WebSocket frames do not reuse the handshake receipt. Terminal errors carry their request context explicitly,
and policy-reload cancellation records the active request before dropping it.
Idle connection closures have no HTTP receipt.
The request span ends after its owned stages, not when response headers are logged.
The `openshell.upstream.send` stage measures request writes and flush; response
handling is measured separately. Handled middleware failures remain stage errors
even when the local rejection response is delivered successfully. Receipt
filtering preserves raw HTTP bytes
and borrows unchanged header blocks. It removes only protected receipt fields
and their `Connection` or `Trailer` nominations, including folded continuations,
without adding general response-header validation.
