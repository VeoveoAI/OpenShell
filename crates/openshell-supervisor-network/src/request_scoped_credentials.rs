// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Request-scoped refresh for endpoint-bound static credentials.
//!
//! A static credential whose binding carries request-scope metadata resolves,
//! for a request that names a scope through its scope header, to a token the
//! gateway mints for that scope instead of the credential's ordinary refreshed
//! token. The token stays in the supervisor: it is cached per sandbox instance
//! and substituted only into the outbound request.
//!
//! - Without the header, or with a malformed one, the request keeps the
//!   ordinary token.
//! - When the issuer or the gateway refuses the scope, the request keeps the
//!   ordinary token, so the upstream service refuses it natively.
//! - When the gateway or the issuer is unavailable, the request is not
//!   forwarded and the caller answers 502.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use miette::{Result, miette};
use openshell_core::grpc_client::GatewayEndpoint;
use openshell_core::provider_credentials::RequestScopedCredential;
use openshell_core::request_scope::ScopedCredentialFailure;
use openshell_ocsf::{
    ActionId, ActivityId, DispositionId, Endpoint, HttpActivityBuilder, HttpRequest, SeverityId,
    StatusId, ctx::ctx as ocsf_ctx, ocsf_emit,
};
use tokio::sync::OnceCell;
use tracing::warn;

use crate::l7::provider::L7Request;
use crate::l7::relay::L7EvalContext;

/// Scoped tokens one sandbox instance retains.
const DEFAULT_CACHE_CAPACITY: usize = 1024;

/// One scoped token request for the gateway.
pub struct ScopedTokenRequest<'a> {
    pub provider: &'a str,
    pub credential_key: &'a str,
    pub scope: &'a str,
    pub provider_attachment_epoch: &'a str,
    /// Supervisor-minted ID of the HTTP exchange that needs the token.
    pub request_id: &'a str,
}

/// A token minted for one request scope.
#[derive(Clone)]
pub struct ScopedToken {
    pub access_token: Arc<str>,
    pub expires_at_ms: i64,
}

impl fmt::Debug for ScopedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopedToken")
            .field("expires_at_ms", &self.expires_at_ms)
            .finish_non_exhaustive()
    }
}

/// Mints scoped tokens for one sandbox instance.
pub trait ScopedTokenMinter: Send + Sync {
    fn mint<'a>(
        &'a self,
        request: ScopedTokenRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<ScopedToken, ScopedCredentialFailure>> + Send + 'a>>;
}

/// Mints through the gateway's `MintScopedProviderCredential` as this sandbox.
pub struct GatewayScopedTokenMinter {
    gateway: Option<GatewayEndpoint>,
    sandbox_id: Option<String>,
}

impl GatewayScopedTokenMinter {
    /// Without a gateway or sandbox identity every mint is unavailable.
    #[must_use]
    pub fn new(gateway: Option<GatewayEndpoint>, sandbox_id: Option<String>) -> Self {
        Self {
            gateway,
            sandbox_id: sandbox_id.filter(|value| !value.trim().is_empty()),
        }
    }
}

impl ScopedTokenMinter for GatewayScopedTokenMinter {
    fn mint<'a>(
        &'a self,
        request: ScopedTokenRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<ScopedToken, ScopedCredentialFailure>> + Send + 'a>>
    {
        Box::pin(async move {
            let (Some(gateway), Some(sandbox_id)) =
                (self.gateway.as_ref(), self.sandbox_id.as_deref())
            else {
                return Err(ScopedCredentialFailure::Unavailable);
            };
            let minted = openshell_core::grpc_client::mint_scoped_provider_credential(
                gateway,
                openshell_core::grpc_client::ScopedProviderCredentialRequest {
                    sandbox_id,
                    provider: request.provider,
                    credential_key: request.credential_key,
                    scope: request.scope,
                    provider_attachment_epoch: request.provider_attachment_epoch,
                    request_id: request.request_id,
                },
            )
            .await?;
            Ok(ScopedToken {
                access_token: Arc::from(minted.access_token),
                expires_at_ms: minted.expires_at_ms,
            })
        })
    }
}

/// The gateway or issuer could not supply a request-scoped credential. The
/// request must not be forwarded.
#[derive(Debug)]
pub struct RequestScopedCredentialUnavailable;

impl fmt::Display for RequestScopedCredentialUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("request-scoped credential unavailable")
    }
}

impl std::error::Error for RequestScopedCredentialUnavailable {}

impl miette::Diagnostic for RequestScopedCredentialUnavailable {}

#[derive(Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    provider_attachment_epoch: String,
    provider: String,
    credential_identity: String,
    env_key: String,
    scope: String,
}

impl CacheKey {
    fn new(credential: &RequestScopedCredential, scope: &str) -> Self {
        Self {
            provider_attachment_epoch: credential.provider_attachment_epoch.clone(),
            provider: credential.provider.clone(),
            credential_identity: credential.credential_identity.clone(),
            env_key: credential.env_key.clone(),
            scope: scope.to_string(),
        }
    }
}

struct CachedToken {
    token: ScopedToken,
    reuse_until_ms: i64,
    inserted: u64,
}

type Flight = Arc<OnceCell<Result<ScopedToken, ScopedCredentialFailure>>>;

#[derive(Default)]
struct CacheState {
    tokens: HashMap<CacheKey, CachedToken>,
    flights: HashMap<CacheKey, Flight>,
    next_insertion: u64,
}

/// Scoped tokens for one sandbox instance: a bounded cache with one mint in
/// flight per (provider attachment, credential, scope).
pub struct RequestScopedCredentials {
    minter: Arc<dyn ScopedTokenMinter>,
    state: Mutex<CacheState>,
    capacity: usize,
    clock: Clock,
}

type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

impl RequestScopedCredentials {
    #[must_use]
    pub fn new(minter: Arc<dyn ScopedTokenMinter>) -> Self {
        Self::with_capacity_and_clock(
            minter,
            DEFAULT_CACHE_CAPACITY,
            Arc::new(openshell_core::time::now_ms),
        )
    }

    fn with_capacity_and_clock(
        minter: Arc<dyn ScopedTokenMinter>,
        capacity: usize,
        clock: Clock,
    ) -> Self {
        Self {
            minter,
            state: Mutex::new(CacheState::default()),
            capacity: capacity.max(1),
            clock,
        }
    }

    /// Return a cached token for `scope`, or mint one. The flag reports
    /// whether this call performed the mint.
    async fn obtain(
        &self,
        credential: &RequestScopedCredential,
        scope: &str,
        request_id: &str,
    ) -> Result<(ScopedToken, bool), ScopedCredentialFailure> {
        let key = CacheKey::new(credential, scope);
        let flight = {
            let mut state = self.lock();
            let now = (self.clock)();
            if let Some(cached) = state.tokens.get(&key)
                && cached.reuse_until_ms > now
            {
                return Ok((cached.token.clone(), false));
            }
            if state.flights.len() >= self.capacity {
                // Drop flights whose every caller was cancelled before minting.
                state
                    .flights
                    .retain(|_, flight| Arc::strong_count(flight) > 1);
            }
            state.flights.entry(key.clone()).or_default().clone()
        };
        let mut minted = false;
        let result = flight
            .get_or_init(|| {
                minted = true;
                self.mint(credential, scope, request_id)
            })
            .await
            .clone();
        {
            let mut state = self.lock();
            if state
                .flights
                .get(&key)
                .is_some_and(|current| Arc::ptr_eq(current, &flight))
            {
                state.flights.remove(&key);
            }
            if minted && let Ok(token) = &result {
                let now = (self.clock)();
                self.insert(&mut state, key, token.clone(), credential, now);
            }
        }
        result.map(|token| (token, minted))
    }

    async fn mint(
        &self,
        credential: &RequestScopedCredential,
        scope: &str,
        request_id: &str,
    ) -> Result<ScopedToken, ScopedCredentialFailure> {
        let token = self
            .minter
            .mint(ScopedTokenRequest {
                provider: &credential.provider,
                credential_key: &credential.env_key,
                scope,
                provider_attachment_epoch: &credential.provider_attachment_epoch,
                request_id,
            })
            .await?;
        // A token must be safe header material and still valid on arrival.
        if openshell_core::oauth::validate_access_token(&token.access_token).is_err()
            || token.expires_at_ms <= (self.clock)()
        {
            return Err(ScopedCredentialFailure::Unavailable);
        }
        Ok(token)
    }

    fn insert(
        &self,
        state: &mut CacheState,
        key: CacheKey,
        token: ScopedToken,
        credential: &RequestScopedCredential,
        now: i64,
    ) {
        let refresh_before_ms =
            i64::try_from(credential.refresh_before.as_millis()).unwrap_or(i64::MAX);
        let reuse_until_ms = token.expires_at_ms.saturating_sub(refresh_before_ms);
        if reuse_until_ms <= now {
            state.tokens.remove(&key);
            return;
        }
        if !state.tokens.contains_key(&key) && state.tokens.len() >= self.capacity {
            state.tokens.retain(|_, cached| cached.reuse_until_ms > now);
            if state.tokens.len() >= self.capacity
                && let Some(oldest) = state
                    .tokens
                    .iter()
                    .min_by_key(|(_, cached)| cached.inserted)
                    .map(|(key, _)| key.clone())
            {
                state.tokens.remove(&oldest);
            }
        }
        state.next_insertion += 1;
        let inserted = state.next_insertion;
        state.tokens.insert(
            key,
            CachedToken {
                token,
                reuse_until_ms,
                inserted,
            },
        );
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, CacheState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Resolve request-scoped credentials for an admitted request before its
/// placeholders are rewritten.
///
/// `ctx` must already hold the endpoint-scoped resolver for `req`. For each
/// static credential bound to this endpoint that declares request-scoped
/// refresh and whose scope header the request carries exactly once with a
/// valid value, the credential's placeholder in this request resolves to the
/// scoped token. Every other credential keeps its ordinary value.
///
/// # Errors
///
/// Returns [`RequestScopedCredentialUnavailable`] when the gateway or the
/// issuer is unavailable; the caller must answer 502 without forwarding.
pub(crate) async fn apply(
    req: &L7Request,
    ctx: &mut L7EvalContext,
    request_id: &str,
) -> Result<()> {
    let (Some(scoped_credentials), Some(provider_credentials), Some(resolver)) = (
        ctx.request_scoped_credentials.clone(),
        ctx.provider_credentials.as_ref(),
        ctx.secret_resolver.clone(),
    ) else {
        return Ok(());
    };
    let (credentials, revision) = provider_credentials.request_scoped_credentials_for_endpoint(
        &ctx.host,
        ctx.port,
        &req.target,
    );
    if credentials.is_empty() {
        return Ok(());
    }
    if ctx.provider_credential_revision != Some(revision) {
        return Err(miette!(
            "provider credentials changed during request preparation"
        ));
    }
    let headers = request_headers(&req.raw_header);
    let mut resolver = (*resolver).clone();
    let mut applied = false;
    for credential in &credentials {
        let values = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(&credential.header))
            .map(|(_, value)| *value)
            .collect::<Vec<_>>();
        let Some(scope) = openshell_core::request_scope::render_scope(
            &credential.header,
            &credential.scope_template,
            &values,
        ) else {
            continue;
        };
        match scoped_credentials
            .obtain(credential, &scope, request_id)
            .await
        {
            Ok((token, minted)) => {
                if minted {
                    emit_minted(ctx, req, credential, &scope, request_id);
                }
                resolver = resolver.with_env_key_value(
                    &credential.env_key,
                    &token.access_token,
                    token.expires_at_ms,
                );
                applied = true;
            }
            Err(
                failure @ (ScopedCredentialFailure::IssuerRefused
                | ScopedCredentialFailure::GatewayRefused),
            ) => emit_refused(ctx, req, credential, &scope, request_id, failure),
            Err(ScopedCredentialFailure::Unavailable) => {
                emit_unavailable(ctx, req, credential, &scope, request_id);
                return Err(RequestScopedCredentialUnavailable.into());
            }
        }
    }
    if applied {
        ctx.secret_resolver = Some(Arc::new(resolver));
    }
    Ok(())
}

/// Header fields of a parsed request head. A head that is not UTF-8 yields
/// none, so its request keeps ordinary credentials.
fn request_headers(raw_header: &[u8]) -> Vec<(&str, &str)> {
    let end = raw_header
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap_or(raw_header.len());
    let Ok(head) = std::str::from_utf8(&raw_header[..end]) else {
        return Vec::new();
    };
    head.split("\r\n")
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim(), value))
        .collect()
}

fn request_path(target: &str) -> &str {
    target.split('?').next().unwrap_or(target)
}

fn credential_name(credential: &RequestScopedCredential) -> String {
    format!("{}:{}", credential.provider, credential.env_key)
}

fn emit_minted(
    ctx: &L7EvalContext,
    req: &L7Request,
    credential: &RequestScopedCredential,
    scope: &str,
    request_id: &str,
) {
    ocsf_emit!(
        HttpActivityBuilder::new(ocsf_ctx())
            .activity(ActivityId::Other)
            .action(ActionId::Allowed)
            .disposition(DispositionId::Allowed)
            .severity(SeverityId::Informational)
            .http_request(HttpRequest::new(
                &req.action,
                ctx.ocsf_url(request_path(&req.target)),
            ))
            .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
            .message(format!(
                "Request-scoped credential {} minted for scope {scope} to {}:{}",
                credential_name(credential),
                ctx.host,
                ctx.port
            ))
            .unmapped("request_id", request_id)
            .build()
    );
}

fn emit_refused(
    ctx: &L7EvalContext,
    req: &L7Request,
    credential: &RequestScopedCredential,
    scope: &str,
    request_id: &str,
    failure: ScopedCredentialFailure,
) {
    warn!(
        host = %ctx.host,
        port = ctx.port,
        credential = %credential_name(credential),
        scope = %scope,
        request_id = %request_id,
        code = failure.code(),
        "Request-scoped credential refused; forwarding the ordinary credential"
    );
    ocsf_emit!(
        HttpActivityBuilder::new(ocsf_ctx())
            .activity(ActivityId::Other)
            .action(ActionId::Allowed)
            .disposition(DispositionId::Allowed)
            .severity(SeverityId::Low)
            .status(StatusId::Failure)
            .http_request(HttpRequest::new(
                &req.action,
                ctx.ocsf_url(request_path(&req.target)),
            ))
            .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
            .message(format!(
                "Request-scoped credential {} refused for scope {scope} to {}:{}; forwarding the ordinary credential",
                credential_name(credential),
                ctx.host,
                ctx.port
            ))
            .unmapped("request_id", request_id)
            .unmapped("code", failure.code())
            .build()
    );
}

fn emit_unavailable(
    ctx: &L7EvalContext,
    req: &L7Request,
    credential: &RequestScopedCredential,
    scope: &str,
    request_id: &str,
) {
    warn!(
        host = %ctx.host,
        port = ctx.port,
        credential = %credential_name(credential),
        scope = %scope,
        request_id = %request_id,
        "Request-scoped credential unavailable; request not forwarded"
    );
    ocsf_emit!(
        HttpActivityBuilder::new(ocsf_ctx())
            .activity(ActivityId::Fail)
            .action(ActionId::Denied)
            .disposition(DispositionId::Blocked)
            .severity(SeverityId::Medium)
            .status(StatusId::Failure)
            .http_request(HttpRequest::new(
                &req.action,
                ctx.ocsf_url(request_path(&req.target)),
            ))
            .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
            .message(format!(
                "Request-scoped credential {} unavailable for scope {scope} to {}:{}",
                credential_name(credential),
                ctx.host,
                ctx.port
            ))
            .unmapped("request_id", request_id)
            .build()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opa::{NetworkInput, OpaEngine};
    use bytes::Bytes;
    use http::{Request, Response, StatusCode};
    use openshell_core::proto::{
        ProviderCredentialRequestScope, StaticCredentialBinding, StaticCredentialEndpointBinding,
        StaticCredentialRequestScope,
    };
    use openshell_core::provider_credentials::ProviderCredentialState;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    const EPOCH: &str = "attachment-epoch-1";
    const KEY: &str = "LORE_TOKEN";
    const ORDINARY: &str = "synthetic-ordinary-token";
    // 16 raw bytes 0x00..=0x0f, as gRPC sends binary metadata.
    const PARTITION_PADDED: &str = "AAECAwQFBgcICQoLDA0ODw==";
    const PARTITION_UNPADDED: &str = "AAECAwQFBgcICQoLDA0ODw";
    const SCOPE: &str = "lore-repo-000102030405060708090a0b0c0d0e0f";
    const OTHER_PARTITION: &str = "/w==";
    const OTHER_SCOPE: &str = "lore-repo-ff";
    const POLICY: &str = r"
network_policies:
  lore:
    name: lore
    endpoints:
      - host: lore.example.test
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow: {method: POST, path: /**}
    binaries:
      - {path: /usr/bin/lore}
";

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MintCall {
        provider: String,
        credential_key: String,
        scope: String,
        provider_attachment_epoch: String,
    }

    /// Scripted minter: answers by scope and records every mint.
    struct FakeMinter {
        calls: Mutex<Vec<MintCall>>,
        answers: HashMap<String, Result<ScopedToken, ScopedCredentialFailure>>,
        release: Option<Arc<tokio::sync::Semaphore>>,
    }

    impl FakeMinter {
        fn new(answers: &[(&str, Result<ScopedToken, ScopedCredentialFailure>)]) -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                answers: answers
                    .iter()
                    .map(|(scope, answer)| ((*scope).to_string(), answer.clone()))
                    .collect(),
                release: None,
            })
        }

        fn calls(&self) -> Vec<MintCall> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl ScopedTokenMinter for FakeMinter {
        fn mint<'a>(
            &'a self,
            request: ScopedTokenRequest<'a>,
        ) -> Pin<Box<dyn Future<Output = Result<ScopedToken, ScopedCredentialFailure>> + Send + 'a>>
        {
            Box::pin(async move {
                self.calls.lock().unwrap().push(MintCall {
                    provider: request.provider.to_string(),
                    credential_key: request.credential_key.to_string(),
                    scope: request.scope.to_string(),
                    provider_attachment_epoch: request.provider_attachment_epoch.to_string(),
                });
                if let Some(release) = &self.release {
                    release.acquire().await.unwrap().forget();
                }
                self.answers
                    .get(request.scope)
                    .cloned()
                    .unwrap_or(Err(ScopedCredentialFailure::Unavailable))
            })
        }
    }

    fn token(value: &str, expires_at_ms: i64) -> ScopedToken {
        ScopedToken {
            access_token: Arc::from(value),
            expires_at_ms,
        }
    }

    fn far_future() -> i64 {
        openshell_core::time::now_ms() + 3_600_000
    }

    fn lore_credential() -> RequestScopedCredential {
        RequestScopedCredential {
            env_key: KEY.to_string(),
            credential_identity: "lore-provider-id:LORE_TOKEN".to_string(),
            provider: "lore".to_string(),
            provider_attachment_epoch: EPOCH.to_string(),
            header: "lore-partition-bin".to_string(),
            scope_template: "lore-repo-{value}".to_string(),
            refresh_before: Duration::from_mins(1),
        }
    }

    fn lore_state() -> ProviderCredentialState {
        ProviderCredentialState::from_bound_environment(
            7,
            HashMap::from([(KEY.to_string(), ORDINARY.to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(KEY.to_string(), lore_state_binding())]),
            Vec::new(),
        )
        .expect("bound provider state")
    }

    fn engine() -> OpaEngine {
        OpaEngine::from_strings(include_str!("../data/sandbox-policy.rego"), POLICY).unwrap()
    }

    fn relay_parts(
        engine: &OpaEngine,
        minter: Arc<FakeMinter>,
    ) -> (
        crate::l7::L7EndpointConfig,
        crate::opa::TunnelPolicyEngine,
        L7EvalContext,
        String,
    ) {
        let input = NetworkInput {
            host: "lore.example.test".into(),
            port: 443,
            binary_path: PathBuf::from("/usr/bin/lore"),
            binary_sha256: "unused".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
        };
        let (config, generation) = engine
            .query_endpoint_config_with_generation(&input)
            .unwrap();
        let config = crate::l7::parse_l7_config(&config.unwrap()).unwrap();
        let tunnel = engine.clone_engine_for_tunnel(generation).unwrap();
        let state = lore_state();
        let placeholder = state.snapshot().child_env[KEY].clone();
        let context = L7EvalContext {
            host: input.host,
            port: 443,
            request_default_port: Some(443),
            binary_path: "/usr/bin/lore".into(),
            policy_name: "lore".into(),
            provider_credentials: Some(state),
            request_scoped_credentials: Some(Arc::new(RequestScopedCredentials::new(minter))),
            ..Default::default()
        };
        (config, tunnel, context, placeholder)
    }

    /// An HTTP/2 relay in front of an upstream that records request headers.
    struct Http2Harness {
        app: h2::client::SendRequest<Bytes>,
        seen: tokio::sync::mpsc::Receiver<http::HeaderMap>,
        placeholder: String,
        tasks: Vec<tokio::task::JoinHandle<()>>,
    }

    impl Http2Harness {
        async fn start(minter: Arc<FakeMinter>) -> Self {
            let engine = engine();
            let (config, tunnel, context, placeholder) = relay_parts(&engine, minter);
            let (app, relay_client) = tokio::io::duplex(64 * 1024);
            let (relay_upstream, upstream) = tokio::io::duplex(64 * 1024);
            let relay_task = tokio::spawn(async move {
                let _engine = engine;
                let _ =
                    crate::l7::http2::relay(relay_client, relay_upstream, config, tunnel, context)
                        .await;
            });
            let (seen_tx, seen) = tokio::sync::mpsc::channel(8);
            let upstream_task = tokio::spawn(async move {
                let mut server = h2::server::handshake(upstream).await.unwrap();
                while let Some(request) = server.accept().await {
                    let (request, mut response) = request.unwrap();
                    seen_tx.send(request.headers().clone()).await.unwrap();
                    response
                        .send_response(
                            Response::builder()
                                .header("content-type", "application/grpc")
                                .header("grpc-status", "0")
                                .body(())
                                .unwrap(),
                            true,
                        )
                        .unwrap();
                }
            });
            let (app, connection) = h2::client::handshake(app).await.unwrap();
            let app_task = tokio::spawn(async move {
                let _ = connection.await;
            });
            Self {
                app,
                seen,
                placeholder,
                tasks: vec![relay_task, upstream_task, app_task],
            }
        }

        /// Send one unary gRPC request and return its response status.
        async fn call(&mut self, partition: &[&str]) -> StatusCode {
            let mut request = Request::builder()
                .method("POST")
                .uri("https://lore.example.test/lore.v1.Repository/Get")
                .header("content-type", "application/grpc")
                .header("authorization", format!("Bearer {}", self.placeholder));
            for value in partition {
                request = request.header("lore-partition-bin", *value);
            }
            let app = self.app.clone().ready().await.unwrap();
            let (response, _) = app
                .clone()
                .send_request(request.body(()).unwrap(), true)
                .unwrap();
            self.app = app;
            tokio::time::timeout(Duration::from_secs(5), response)
                .await
                .expect("relay should answer")
                .unwrap()
                .status()
        }

        async fn forwarded_authorization(&mut self) -> String {
            let headers = tokio::time::timeout(Duration::from_secs(5), self.seen.recv())
                .await
                .expect("request should reach upstream")
                .unwrap();
            assert_eq!(headers.get_all("authorization").iter().count(), 1);
            headers["authorization"].to_str().unwrap().to_string()
        }

        fn assert_nothing_forwarded(&mut self) {
            assert!(
                self.seen.try_recv().is_err(),
                "request must not reach upstream"
            );
        }
    }

    impl Drop for Http2Harness {
        fn drop(&mut self) {
            for task in &self.tasks {
                task.abort();
            }
        }
    }

    #[tokio::test]
    async fn grpc_request_with_partition_header_gets_the_scoped_token() {
        let minter = FakeMinter::new(&[(SCOPE, Ok(token("synthetic-scoped-token", far_future())))]);
        let mut harness = Http2Harness::start(minter.clone()).await;

        assert_eq!(harness.call(&[PARTITION_UNPADDED]).await, StatusCode::OK);
        assert_eq!(
            harness.forwarded_authorization().await,
            "Bearer synthetic-scoped-token"
        );
        assert_eq!(
            minter.calls(),
            vec![MintCall {
                provider: "lore".to_string(),
                credential_key: KEY.to_string(),
                scope: SCOPE.to_string(),
                provider_attachment_epoch: EPOCH.to_string(),
            }]
        );

        // The padded form names the same repository and reuses the cached token.
        assert_eq!(harness.call(&[PARTITION_PADDED]).await, StatusCode::OK);
        assert_eq!(
            harness.forwarded_authorization().await,
            "Bearer synthetic-scoped-token"
        );
        assert_eq!(minter.calls().len(), 1);
    }

    #[tokio::test]
    async fn grpc_request_without_or_with_invalid_partition_keeps_the_ordinary_token() {
        let minter = FakeMinter::new(&[(SCOPE, Ok(token("synthetic-scoped-token", far_future())))]);
        let mut harness = Http2Harness::start(minter.clone()).await;

        for partition in [
            &[][..],
            &["not base64!"][..],
            &[""][..],
            &[PARTITION_PADDED, PARTITION_PADDED][..],
        ] {
            assert_eq!(
                harness.call(partition).await,
                StatusCode::OK,
                "{partition:?}"
            );
            assert_eq!(
                harness.forwarded_authorization().await,
                format!("Bearer {ORDINARY}"),
                "{partition:?}"
            );
        }
        assert!(minter.calls().is_empty());
    }

    #[tokio::test]
    async fn refused_scope_falls_back_to_the_ordinary_token() {
        let minter = FakeMinter::new(&[
            (SCOPE, Err(ScopedCredentialFailure::IssuerRefused)),
            (OTHER_SCOPE, Err(ScopedCredentialFailure::GatewayRefused)),
        ]);
        let mut harness = Http2Harness::start(minter.clone()).await;

        for partition in [PARTITION_PADDED, OTHER_PARTITION] {
            assert_eq!(harness.call(&[partition]).await, StatusCode::OK);
            assert_eq!(
                harness.forwarded_authorization().await,
                format!("Bearer {ORDINARY}")
            );
        }
        let scopes = minter
            .calls()
            .into_iter()
            .map(|call| call.scope)
            .collect::<Vec<_>>();
        assert_eq!(scopes, [SCOPE, OTHER_SCOPE]);
    }

    #[tokio::test]
    async fn unavailable_scope_answers_502_before_forwarding() {
        let minter = FakeMinter::new(&[(SCOPE, Err(ScopedCredentialFailure::Unavailable))]);
        let mut harness = Http2Harness::start(minter.clone()).await;

        assert_eq!(
            harness.call(&[PARTITION_PADDED]).await,
            StatusCode::BAD_GATEWAY
        );
        tokio::task::yield_now().await;
        harness.assert_nothing_forwarded();
        assert_eq!(minter.calls().len(), 1);

        // The connection stays usable; a request without the header proceeds.
        assert_eq!(harness.call(&[]).await, StatusCode::OK);
        assert_eq!(
            harness.forwarded_authorization().await,
            format!("Bearer {ORDINARY}")
        );
    }

    #[tokio::test]
    async fn http1_request_uses_the_same_preparation_step() {
        let minter = FakeMinter::new(&[
            (SCOPE, Ok(token("synthetic-scoped-token", far_future()))),
            (OTHER_SCOPE, Err(ScopedCredentialFailure::Unavailable)),
        ]);
        let engine = engine();

        let (config, tunnel, context, placeholder) = relay_parts(&engine, minter.clone());
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            crate::l7::relay::relay_with_inspection(
                &config,
                tunnel,
                &mut relay_client,
                &mut relay_upstream,
                &context,
            )
            .await
        });
        app.write_all(
            format!(
                "POST /lore.v1.Repository/Get HTTP/1.1\r\nHost: lore.example.test\r\nAuthorization: Bearer {placeholder}\r\nLore-Partition-Bin: {PARTITION_PADDED}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut forwarded = [0_u8; 1024];
        let n = tokio::time::timeout(Duration::from_secs(5), upstream.read(&mut forwarded))
            .await
            .expect("request should reach upstream")
            .unwrap();
        let forwarded = String::from_utf8_lossy(&forwarded[..n]).to_string();
        assert!(
            forwarded.contains("Authorization: Bearer synthetic-scoped-token\r\n"),
            "{forwarded}"
        );
        assert!(!forwarded.contains(ORDINARY));
        upstream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        tokio::time::timeout(Duration::from_secs(5), app.read_to_string(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(response.contains("204 No Content"), "{response}");
        let _ = tokio::time::timeout(Duration::from_secs(5), relay).await;

        // Unavailability answers 502 with the request ID and forwards nothing.
        let (config, tunnel, context, placeholder) = relay_parts(&engine, minter.clone());
        let (mut app, mut relay_client) = tokio::io::duplex(8192);
        let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            crate::l7::relay::relay_with_inspection(
                &config,
                tunnel,
                &mut relay_client,
                &mut relay_upstream,
                &context,
            )
            .await
        });
        app.write_all(
            format!(
                "POST /lore.v1.Repository/Get HTTP/1.1\r\nHost: lore.example.test\r\nAuthorization: Bearer {placeholder}\r\nlore-partition-bin: {OTHER_PARTITION}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut response = String::new();
        tokio::time::timeout(Duration::from_secs(5), app.read_to_string(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert!(
            response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
            "{response}"
        );
        assert!(response.contains(openshell_core::token_grant_failure::REQUEST_ID_HEADER));
        let _ = tokio::time::timeout(Duration::from_secs(5), relay).await;
        let mut forwarded = Vec::new();
        upstream.read_to_end(&mut forwarded).await.unwrap();
        assert!(
            forwarded.is_empty(),
            "unavailable credential must forward nothing"
        );
    }

    fn manual_clock(start: i64) -> (Arc<AtomicI64>, Clock) {
        let now = Arc::new(AtomicI64::new(start));
        let clock_now = now.clone();
        (now, Arc::new(move || clock_now.load(Ordering::SeqCst)))
    }

    #[tokio::test]
    async fn cache_reuses_a_token_until_expiry_minus_refresh_before() {
        let start = 1_000_000;
        // Expires 10 minutes from start; reuse ends 60 s earlier.
        let minter =
            FakeMinter::new(&[(SCOPE, Ok(token("synthetic-scoped-token", start + 600_000)))]);
        let (now, clock) = manual_clock(start);
        let cache = RequestScopedCredentials::with_capacity_and_clock(minter.clone(), 16, clock);
        let credential = lore_credential();

        let (first, fresh) = cache.obtain(&credential, SCOPE, "request-1").await.unwrap();
        assert!(fresh);
        assert_eq!(&*first.access_token, "synthetic-scoped-token");
        now.store(start + 539_999, Ordering::SeqCst);
        let (_, fresh) = cache.obtain(&credential, SCOPE, "request-2").await.unwrap();
        assert!(!fresh, "token is reused before its refresh point");
        assert_eq!(minter.calls().len(), 1);

        now.store(start + 540_000, Ordering::SeqCst);
        let (_, fresh) = cache.obtain(&credential, SCOPE, "request-3").await.unwrap();
        assert!(fresh, "token is replaced at its refresh point");
        assert_eq!(minter.calls().len(), 2);

        // Another attachment, credential identity or scope is a separate entry.
        let mut reattached = credential.clone();
        reattached.provider_attachment_epoch = "attachment-epoch-2".to_string();
        let mut replaced = credential.clone();
        replaced.credential_identity = "replacement-provider-id:LORE_TOKEN".to_string();
        cache.obtain(&reattached, SCOPE, "request-4").await.unwrap();
        cache.obtain(&replaced, SCOPE, "request-5").await.unwrap();
        assert_eq!(minter.calls().len(), 4);
        assert_eq!(
            minter.calls()[2].provider_attachment_epoch,
            "attachment-epoch-2"
        );
    }

    #[tokio::test]
    async fn tokens_inside_their_refresh_window_and_failures_are_not_cached() {
        let start = 1_000_000;
        let minter = FakeMinter::new(&[
            // Lifetime shorter than refresh_before: usable now, never reused.
            (SCOPE, Ok(token("synthetic-short-token", start + 30_000))),
            (OTHER_SCOPE, Err(ScopedCredentialFailure::IssuerRefused)),
        ]);
        let (_, clock) = manual_clock(start);
        let cache = RequestScopedCredentials::with_capacity_and_clock(minter.clone(), 16, clock);
        let credential = lore_credential();
        for _ in 0..2 {
            assert!(cache.obtain(&credential, SCOPE, "request").await.unwrap().1);
            assert_eq!(
                cache
                    .obtain(&credential, OTHER_SCOPE, "request")
                    .await
                    .unwrap_err(),
                ScopedCredentialFailure::IssuerRefused
            );
        }
        assert_eq!(minter.calls().len(), 4);
    }

    #[tokio::test]
    async fn concurrent_requests_for_one_scope_share_one_mint() {
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let minter = Arc::new(FakeMinter {
            calls: Mutex::new(Vec::new()),
            answers: HashMap::from([(
                SCOPE.to_string(),
                Ok(token("synthetic-scoped-token", far_future())),
            )]),
            release: Some(release.clone()),
        });
        let cache = RequestScopedCredentials::new(minter.clone());
        let credential = lore_credential();
        let waiters = (0..8)
            .map(|index| {
                let cache = &cache;
                let credential = &credential;
                async move {
                    cache
                        .obtain(credential, SCOPE, &format!("request-{index}"))
                        .await
                }
            })
            .collect::<Vec<_>>();
        let releaser = async {
            // Let every waiter reach the flight before the mint answers.
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
            release.add_permits(1);
        };
        let (results, ()) = tokio::join!(futures::future::join_all(waiters), releaser);
        assert_eq!(minter.calls().len(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| result.as_ref().unwrap().1)
                .count(),
            1
        );
        assert!(results.iter().all(|result| {
            &*result.as_ref().unwrap().0.access_token == "synthetic-scoped-token"
        }));
    }

    #[tokio::test]
    async fn bounded_cache_drops_expired_entries_before_the_oldest() {
        let start = 1_000_000;
        let scopes = [
            "lore-repo-01",
            "lore-repo-02",
            "lore-repo-03",
            "lore-repo-04",
        ];
        let minter = FakeMinter::new(&[
            // Reusable only briefly: its refresh point passes first.
            (scopes[0], Ok(token("synthetic-a", start + 61_000))),
            (scopes[1], Ok(token("synthetic-b", start + 600_000))),
            (scopes[2], Ok(token("synthetic-c", start + 600_000))),
            (scopes[3], Ok(token("synthetic-d", start + 600_000))),
        ]);
        let (now, clock) = manual_clock(start);
        let cache = RequestScopedCredentials::with_capacity_and_clock(minter.clone(), 2, clock);
        let credential = lore_credential();
        cache.obtain(&credential, scopes[1], "r").await.unwrap();
        cache.obtain(&credential, scopes[0], "r").await.unwrap();
        now.store(start + 2_000, Ordering::SeqCst);
        // Full: the expired entry (scopes[0]) goes first, the older live one stays.
        cache.obtain(&credential, scopes[2], "r").await.unwrap();
        assert!(!cache.obtain(&credential, scopes[1], "r").await.unwrap().1);
        // Full with live entries only: the oldest (scopes[1]) goes.
        cache.obtain(&credential, scopes[3], "r").await.unwrap();
        assert!(!cache.obtain(&credential, scopes[2], "r").await.unwrap().1);
        assert!(cache.obtain(&credential, scopes[1], "r").await.unwrap().1);
        assert_eq!(cache.lock().tokens.len(), 2);
    }

    #[tokio::test]
    async fn malformed_or_expired_minted_tokens_are_unavailable() {
        let minter = FakeMinter::new(&[
            (
                SCOPE,
                Ok(token("synthetic token\r\nx-injected: 1", far_future())),
            ),
            (OTHER_SCOPE, Ok(token("synthetic-expired", 1))),
        ]);
        let cache = RequestScopedCredentials::new(minter);
        let credential = lore_credential();
        for scope in [SCOPE, OTHER_SCOPE] {
            assert_eq!(
                cache
                    .obtain(&credential, scope, "request")
                    .await
                    .unwrap_err(),
                ScopedCredentialFailure::Unavailable
            );
        }
    }

    #[test]
    fn scoped_resolver_view_replaces_only_the_selected_key() {
        let state = ProviderCredentialState::from_bound_environment(
            3,
            HashMap::from([
                (KEY.to_string(), ORDINARY.to_string()),
                ("OTHER_TOKEN".to_string(), "synthetic-other".to_string()),
            ]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([
                (KEY.to_string(), lore_state_binding()),
                ("OTHER_TOKEN".to_string(), {
                    let mut binding = lore_state_binding();
                    binding.credential_identity = "other:OTHER_TOKEN".to_string();
                    binding.request_scope = None;
                    binding
                }),
            ]),
            Vec::new(),
        )
        .unwrap();
        let env = state.snapshot().child_env.clone();
        let resolver = state.resolver_for_endpoint("lore.example.test", 443, "/x");
        let scoped = resolver
            .unwrap()
            .with_env_key_value(KEY, "synthetic-scoped", far_future());
        assert_eq!(
            scoped.resolve_placeholder(&env[KEY]),
            Some("synthetic-scoped")
        );
        assert_eq!(
            scoped.resolve_placeholder(&env["OTHER_TOKEN"]),
            Some("synthetic-other")
        );
        // Identity checks still apply: an identityless alias stays unresolvable.
        assert_eq!(
            scoped.resolve_placeholder(&openshell_core::secrets::placeholder_for_env_key(KEY)),
            None
        );
        let (credentials, revision) =
            state.request_scoped_credentials_for_endpoint("lore.example.test", 443, "/x");
        assert_eq!(revision, 3);
        assert_eq!(credentials, vec![lore_credential()]);
        assert!(
            state
                .request_scoped_credentials_for_endpoint("other.example.test", 443, "/x")
                .0
                .is_empty()
        );
    }

    #[test]
    fn scoped_value_follows_a_stable_refresh_handle() {
        // Gateway-managed refresh credentials use an identity-bound stable handle.
        let handle = "ab".repeat(32);
        let mut binding = lore_state_binding();
        binding.credential_identity = format!("refresh:{handle}");
        binding.workload_credential_handle.clone_from(&handle);
        let state = ProviderCredentialState::from_bound_environment(
            5,
            HashMap::from([(KEY.to_string(), ORDINARY.to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(KEY.to_string(), binding)]),
            Vec::new(),
        )
        .unwrap();
        let placeholder = state.snapshot().child_env[KEY].clone();
        assert!(placeholder.contains(&handle));
        let resolver = state
            .resolver_for_endpoint("lore.example.test", 443, "/x")
            .unwrap();
        assert_eq!(resolver.resolve_placeholder(&placeholder), Some(ORDINARY));
        let scoped = resolver.with_env_key_value(KEY, "synthetic-scoped", far_future());
        assert_eq!(
            scoped.resolve_placeholder(&placeholder),
            Some("synthetic-scoped")
        );
        // The swap is a per-request view; the live resolver is unchanged.
        assert_eq!(resolver.resolve_placeholder(&placeholder), Some(ORDINARY));
        let (credentials, _) =
            state.request_scoped_credentials_for_endpoint("lore.example.test", 443, "/x");
        assert_eq!(
            credentials[0].credential_identity,
            format!("refresh:{handle}")
        );
    }

    fn lore_state_binding() -> StaticCredentialBinding {
        StaticCredentialBinding {
            endpoints: vec![StaticCredentialEndpointBinding {
                host: "lore.example.test".to_string(),
                port: 443,
                path: "/**".to_string(),
            }],
            credential_identity: "lore-provider-id:LORE_TOKEN".to_string(),
            workload_credential_handle: String::new(),
            request_scope: Some(StaticCredentialRequestScope {
                provider: "lore".to_string(),
                request_scope: Some(ProviderCredentialRequestScope {
                    header: "lore-partition-bin".to_string(),
                    scope_template: "lore-repo-{value}".to_string(),
                }),
                refresh_before: Some(prost_types::Duration {
                    seconds: 60,
                    nanos: 0,
                }),
                provider_attachment_epoch: EPOCH.to_string(),
            }),
        }
    }

    #[test]
    fn malformed_request_scope_metadata_is_rejected() {
        for mutate in [
            |binding: &mut StaticCredentialBinding| {
                binding.request_scope.as_mut().unwrap().request_scope = None;
            },
            |binding: &mut StaticCredentialBinding| {
                binding.request_scope.as_mut().unwrap().provider.clear();
            },
            |binding: &mut StaticCredentialBinding| {
                binding.request_scope.as_mut().unwrap().refresh_before = None;
            },
            |binding: &mut StaticCredentialBinding| {
                binding
                    .request_scope
                    .as_mut()
                    .unwrap()
                    .request_scope
                    .as_mut()
                    .unwrap()
                    .header = "authorization".to_string();
            },
            |binding: &mut StaticCredentialBinding| {
                binding
                    .request_scope
                    .as_mut()
                    .unwrap()
                    .request_scope
                    .as_mut()
                    .unwrap()
                    .scope_template = "lore-repo".to_string();
            },
        ] {
            let mut binding = lore_state_binding();
            mutate(&mut binding);
            assert!(
                ProviderCredentialState::from_bound_environment(
                    1,
                    HashMap::from([(KEY.to_string(), ORDINARY.to_string())]),
                    HashMap::new(),
                    HashMap::new(),
                    HashMap::from([(KEY.to_string(), binding)]),
                    Vec::new(),
                )
                .is_err()
            );
        }
    }
}
