// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Request-scoped provider credential mints for sandbox supervisors.
//!
//! A credential whose refresh declares `request_scope` can be minted for one
//! OAuth scope rendered from a request header. The supervisor names the
//! credential and the rendered scope; the gateway re-derives every authority
//! from its own records before it uses the credential's stored client material,
//! and it persists nothing.

#![allow(clippy::result_large_err)] // gRPC handlers return Result<Response<_>, Status>

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex, Weak};
use std::time::Duration;

use openshell_core::ObjectId;
use openshell_core::metadata::ObjectWorkspace;
use openshell_core::proto::{
    MintScopedProviderCredentialRequest, MintScopedProviderCredentialResponse, Provider,
    ProviderCredentialRefreshStrategy, Sandbox,
};
use openshell_core::request_scope::{ISSUER_REFUSED_REASON, scope_matches_template};
use openshell_core::rpc_error::{ERROR_DOMAIN, ErrorDetails, StatusExt as _};
use tokio::sync::Semaphore;
use tonic::{Code, Request, Response, Status};
use tracing::{info, warn};

use crate::ServerState;
use crate::auth::principal::Principal;
use crate::provider_refresh::{ScopedMintFailure, mint_scoped_client_credentials};

/// Concurrent mints one sandbox may run. Supervisors coalesce identical
/// requests, so this bounds distinct scopes in flight.
const SCOPED_MINTS_PER_SANDBOX: usize = 4;
/// How long a mint waits for one of its sandbox's permits.
const SCOPED_MINT_ADMISSION_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_FIELD_BYTES: usize = 512;

static SANDBOX_MINT_PERMITS: LazyLock<Mutex<HashMap<String, Weak<Semaphore>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Mint a scoped token for a credential of a provider attached to the caller.
pub(super) async fn handle_mint_scoped_provider_credential(
    state: &Arc<ServerState>,
    request: Request<MintScopedProviderCredentialRequest>,
) -> Result<Response<MintScopedProviderCredentialResponse>, Status> {
    // Only the exact sandbox supervisor may mint for its sandbox.
    let auth_code = match request.extensions().get::<Principal>() {
        Some(Principal::Sandbox(principal))
            if principal.sandbox_id == request.get_ref().sandbox_id =>
        {
            None
        }
        Some(
            Principal::Sandbox(_)
            | Principal::User(_)
            | Principal::Operator(_)
            | Principal::Peer(_)
            | Principal::Supervisor(_),
        ) => Some(Code::PermissionDenied),
        Some(Principal::Anonymous) | None => Some(Code::Unauthenticated),
    };
    if let Some(code) = auth_code {
        return Err(Status::new(
            code,
            "scoped credential mint requires the sandbox's own supervisor",
        ));
    }
    let req = request.into_inner();
    let result = mint(state, &req).await;
    match &result {
        Ok(response) => info!(
            sandbox_id = %req.sandbox_id,
            provider = %req.provider,
            credential_key = %req.credential_key,
            scope = %req.scope,
            expires_at_ms = response
                .expiration_time
                .as_ref()
                .and_then(|time| openshell_core::time::timestamp_to_millis(time).ok())
                .unwrap_or_default(),
            "scoped provider credential minted"
        ),
        Err(status) => warn!(
            sandbox_id = %req.sandbox_id,
            provider = %req.provider,
            credential_key = %req.credential_key,
            scope = %req.scope,
            code = ?status.code(),
            reason = %status.message(),
            "scoped provider credential mint refused"
        ),
    }
    result.map(Response::new)
}

async fn mint(
    state: &ServerState,
    req: &MintScopedProviderCredentialRequest,
) -> Result<MintScopedProviderCredentialResponse, Status> {
    for (field, value) in [
        ("provider", req.provider.as_str()),
        ("credential_key", req.credential_key.as_str()),
        ("scope", req.scope.as_str()),
    ] {
        if value.trim().is_empty() || value.len() > MAX_FIELD_BYTES {
            return Err(Status::invalid_argument(format!(
                "{field} is required and must be at most {MAX_FIELD_BYTES} bytes"
            )));
        }
    }

    let sandbox = state
        .store
        .get_message::<Sandbox>(&req.sandbox_id)
        .await
        .map_err(|_| Status::unavailable("sandbox lookup failed"))?
        .ok_or_else(|| Status::not_found("sandbox not found"))?;
    let spec = sandbox
        .spec
        .as_ref()
        .ok_or_else(|| Status::failed_precondition("sandbox has no spec"))?;
    // The supervisor's metadata must come from the current attachment, and the
    // provider must still be part of it.
    if spec.provider_attachment_epoch != req.provider_attachment_epoch
        || !spec
            .providers
            .iter()
            .any(|provider| provider == &req.provider)
    {
        return Err(Status::permission_denied(
            "provider is not attached to the sandbox under the current attachment",
        ));
    }
    let workspace = sandbox.object_workspace().to_string();
    let provider = state
        .store
        .get_message_by_name::<Provider>(&workspace, &req.provider)
        .await
        .map_err(|_| Status::unavailable("provider lookup failed"))?
        .ok_or_else(|| Status::not_found("provider not found"))?;
    let catalog = state
        .provider_profile_sources
        .snapshot_catalog(state.store.as_ref(), &workspace)
        .await
        .map_err(|_| Status::unavailable("provider profile catalog unavailable"))?;
    let refresh =
        super::provider::provider_refresh_defaults(&catalog, &provider, &req.credential_key)
            .ok_or_else(|| {
                Status::failed_precondition("credential does not declare refresh metadata")
            })?;
    let request_scope = refresh.request_scope.as_ref().ok_or_else(|| {
        Status::failed_precondition("credential does not declare request-scoped refresh")
    })?;
    if refresh.strategy != ProviderCredentialRefreshStrategy::Oauth2ClientCredentials {
        return Err(Status::failed_precondition(
            "request-scoped refresh requires oauth2_client_credentials",
        ));
    }
    // Never trust the supervisor's rendering: the scope must be this
    // credential's template rendered with a value valid for its header.
    if !scope_matches_template(
        &request_scope.header,
        &request_scope.scope_template,
        &req.scope,
    ) {
        return Err(Status::invalid_argument(
            "scope is not the credential's scope template rendered with a valid value",
        ));
    }
    let refresh_state = crate::provider_refresh::get_refresh_state(
        state.store.as_ref(),
        &workspace,
        provider.object_id(),
        &req.credential_key,
    )
    .await
    .map_err(|_| Status::unavailable("provider refresh lookup failed"))?
    .filter(|refresh_state| {
        refresh_state
            .metadata
            .as_ref()
            .is_none_or(|metadata| metadata.deletion_time.is_none())
    })
    .ok_or_else(|| Status::failed_precondition("credential refresh is not configured"))?;

    let permits = sandbox_mint_permits(&req.sandbox_id)?;
    let _permit = tokio::time::timeout(SCOPED_MINT_ADMISSION_TIMEOUT, permits.acquire_owned())
        .await
        .map_err(|_| {
            Status::resource_exhausted("too many concurrent scoped credential mints for sandbox")
        })?
        .map_err(|_| Status::unavailable("scoped credential mint admission closed"))?;

    let minted = mint_scoped_client_credentials(&state.credentials, &refresh_state, &req.scope)
        .await
        .map_err(scoped_mint_status)?;
    Ok(MintScopedProviderCredentialResponse {
        access_token: minted.access_token,
        expiration_time: Some(
            openshell_core::time::timestamp_from_millis(minted.expires_at_ms)
                .map_err(|_| Status::unavailable("token issuer returned an invalid expiry"))?,
        ),
    })
}

/// Encode a failed mint without issuer-supplied text.
fn scoped_mint_status(failure: ScopedMintFailure) -> Status {
    match failure {
        ScopedMintFailure::IssuerRefused(code) => Status::with_error_details(
            Code::PermissionDenied,
            "token issuer refused the requested scope",
            ErrorDetails::with_error_info(
                ISSUER_REFUSED_REASON,
                ERROR_DOMAIN,
                HashMap::from([("code".to_string(), code.to_string())]),
            ),
        ),
        ScopedMintFailure::Configuration(code) => Status::failed_precondition(format!(
            "credential refresh cannot mint a scoped token ({code})"
        )),
        ScopedMintFailure::Unavailable(code) => {
            Status::unavailable(format!("token issuer unavailable ({code})"))
        }
    }
}

fn sandbox_mint_permits(sandbox_id: &str) -> Result<Arc<Semaphore>, Status> {
    let mut permits = SANDBOX_MINT_PERMITS
        .lock()
        .map_err(|_| Status::unavailable("scoped credential mint admission unavailable"))?;
    permits.retain(|_, semaphore| semaphore.strong_count() > 0);
    let semaphore = permits
        .get(sandbox_id)
        .and_then(Weak::upgrade)
        .unwrap_or_else(|| Arc::new(Semaphore::new(SCOPED_MINTS_PER_SANDBOX)));
    permits.insert(sandbox_id.to_string(), Arc::downgrade(&semaphore));
    Ok(semaphore)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::principal::{SandboxIdentitySource, SandboxPrincipal};
    use crate::grpc::test_support::test_server_state_without_provider_profiles;
    use crate::provider_refresh::{NewRefreshStateConfig, new_refresh_state, put_refresh_state};
    use openshell_core::proto::datamodel::v1::ObjectMeta;
    use openshell_core::proto::{SandboxSpec, StaticCredentialRequestScope};
    use openshell_core::request_scope::ScopedCredentialFailure;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const SANDBOX: &str = "scoped-sandbox";
    const EPOCH: &str = "attachment-epoch-1";
    const KEY: &str = "LORE_TOKEN";
    const PARTITION_HEX: &str = "000102030405060708090a0b0c0d0e0f";
    const DESCRIPTION_CANARY: &str = "ISSUER_DESCRIPTION_CANARY_5521";

    fn lore_profile(token_url: &str, request_scope: bool) -> String {
        let request_scope = if request_scope {
            "      request_scope:\n        header: lore-partition-bin\n        scope_template: \"lore-repo-{value}\"\n"
        } else {
            ""
        };
        format!(
            r"
id: lore
display_name: Lore
credentials:
  - name: lore_token
    env_vars: [LORE_TOKEN]
    required: true
    auth_style: bearer
    header_name: authorization
    refresh:
      strategy: oauth2_client_credentials
      token_url: {token_url}
      refresh_before: 60s
{request_scope}endpoints:
  - host: lore.example.com
    port: 443
    protocol: rest
    access: full
"
        )
    }

    struct Fixture {
        state: Arc<ServerState>,
        provider: Provider,
    }

    async fn fixture(token_url: &str, request_scope: bool, attached: bool) -> Fixture {
        let state = test_server_state_without_provider_profiles().await;
        let profile =
            openshell_providers::parse_profile_yaml(&lore_profile(token_url, request_scope))
                .unwrap()
                .to_proto();
        state
            .store
            .put_message(&crate::provider_profile_sources::stored_provider_profile(
                profile,
            ))
            .await
            .unwrap();
        let provider = Provider {
            metadata: Some(ObjectMeta {
                id: "lore-provider-id".to_string(),
                name: "lore".to_string(),
                workspace: "default".to_string(),
                ..Default::default()
            }),
            r#type: "lore".to_string(),
            profile_workspace: "default".to_string(),
            ..Default::default()
        };
        state.store.put_message(&provider).await.unwrap();
        state
            .store
            .put_message(&Sandbox {
                metadata: Some(ObjectMeta {
                    id: SANDBOX.to_string(),
                    name: SANDBOX.to_string(),
                    workspace: "default".to_string(),
                    ..Default::default()
                }),
                spec: Some(SandboxSpec {
                    providers: if attached {
                        vec!["lore".to_string()]
                    } else {
                        Vec::new()
                    },
                    provider_attachment_epoch: EPOCH.to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            })
            .await
            .unwrap();
        let mut refresh = new_refresh_state(
            &provider,
            "default",
            KEY,
            NewRefreshStateConfig {
                strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials,
                material: HashMap::from([("client_id".to_string(), "client-id".to_string())]),
                secret_material_keys: vec!["client_secret".to_string()],
                expires_at_ms: 0,
                token_url: token_url.to_string(),
                scopes: vec!["lore-all".to_string()],
                refresh_before: Some(prost_types::Duration {
                    seconds: 60,
                    nanos: 0,
                }),
                max_lifetime: None,
                additional_output_keys: HashMap::new(),
            },
        )
        .unwrap();
        refresh.secret_material_handles = state
            .credentials
            .store_refresh_material_with_object_id(
                crate::provider_refresh::refresh_material_scope(&refresh),
                "lore-client-secret",
                &HashMap::from([("client_secret".to_string(), "client-secret".to_string())]),
                &HashMap::new(),
            )
            .await
            .unwrap();
        put_refresh_state(state.store.as_ref(), &refresh)
            .await
            .unwrap();
        Fixture { state, provider }
    }

    fn mint_request(scope: &str) -> Request<MintScopedProviderCredentialRequest> {
        mint_request_as(SANDBOX, scope, EPOCH)
    }

    fn mint_request_as(
        principal: &str,
        scope: &str,
        epoch: &str,
    ) -> Request<MintScopedProviderCredentialRequest> {
        let mut request = Request::new(MintScopedProviderCredentialRequest {
            sandbox_id: SANDBOX.to_string(),
            provider: "lore".to_string(),
            credential_key: KEY.to_string(),
            scope: scope.to_string(),
            provider_attachment_epoch: epoch.to_string(),
        });
        request
            .extensions_mut()
            .insert(Principal::Sandbox(SandboxPrincipal {
                sandbox_id: principal.to_string(),
                source: SandboxIdentitySource::BootstrapJwt {
                    issuer: "test".to_string(),
                },
                trust_domain: None,
            }));
        request
    }

    fn lore_scope() -> String {
        format!("lore-repo-{PARTITION_HEX}")
    }

    async fn stored_refresh_version(fixture: &Fixture) -> u64 {
        crate::provider_refresh::get_refresh_state(
            fixture.state.store.as_ref(),
            "default",
            fixture.provider.object_id(),
            KEY,
        )
        .await
        .unwrap()
        .unwrap()
        .metadata
        .unwrap()
        .resource_version
    }

    #[tokio::test]
    async fn mints_the_rendered_scope_with_stored_client_material_and_persists_nothing() {
        let issuer = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .and(body_string_contains("grant_type=client_credentials"))
            .and(body_string_contains("client_id=client-id"))
            .and(body_string_contains("client_secret=client-secret"))
            .and(body_string_contains(format!(
                "scope=lore-repo-{PARTITION_HEX}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "synthetic-scoped-token",
                "expires_in": 600,
                "token_type": "Bearer"
            })))
            .expect(1)
            .mount(&issuer)
            .await;
        let fixture = fixture(&format!("{}/oauth/token", issuer.uri()), true, true).await;
        let version = stored_refresh_version(&fixture).await;
        let before_ms = openshell_core::time::now_ms();

        let response =
            handle_mint_scoped_provider_credential(&fixture.state, mint_request(&lore_scope()))
                .await
                .unwrap()
                .into_inner();

        assert_eq!(response.access_token, "synthetic-scoped-token");
        let expires_at_ms =
            openshell_core::time::timestamp_to_millis(response.expiration_time.as_ref().unwrap())
                .unwrap();
        assert!(expires_at_ms >= before_ms + 599_000);
        assert!(expires_at_ms <= openshell_core::time::now_ms() + 600_000);
        assert_eq!(stored_refresh_version(&fixture).await, version);
        let stored = fixture
            .state
            .store
            .get_message_by_name::<Provider>("default", "lore")
            .await
            .unwrap()
            .unwrap();
        assert!(stored.credentials.is_empty());
        assert!(stored.credential_handles.is_empty());
        assert!(stored.credential_expiration_times.is_empty());
    }

    #[tokio::test]
    async fn refuses_unattached_provider_or_stale_attachment_before_minting() {
        let issuer = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&issuer)
            .await;
        let token_url = format!("{}/oauth/token", issuer.uri());
        let unattached = fixture(&token_url, true, false).await;
        let error =
            handle_mint_scoped_provider_credential(&unattached.state, mint_request(&lore_scope()))
                .await
                .unwrap_err();
        assert_eq!(error.code(), Code::PermissionDenied);
        assert_eq!(
            ScopedCredentialFailure::from_status(&error),
            ScopedCredentialFailure::GatewayRefused
        );

        let attached = fixture(&token_url, true, true).await;
        let error = handle_mint_scoped_provider_credential(
            &attached.state,
            mint_request_as(SANDBOX, &lore_scope(), "previous-epoch"),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), Code::PermissionDenied);

        let error = handle_mint_scoped_provider_credential(
            &attached.state,
            mint_request_as("other-sandbox", &lore_scope(), EPOCH),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), Code::PermissionDenied);
    }

    #[tokio::test]
    async fn refuses_credentials_without_request_scope_and_foreign_scopes() {
        let issuer = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&issuer)
            .await;
        let token_url = format!("{}/oauth/token", issuer.uri());
        let plain = fixture(&token_url, false, true).await;
        let error =
            handle_mint_scoped_provider_credential(&plain.state, mint_request(&lore_scope()))
                .await
                .unwrap_err();
        assert_eq!(error.code(), Code::FailedPrecondition);

        let scoped = fixture(&token_url, true, true).await;
        for scope in [
            "lore-all".to_string(),
            "lore-repo-ABCDEF".to_string(),
            format!("lore-repo-{PARTITION_HEX} lore-all"),
            format!("other-{PARTITION_HEX}"),
        ] {
            let error = handle_mint_scoped_provider_credential(&scoped.state, mint_request(&scope))
                .await
                .unwrap_err();
            assert_eq!(error.code(), Code::InvalidArgument, "{scope}");
            assert_eq!(
                ScopedCredentialFailure::from_status(&error),
                ScopedCredentialFailure::GatewayRefused
            );
        }
    }

    #[tokio::test]
    async fn issuer_oauth_error_is_a_distinct_refusal_without_its_description() {
        let issuer = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_scope",
                "error_description": DESCRIPTION_CANARY,
            })))
            .expect(1)
            .mount(&issuer)
            .await;
        let fixture = fixture(&format!("{}/oauth/token", issuer.uri()), true, true).await;

        let error =
            handle_mint_scoped_provider_credential(&fixture.state, mint_request(&lore_scope()))
                .await
                .unwrap_err();

        assert_eq!(error.code(), Code::PermissionDenied);
        assert_eq!(
            openshell_core::rpc_error::reason(&error).as_deref(),
            Some(ISSUER_REFUSED_REASON)
        );
        assert_eq!(
            ScopedCredentialFailure::from_status(&error),
            ScopedCredentialFailure::IssuerRefused
        );
        assert!(!format!("{error:?}").contains(DESCRIPTION_CANARY));
        assert!(!String::from_utf8_lossy(error.details()).contains(DESCRIPTION_CANARY));
    }

    #[tokio::test]
    async fn issuer_server_failure_is_unavailable() {
        let issuer = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(503).set_body_string(DESCRIPTION_CANARY))
            .expect(1)
            .mount(&issuer)
            .await;
        let fixture = fixture(&format!("{}/oauth/token", issuer.uri()), true, true).await;

        let error =
            handle_mint_scoped_provider_credential(&fixture.state, mint_request(&lore_scope()))
                .await
                .unwrap_err();

        assert_eq!(error.code(), Code::Unavailable);
        assert_eq!(
            ScopedCredentialFailure::from_status(&error),
            ScopedCredentialFailure::Unavailable
        );
        assert!(!format!("{error:?}").contains(DESCRIPTION_CANARY));
    }

    #[tokio::test]
    async fn issuer_temporary_oauth_error_is_unavailable() {
        let issuer = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "temporarily_unavailable",
            })))
            .mount(&issuer)
            .await;
        let fixture = fixture(&format!("{}/oauth/token", issuer.uri()), true, true).await;
        let error =
            handle_mint_scoped_provider_credential(&fixture.state, mint_request(&lore_scope()))
                .await
                .unwrap_err();
        assert_eq!(
            ScopedCredentialFailure::from_status(&error),
            ScopedCredentialFailure::Unavailable
        );
    }

    #[tokio::test]
    async fn environment_bindings_carry_request_scope_and_current_attachment() {
        let fixture = fixture("https://hub.example.com/oauth/token", true, true).await;
        let catalog = fixture
            .state
            .provider_profile_sources
            .snapshot_catalog(fixture.state.store.as_ref(), "default")
            .await
            .unwrap();
        let mut provider = fixture.provider.clone();
        provider
            .credentials
            .insert(KEY.to_string(), "synthetic-ordinary-token".to_string());
        let records = vec![super::super::provider::ProviderEnvironmentRecord {
            name: "lore".to_string(),
            object_id: provider.object_id().to_string(),
            resource_version: 1,
            refresh_states: crate::provider_refresh::list_refresh_states_for_provider(
                fixture.state.store.as_ref(),
                provider.object_id(),
            )
            .await
            .unwrap(),
            provider,
        }];
        let environment = super::super::provider::resolve_provider_environment_from_records_with_policy_bindings_and_credentials(
            &catalog,
            &records,
            &HashMap::new(),
            &fixture.state.credentials,
            Some(SANDBOX),
        )
        .await
        .unwrap();
        let binding = environment.static_credential_bindings.get(KEY).unwrap();
        assert_eq!(
            binding.request_scope,
            Some(StaticCredentialRequestScope {
                provider: "lore".to_string(),
                request_scope: Some(openshell_core::proto::ProviderCredentialRequestScope {
                    header: "lore-partition-bin".to_string(),
                    scope_template: "lore-repo-{value}".to_string(),
                }),
                refresh_before: Some(prost_types::Duration {
                    seconds: 60,
                    nanos: 0,
                }),
                // The snapshot builder stamps the sandbox's attachment.
                provider_attachment_epoch: String::new(),
            })
        );
    }
}
