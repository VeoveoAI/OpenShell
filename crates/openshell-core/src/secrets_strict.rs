// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Strict credential binding.
//!
//! A strict endpoint binding admits a request only when the request's
//! credential is a placeholder of a credential bound at that endpoint. The
//! request's credential is whatever it carries at a credential position: the
//! `Authorization` header and each position that a bound credential declares
//! through its profile `auth_style`. Every position the request carries must
//! hold exactly one bound placeholder, and the request must carry at least one
//! position. A literal value, a placeholder of an unbound credential, or a
//! request without any credential position is refused.
//!
//! The check reads only placeholder syntax and environment keys. It never
//! materializes a secret, and its errors never carry the refused value.

use super::{
    PLACEHOLDER_PREFIX, UnresolvedPlaceholderError, UnresolvedPlaceholderReason, alias_token_at,
    basic_auth_token, canonical_token_at, decode_basic_auth_token, percent_decode,
    placeholder_env_key,
};
use std::collections::HashSet;

const AUTHORIZATION: &str = "authorization";
const PATH_TEMPLATE_CREDENTIAL: &str = "{credential}";

/// One place in an HTTP request that carries a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialPosition {
    /// A request header, by lowercase field name. A header position may
    /// occur more than once; every occurrence is checked.
    Header(String),
    /// A query parameter, by exact name. Every occurrence is checked.
    Query(String),
    /// The path segment that a path template marks with `{credential}`.
    Path(PathCredentialPosition),
}

/// The `{credential}` segment of a path template.
///
/// The position is present in a request path whose segments before it equal
/// the template's literal segments and whose segment at that index starts
/// with `prefix` and ends with `suffix`. The text between them is the
/// credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathCredentialPosition {
    leading: Vec<String>,
    prefix: String,
    suffix: String,
}

impl CredentialPosition {
    /// Build the position a provider profile credential declares.
    ///
    /// `auth_style` accepts the profile values `basic`, `bearer`, `header`,
    /// `query`, and `path`. An empty style declares no position.
    ///
    /// # Errors
    ///
    /// Returns a static description when the style is unknown or its
    /// required field is missing or malformed.
    pub fn from_placement(
        auth_style: &str,
        header_name: &str,
        query_param: &str,
        path_template: &str,
    ) -> Result<Option<Self>, &'static str> {
        match auth_style.trim().to_ascii_lowercase().as_str() {
            "" => Ok(None),
            "basic" => {
                let header = header_name.trim();
                let header = if header.is_empty() {
                    AUTHORIZATION
                } else {
                    header
                };
                Ok(Some(Self::header(header)?))
            }
            "bearer" | "header" => Ok(Some(Self::header(header_name.trim())?)),
            "query" => {
                let name = query_param.trim();
                if name.is_empty() {
                    return Err("query credential placement has no query parameter");
                }
                Ok(Some(Self::Query(name.to_string())))
            }
            "path" => Ok(Some(Self::Path(PathCredentialPosition::from_template(
                path_template,
            )?))),
            _ => Err("credential placement has an unsupported auth style"),
        }
    }

    fn header(name: &str) -> Result<Self, &'static str> {
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
        {
            return Err("header credential placement has an invalid header name");
        }
        Ok(Self::Header(name.to_ascii_lowercase()))
    }
}

impl PathCredentialPosition {
    fn from_template(template: &str) -> Result<Self, &'static str> {
        let template = template.trim();
        let malformed = "path credential placement needs a path template starting with / that contains {credential} exactly once";
        if !template.starts_with('/') || template.matches(PATH_TEMPLATE_CREDENTIAL).count() != 1 {
            return Err(malformed);
        }
        let segments = template.split('/').collect::<Vec<_>>();
        let index = segments
            .iter()
            .position(|segment| segment.contains(PATH_TEMPLATE_CREDENTIAL))
            .ok_or(malformed)?;
        let (prefix, suffix) = segments[index]
            .split_once(PATH_TEMPLATE_CREDENTIAL)
            .ok_or(malformed)?;
        Ok(Self {
            leading: segments[..index].iter().map(ToString::to_string).collect(),
            prefix: prefix.to_string(),
            suffix: suffix.to_string(),
        })
    }

    /// The credential text of `path`, or `None` when the path does not have
    /// this position.
    fn credential_in(&self, path: &str) -> Option<String> {
        let segments = path.split('/').map(percent_decode).collect::<Vec<_>>();
        let index = self.leading.len();
        if segments.len() <= index || segments[..index] != self.leading[..] {
            return None;
        }
        let segment = &segments[index];
        (segment.len() >= self.prefix.len() + self.suffix.len()
            && segment.starts_with(&self.prefix)
            && segment.ends_with(&self.suffix))
        .then(|| segment[self.prefix.len()..segment.len() - self.suffix.len()].to_string())
    }
}

/// The strict requirement for one request endpoint.
///
/// `env_keys` are the credential environment keys bound at the endpoint.
/// `positions` always include the `Authorization` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrictCredentialBinding {
    positions: Vec<CredentialPosition>,
    env_keys: HashSet<String>,
}

impl StrictCredentialBinding {
    /// Require a placeholder of one of `env_keys` at the `Authorization`
    /// header and at every declared position.
    #[must_use]
    pub fn new(
        env_keys: HashSet<String>,
        declared: impl IntoIterator<Item = CredentialPosition>,
    ) -> Self {
        let mut positions = vec![CredentialPosition::Header(AUTHORIZATION.to_string())];
        for position in declared {
            if !positions.contains(&position) {
                positions.push(position);
            }
        }
        Self {
            positions,
            env_keys,
        }
    }

    /// Check one HTTP/1 request header block, request line included.
    ///
    /// Absolute-form request targets are reduced to their path and query.
    pub(super) fn check_request(
        &self,
        denied_env_keys: &HashSet<String>,
        header_block: &str,
    ) -> Result<(), UnresolvedPlaceholderError> {
        let mut lines = header_block.split("\r\n");
        let target = lines
            .next()
            .and_then(|line| line.split(' ').nth(1))
            .map_or("", origin_form_target);
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let headers = lines
            .take_while(|line| !line.is_empty())
            .filter_map(|line| line.split_once(':'))
            .collect::<Vec<_>>();

        let check = CredentialCheck {
            env_keys: &self.env_keys,
            denied_env_keys,
        };
        let mut carried = false;
        for position in &self.positions {
            match position {
                CredentialPosition::Header(name) => {
                    for (_, value) in headers
                        .iter()
                        .filter(|(field, _)| field.trim().eq_ignore_ascii_case(name))
                    {
                        check.header_value(value.trim())?;
                        carried = true;
                    }
                }
                CredentialPosition::Query(name) => {
                    for (_, value) in query
                        .split('&')
                        .filter_map(|param| param.split_once('='))
                        .filter(|(key, _)| percent_decode(key) == *name)
                    {
                        check.token(&percent_decode(value), "query_param")?;
                        carried = true;
                    }
                }
                CredentialPosition::Path(template) => {
                    if let Some(credential) = template.credential_in(path) {
                        check.token(&credential, "path")?;
                        carried = true;
                    }
                }
            }
        }
        if carried {
            Ok(())
        } else {
            Err(placeholder_required("header"))
        }
    }
}

struct CredentialCheck<'a> {
    env_keys: &'a HashSet<String>,
    denied_env_keys: &'a HashSet<String>,
}

impl CredentialCheck<'_> {
    /// A header credential is a bound placeholder, optionally after one
    /// authentication scheme token. Basic credentials are decoded: each
    /// non-empty part of `user-id:password` must be a bound placeholder.
    fn header_value(&self, value: &str) -> Result<(), UnresolvedPlaceholderError> {
        if let Some(encoded) = basic_auth_token(value) {
            let decoded =
                decode_basic_auth_token(encoded).ok_or_else(|| placeholder_required("header"))?;
            let parts: [&str; 2] = split_basic_credentials(&decoded).into();
            let parts = parts
                .into_iter()
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>();
            if parts.is_empty() {
                return Err(placeholder_required("header"));
            }
            return parts
                .into_iter()
                .try_for_each(|part| self.token(part, "header"));
        }
        let credential = value
            .split_once(char::is_whitespace)
            .map_or(value, |(_, credential)| credential.trim());
        self.token(credential, "header")
    }

    /// `value` must be exactly one placeholder of a credential bound here.
    fn token(&self, value: &str, location: &'static str) -> Result<(), UnresolvedPlaceholderError> {
        let token = if value.starts_with(PLACEHOLDER_PREFIX) {
            canonical_token_at(value, 0)
        } else {
            alias_token_at(value, 0)
        }
        .filter(|(end, _)| *end == value.len())
        .map(|(_, token)| token);
        let Some(key) = token.and_then(placeholder_env_key) else {
            return Err(placeholder_required(location));
        };
        if self.env_keys.contains(key) {
            Ok(())
        } else if self.denied_env_keys.contains(key) {
            Err(UnresolvedPlaceholderError {
                location,
                reason: UnresolvedPlaceholderReason::EndpointMismatch,
            })
        } else {
            Err(placeholder_required(location))
        }
    }
}

/// Split decoded Basic credentials into user-id and password.
///
/// A user-id cannot contain a colon, but a canonical placeholder does, so a
/// user-id that is a whole placeholder ends where the placeholder ends.
fn split_basic_credentials(decoded: &str) -> (&str, &str) {
    let user_end = canonical_token_at(decoded, 0)
        .map(|(end, _)| end)
        .filter(|end| decoded[*end..].is_empty() || decoded[*end..].starts_with(':'))
        .or_else(|| decoded.find(':'))
        .unwrap_or(decoded.len());
    (
        &decoded[..user_end],
        decoded.get(user_end + 1..).unwrap_or(""),
    )
}

fn placeholder_required(location: &'static str) -> UnresolvedPlaceholderError {
    UnresolvedPlaceholderError {
        location,
        reason: UnresolvedPlaceholderReason::PlaceholderRequired,
    }
}

/// Reduce an absolute-form request target to its path and query.
fn origin_form_target(target: &str) -> &str {
    let lower = target.get(..8).unwrap_or(target).to_ascii_lowercase();
    let Some(after_scheme) = ["http://", "https://"]
        .into_iter()
        .find(|scheme| lower.starts_with(scheme))
        .map(|scheme| &target[scheme.len()..])
    else {
        return target;
    };
    after_scheme
        .find(['/', '?'])
        .map_or("/", |start| &after_scheme[start..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::{SecretResolver, placeholder_for_env_key_for_revision};
    use base64::Engine as _;
    use std::collections::HashMap;
    use std::sync::Arc;

    const TOKEN: &str = "API_TOKEN";
    const OTHER: &str = "OTHER_TOKEN";
    const SECRET: &str = "real-secret-value";

    fn keys(keys: &[&str]) -> HashSet<String> {
        keys.iter().map(ToString::to_string).collect()
    }

    /// A resolver scoped to an endpoint that binds `TOKEN` strictly and
    /// denies `OTHER`, as `ProviderCredentialState` builds it.
    fn strict_resolver(declared: Vec<CredentialPosition>) -> (SecretResolver, String) {
        let (env, resolver) = SecretResolver::from_provider_env_for_revision(
            HashMap::from([
                (TOKEN.to_string(), SECRET.to_string()),
                (OTHER.to_string(), "other-secret".to_string()),
            ]),
            HashMap::new(),
            3,
        );
        let resolver = resolver.expect("resolver").scoped_to_env_keys(
            &keys(&[TOKEN, OTHER]),
            &keys(&[TOKEN]),
            HashMap::from([(TOKEN.to_string(), Arc::new(HashSet::from([3])))]),
        );
        let binding = StrictCredentialBinding::new(keys(&[TOKEN]), declared);
        (
            resolver.with_strict_binding(Arc::new(binding)),
            env[TOKEN].clone(),
        )
    }

    fn request(target: &str, headers: &[(&str, &str)]) -> String {
        let mut raw = format!("GET {target} HTTP/1.1\r\nHost: api.example.com\r\n");
        for (name, value) in headers {
            raw.push_str(name);
            raw.push_str(": ");
            raw.push_str(value);
            raw.push_str("\r\n");
        }
        raw.push_str("\r\n");
        raw
    }

    fn rewrite(resolver: &SecretResolver, raw: &str) -> Result<String, UnresolvedPlaceholderError> {
        crate::secrets::rewrite_http_header_block(raw.as_bytes(), Some(resolver))
            .map(|result| String::from_utf8(result.rewritten).expect("utf-8"))
    }

    fn header(name: &str) -> CredentialPosition {
        CredentialPosition::from_placement("header", name, "", "")
            .expect("valid")
            .expect("position")
    }

    fn assert_placeholder_required(result: Result<String, UnresolvedPlaceholderError>) {
        let error = result.expect_err("strict binding must refuse the request");
        assert!(error.is_placeholder_required(), "{error}");
        assert!(error.is_denied());
        assert!(!error.is_endpoint_mismatch());
        assert!(!error.to_string().contains(SECRET));
    }

    #[test]
    fn bearer_placeholder_is_admitted_and_substituted() {
        let (resolver, placeholder) = strict_resolver(Vec::new());
        let rewritten = rewrite(
            &resolver,
            &request(
                "/v1/chat",
                &[("Authorization", &format!("Bearer {placeholder}"))],
            ),
        )
        .expect("bound placeholder is admitted");
        assert!(rewritten.contains(&format!("Authorization: Bearer {SECRET}\r\n")));
        assert!(!rewritten.contains("openshell:resolve:env:"));
    }

    #[test]
    fn literal_bearer_credential_is_refused() {
        let (resolver, _) = strict_resolver(Vec::new());
        assert_placeholder_required(rewrite(
            &resolver,
            &request(
                "/v1/chat",
                &[("Authorization", "Bearer sk-typed-into-the-app")],
            ),
        ));
    }

    #[test]
    fn request_without_a_credential_is_refused() {
        let (resolver, _) = strict_resolver(vec![header("x-api-key")]);
        assert_placeholder_required(rewrite(
            &resolver,
            &request("/v1/chat", &[("Accept", "application/json")]),
        ));
    }

    #[test]
    fn declared_header_carries_the_credential() {
        let (resolver, placeholder) = strict_resolver(vec![header("X-Api-Key")]);
        let rewritten = rewrite(&resolver, &request("/v1", &[("x-api-key", &placeholder)]))
            .expect("declared header placeholder is admitted");
        assert!(rewritten.contains(&format!("x-api-key: {SECRET}\r\n")));

        assert_placeholder_required(rewrite(
            &resolver,
            &request("/v1", &[("X-API-KEY", "typed-secret")]),
        ));
    }

    #[test]
    fn literal_authorization_beside_a_placeholder_is_refused() {
        let (resolver, placeholder) = strict_resolver(vec![header("x-api-key")]);
        assert_placeholder_required(rewrite(
            &resolver,
            &request(
                "/v1",
                &[
                    ("x-api-key", &placeholder),
                    ("Authorization", "Bearer typed-oauth-token"),
                ],
            ),
        ));
    }

    #[test]
    fn every_occurrence_of_a_position_must_carry_a_placeholder() {
        let (resolver, placeholder) = strict_resolver(Vec::new());
        assert_placeholder_required(rewrite(
            &resolver,
            &request(
                "/v1",
                &[
                    ("Authorization", &format!("Bearer {placeholder}")),
                    ("authorization", "Bearer typed"),
                ],
            ),
        ));
    }

    #[test]
    fn placeholder_with_extra_text_is_refused() {
        let (resolver, placeholder) = strict_resolver(Vec::new());
        for value in [
            format!("Bearer {placeholder}suffix"),
            format!("Bearer prefix{placeholder}"),
            format!("Bearer {placeholder} extra"),
        ] {
            assert!(
                rewrite(&resolver, &request("/v1", &[("Authorization", &value)])).is_err(),
                "{value}"
            );
        }
    }

    #[test]
    fn unbound_placeholder_reports_endpoint_mismatch() {
        let (resolver, _) = strict_resolver(Vec::new());
        let other = placeholder_for_env_key_for_revision(OTHER, 3);
        let error = rewrite(
            &resolver,
            &request("/v1", &[("Authorization", &format!("Bearer {other}"))]),
        )
        .expect_err("unbound placeholder");
        assert!(error.is_endpoint_mismatch());
        assert!(error.is_denied());
    }

    #[test]
    fn unknown_placeholder_is_refused() {
        let (resolver, _) = strict_resolver(Vec::new());
        assert_placeholder_required(rewrite(
            &resolver,
            &request(
                "/v1",
                &[("Authorization", "Bearer openshell:resolve:env:v3_UNKNOWN")],
            ),
        ));
    }

    #[test]
    fn basic_credentials_require_placeholders_in_every_part() {
        let (resolver, placeholder) = strict_resolver(vec![
            CredentialPosition::from_placement("basic", "", "", "")
                .expect("valid")
                .expect("position"),
        ]);
        let b64 = |text: &str| base64::engine::general_purpose::STANDARD.encode(text);

        for admitted in [format!("{placeholder}:"), format!(":{placeholder}")] {
            let rewritten = rewrite(
                &resolver,
                &request(
                    "/v1",
                    &[("Authorization", &format!("Basic {}", b64(&admitted)))],
                ),
            )
            .expect("placeholder-only basic credential is admitted");
            let expected = admitted.replace(&placeholder, SECRET);
            assert!(rewritten.contains(&format!("Authorization: Basic {}\r\n", b64(&expected))));
        }

        for refused in [
            "user:typed-password".to_string(),
            format!("typed-user:{placeholder}"),
            format!("{placeholder}:typed-password"),
            ":".to_string(),
        ] {
            assert_placeholder_required(rewrite(
                &resolver,
                &request(
                    "/v1",
                    &[("Authorization", &format!("Basic {}", b64(&refused)))],
                ),
            ));
        }
        assert_placeholder_required(rewrite(
            &resolver,
            &request("/v1", &[("Authorization", "Basic !!not-base64!!")]),
        ));
    }

    #[test]
    fn query_credential_position() {
        let (resolver, placeholder) = strict_resolver(vec![
            CredentialPosition::from_placement("query", "", "key", "")
                .expect("valid")
                .expect("position"),
        ]);
        let rewritten = rewrite(
            &resolver,
            &request(&format!("/maps?key={placeholder}&q=paris"), &[]),
        )
        .expect("query placeholder is admitted");
        assert!(rewritten.starts_with(&format!("GET /maps?key={SECRET}&q=paris HTTP/1.1")));

        assert_placeholder_required(rewrite(
            &resolver,
            &request("/maps?key=typed-key&q=paris", &[]),
        ));
        assert_placeholder_required(rewrite(
            &resolver,
            &request(&format!("/maps?key={placeholder}&key=typed"), &[]),
        ));
        assert_placeholder_required(rewrite(&resolver, &request("/maps?q=paris", &[])));
    }

    #[test]
    fn path_credential_position() {
        let (resolver, placeholder) = strict_resolver(vec![
            CredentialPosition::from_placement("path", "", "", "/bot{credential}/sendMessage")
                .expect("valid")
                .expect("position"),
        ]);
        let rewritten = rewrite(
            &resolver,
            &request(&format!("/bot{placeholder}/getUpdates"), &[]),
        )
        .expect("path placeholder is admitted");
        assert!(rewritten.starts_with(&format!("GET /bot{SECRET}/getUpdates HTTP/1.1")));

        assert_placeholder_required(rewrite(
            &resolver,
            &request("/bot123456:typed-token/getUpdates", &[]),
        ));
        // A path without the position carries no credential.
        assert_placeholder_required(rewrite(&resolver, &request("/health", &[])));
    }

    #[test]
    fn absolute_form_targets_are_checked_by_path_and_query() {
        let binding = StrictCredentialBinding::new(
            keys(&[TOKEN]),
            [CredentialPosition::Query("key".to_string())],
        );
        let placeholder = placeholder_for_env_key_for_revision(TOKEN, 3);
        binding
            .check_request(
                &HashSet::new(),
                &format!("GET http://api.example.com/maps?key={placeholder} HTTP/1.1\r\n\r\n"),
            )
            .expect("absolute-form query placeholder is admitted");
        assert!(
            binding
                .check_request(
                    &HashSet::new(),
                    "GET HTTP://api.example.com?key=typed HTTP/1.1\r\n\r\n",
                )
                .expect_err("literal")
                .is_placeholder_required()
        );
    }

    #[test]
    fn non_strict_resolver_is_unchanged() {
        let (env, resolver) = SecretResolver::from_provider_env_for_revision(
            HashMap::from([(TOKEN.to_string(), SECRET.to_string())]),
            HashMap::new(),
            3,
        );
        let resolver = resolver.expect("resolver");
        let raw = request("/v1", &[("Authorization", "Bearer typed-literal")]);
        assert_eq!(rewrite(&resolver, &raw).expect("literal passes"), raw);
        assert!(rewrite(&resolver, &request("/v1", &[])).is_ok());
        let rewritten = rewrite(
            &resolver,
            &request(
                "/v1",
                &[("Authorization", &format!("Bearer {}", env[TOKEN]))],
            ),
        )
        .expect("placeholder resolves");
        assert!(rewritten.contains(&format!("Bearer {SECRET}")));
    }

    #[test]
    fn placements_validate_their_required_fields() {
        assert_eq!(CredentialPosition::from_placement("", "", "", ""), Ok(None));
        assert_eq!(
            CredentialPosition::from_placement("Bearer", "Authorization", "", ""),
            Ok(Some(CredentialPosition::Header(
                "authorization".to_string()
            )))
        );
        for (style, header, query, path) in [
            ("bearer", "", "", ""),
            ("header", "bad header", "", ""),
            ("query", "", "", ""),
            ("path", "", "", "/v1/resources"),
            ("path", "", "", "v1/{credential}"),
            ("path", "", "", "/{credential}/{credential}"),
            ("cookie", "", "", ""),
        ] {
            assert!(
                CredentialPosition::from_placement(style, header, query, path).is_err(),
                "{style} {header} {query} {path}"
            );
        }
    }
}
