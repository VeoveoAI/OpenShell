// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Request-scoped refresh: derive an OAuth scope from one request header.
//!
//! A credential's `refresh.request_scope` names a request header and a scope
//! template. The supervisor renders the template from a request's header value
//! and the gateway re-validates the rendered scope before it mints a token, so
//! both sides use these rules.

use base64::Engine as _;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use tonic::{Code, Status};

/// The placeholder a scope template contains exactly once.
pub const VALUE_PLACEHOLDER: &str = "{value}";

/// `google.rpc.ErrorInfo` reason of a scoped mint the token issuer refused.
pub const ISSUER_REFUSED_REASON: &str = "SCOPED_CREDENTIAL_ISSUER_REFUSED";

/// Why a scoped credential mint produced no token, as a supervisor acts on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopedCredentialFailure {
    /// The token issuer refused the scope. The request keeps its ordinary
    /// token, so the upstream service refuses it natively.
    IssuerRefused,
    /// The gateway refused to mint for this request, for example after a
    /// profile or attachment change. The request keeps its ordinary token.
    GatewayRefused,
    /// The gateway or the issuer is unavailable. The request is not forwarded.
    Unavailable,
}

impl ScopedCredentialFailure {
    /// Classify a `MintScopedProviderCredential` failure.
    ///
    /// Only an explicit refusal keeps the request moving; every other status,
    /// including transport failures, means the scoped token is unavailable.
    #[must_use]
    pub fn from_status(status: &Status) -> Self {
        match status.code() {
            Code::PermissionDenied
                if crate::rpc_error::reason(status).as_deref() == Some(ISSUER_REFUSED_REASON) =>
            {
                Self::IssuerRefused
            }
            Code::PermissionDenied
            | Code::FailedPrecondition
            | Code::InvalidArgument
            | Code::NotFound => Self::GatewayRefused,
            _ => Self::Unavailable,
        }
    }

    /// Stable log code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::IssuerRefused => "issuer_refused",
            Self::GatewayRefused => "gateway_refused",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Longest accepted header name.
pub const MAX_HEADER_NAME_BYTES: usize = 128;
/// Longest accepted scope template.
pub const MAX_SCOPE_TEMPLATE_BYTES: usize = 256;
/// Longest decoded value of a binary (`-bin`) header.
pub const MAX_BINARY_VALUE_BYTES: usize = 64;
/// Longest value of a text header.
pub const MAX_TEXT_VALUE_BYTES: usize = 256;

const BINARY_HEADER_SUFFIX: &str = "-bin";

/// Fields that describe one connection rather than the request.
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Fields that carry credentials or routing and must not select a scope.
const RESERVED_HEADERS: &[&str] = &["authorization", "cookie", "host"];

/// gRPC binary metadata is standard base64, with padding optional.
const BINARY_HEADER_ENGINE: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// Validate the header that selects a request scope.
///
/// # Errors
///
/// Returns a message naming the violated rule.
pub fn validate_header_name(header: &str) -> Result<(), String> {
    if header.is_empty() {
        return Err("request_scope.header is required".to_string());
    }
    if header.starts_with(':') {
        return Err(format!(
            "request_scope.header '{header}' must not be an HTTP/2 pseudo-header"
        ));
    }
    if header.len() > MAX_HEADER_NAME_BYTES || !header.bytes().all(is_lowercase_tchar) {
        return Err(format!(
            "request_scope.header '{header}' must be a lowercase HTTP field name of at most {MAX_HEADER_NAME_BYTES} bytes"
        ));
    }
    if HOP_BY_HOP_HEADERS.contains(&header) {
        return Err(format!(
            "request_scope.header '{header}' must not be a hop-by-hop field"
        ));
    }
    if RESERVED_HEADERS.contains(&header) {
        return Err(format!("request_scope.header must not be '{header}'"));
    }
    Ok(())
}

/// Validate a scope template: `{value}` exactly once, plus only RFC 6749
/// section 3.3 scope-token characters.
///
/// # Errors
///
/// Returns a message naming the violated rule.
pub fn validate_scope_template(template: &str) -> Result<(), String> {
    if template.len() > MAX_SCOPE_TEMPLATE_BYTES {
        return Err(format!(
            "request_scope.scope_template must be at most {MAX_SCOPE_TEMPLATE_BYTES} bytes"
        ));
    }
    let count = template.matches(VALUE_PLACEHOLDER).count();
    if count != 1 {
        return Err(format!(
            "request_scope.scope_template must contain {VALUE_PLACEHOLDER} exactly once, found {count}"
        ));
    }
    if !template
        .replacen(VALUE_PLACEHOLDER, "", 1)
        .bytes()
        .all(is_scope_char)
    {
        return Err(
            "request_scope.scope_template may contain only OAuth scope characters (RFC 6749 section 3.3): printable ASCII except space, '\"' and '\\'"
                .to_string(),
        );
    }
    Ok(())
}

/// Render one raw request header value into the scope `{value}`.
///
/// A binary (`-bin`) header is base64-decoded to 1 to 64 bytes and rendered as
/// lowercase hex. A text header must match `[A-Za-z0-9._~-]{1,256}`. Returns
/// `None` for any other value.
#[must_use]
pub fn render_value(header: &str, raw_value: &str) -> Option<String> {
    let value = raw_value.trim_matches([' ', '\t']);
    if is_binary_header(header) {
        let bytes = BINARY_HEADER_ENGINE.decode(value).ok()?;
        if bytes.is_empty() || bytes.len() > MAX_BINARY_VALUE_BYTES {
            return None;
        }
        Some(lowercase_hex(&bytes))
    } else {
        is_text_value(value).then(|| value.to_string())
    }
}

/// Render the scope for a request that carries `values` for the scope header.
///
/// The request must carry the header exactly once with a valid value.
#[must_use]
pub fn render_scope(header: &str, scope_template: &str, values: &[&str]) -> Option<String> {
    let [value] = values else {
        return None;
    };
    let value = render_value(header, value)?;
    Some(scope_template.replacen(VALUE_PLACEHOLDER, &value, 1))
}

/// Whether `scope` is `scope_template` rendered with a valid value for `header`.
#[must_use]
pub fn scope_matches_template(header: &str, scope_template: &str, scope: &str) -> bool {
    let Some((prefix, suffix)) = scope_template.split_once(VALUE_PLACEHOLDER) else {
        return false;
    };
    let Some(value) = scope
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_suffix(suffix))
    else {
        return false;
    };
    if is_binary_header(header) {
        value.len() % 2 == 0
            && (2..=MAX_BINARY_VALUE_BYTES * 2).contains(&value.len())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    } else {
        is_text_value(value)
    }
}

fn is_binary_header(header: &str) -> bool {
    header.ends_with(BINARY_HEADER_SUFFIX)
}

fn is_text_value(value: &str) -> bool {
    (1..=MAX_TEXT_VALUE_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-'))
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut rendered = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        rendered.push(char::from(DIGITS[usize::from(byte >> 4)]));
        rendered.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    rendered
}

/// RFC 9110 `tchar`, restricted to lowercase letters.
fn is_lowercase_tchar(byte: u8) -> bool {
    byte.is_ascii_lowercase()
        || byte.is_ascii_digit()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// RFC 6749 section 3.3 `NQCHAR`.
fn is_scope_char(byte: u8) -> bool {
    matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LORE_HEADER: &str = "lore-partition-bin";
    const LORE_TEMPLATE: &str = "lore-repo-{value}";
    // 16 bytes 0x00..=0x0f.
    const PARTITION_PADDED: &str = "AAECAwQFBgcICQoLDA0ODw==";
    const PARTITION_UNPADDED: &str = "AAECAwQFBgcICQoLDA0ODw";
    const PARTITION_HEX: &str = "000102030405060708090a0b0c0d0e0f";

    #[test]
    fn binary_header_renders_padded_and_unpadded_values_as_lowercase_hex() {
        for raw in [
            PARTITION_PADDED,
            PARTITION_UNPADDED,
            " AAECAwQFBgcICQoLDA0ODw== ",
        ] {
            assert_eq!(
                render_scope(LORE_HEADER, LORE_TEMPLATE, &[raw]).as_deref(),
                Some("lore-repo-000102030405060708090a0b0c0d0e0f"),
                "{raw}"
            );
        }
        assert_eq!(render_value(LORE_HEADER, "/w==").as_deref(), Some("ff"));
    }

    #[test]
    fn binary_header_rejects_malformed_empty_and_oversized_values() {
        let oversized = BINARY_HEADER_ENGINE.encode([7_u8; MAX_BINARY_VALUE_BYTES + 1]);
        let largest = BINARY_HEADER_ENGINE.encode([7_u8; MAX_BINARY_VALUE_BYTES]);
        for raw in [
            "",
            "   ",
            "not base64!",
            "AAECAwQFBgcICQoLDA0ODw===",
            "AAEC,AwQF",
            "AAEC AwQF",
            // URL-safe alphabet is not gRPC binary metadata.
            "_-8",
            oversized.as_str(),
        ] {
            assert_eq!(render_value(LORE_HEADER, raw), None, "{raw:?}");
        }
        assert_eq!(
            render_value(LORE_HEADER, &largest).map(|value| value.len()),
            Some(MAX_BINARY_VALUE_BYTES * 2)
        );
    }

    #[test]
    fn text_header_accepts_only_unreserved_characters() {
        assert_eq!(
            render_scope("x-repo", "repo:{value}:read", &["Repo_1.a~b-c"]).as_deref(),
            Some("repo:Repo_1.a~b-c:read")
        );
        let longest = "a".repeat(MAX_TEXT_VALUE_BYTES);
        assert_eq!(render_value("x-repo", &longest), Some(longest.clone()));
        for raw in [
            "",
            "two words",
            "slash/value",
            "colon:value",
            "quote\"",
            "caf\u{e9}",
            &"a".repeat(MAX_TEXT_VALUE_BYTES + 1),
        ] {
            assert_eq!(render_value("x-repo", raw), None, "{raw:?}");
        }
    }

    #[test]
    fn scope_requires_exactly_one_header_value() {
        assert_eq!(render_scope(LORE_HEADER, LORE_TEMPLATE, &[]), None);
        assert_eq!(
            render_scope(
                LORE_HEADER,
                LORE_TEMPLATE,
                &[PARTITION_PADDED, PARTITION_PADDED]
            ),
            None
        );
    }

    #[test]
    fn scope_matching_revalidates_the_rendered_value() {
        let scope = format!("lore-repo-{PARTITION_HEX}");
        assert!(scope_matches_template(LORE_HEADER, LORE_TEMPLATE, &scope));
        for scope in [
            "lore-repo-".to_string(),
            "lore-repo-0".to_string(),
            "lore-repo-ABCD".to_string(),
            format!("lore-repo-{PARTITION_HEX} other"),
            format!("other-{PARTITION_HEX}"),
            format!("lore-repo-{}", "ab".repeat(MAX_BINARY_VALUE_BYTES + 1)),
        ] {
            assert!(
                !scope_matches_template(LORE_HEADER, LORE_TEMPLATE, &scope),
                "{scope}"
            );
        }
        assert!(scope_matches_template(
            "x-repo",
            "repo:{value}:read",
            "repo:Ab.c:read"
        ));
        assert!(!scope_matches_template(
            "x-repo",
            "repo:{value}:read",
            "repo:a/b:read"
        ));
        assert!(!scope_matches_template(
            "x-repo",
            "repo:{value}:read",
            "repo::read"
        ));
        assert!(!scope_matches_template(
            "x-repo",
            "no-placeholder",
            "no-placeholder"
        ));
    }

    #[test]
    fn mint_failures_keep_requests_moving_only_on_explicit_refusal() {
        use crate::rpc_error::StatusExt as _;

        let issuer_refused = Status::with_error_details(
            Code::PermissionDenied,
            "token issuer refused the requested scope",
            crate::rpc_error::ErrorDetails::with_error_info(
                ISSUER_REFUSED_REASON,
                crate::rpc_error::ERROR_DOMAIN,
                std::collections::HashMap::new(),
            ),
        );
        assert_eq!(
            ScopedCredentialFailure::from_status(&issuer_refused),
            ScopedCredentialFailure::IssuerRefused
        );
        for code in [
            Code::PermissionDenied,
            Code::FailedPrecondition,
            Code::InvalidArgument,
            Code::NotFound,
        ] {
            assert_eq!(
                ScopedCredentialFailure::from_status(&Status::new(code, "refused")),
                ScopedCredentialFailure::GatewayRefused,
                "{code:?}"
            );
        }
        for code in [
            Code::Unavailable,
            Code::DeadlineExceeded,
            Code::ResourceExhausted,
            Code::Internal,
            Code::Unknown,
            Code::Unimplemented,
            Code::Unauthenticated,
        ] {
            assert_eq!(
                ScopedCredentialFailure::from_status(&Status::new(code, "failed")),
                ScopedCredentialFailure::Unavailable,
                "{code:?}"
            );
        }
    }

    #[test]
    fn header_names_reject_reserved_and_non_canonical_fields() {
        assert!(validate_header_name(LORE_HEADER).is_ok());
        assert!(validate_header_name("x-repo").is_ok());
        for header in [
            "",
            ":authority",
            ":path",
            "Lore-Partition-Bin",
            "bad header",
            "bad:header",
            "authorization",
            "host",
            "cookie",
            "connection",
            "te",
            "transfer-encoding",
            "upgrade",
            "proxy-authorization",
            "keep-alive",
        ] {
            assert!(validate_header_name(header).is_err(), "{header:?}");
        }
        assert!(validate_header_name(&"a".repeat(MAX_HEADER_NAME_BYTES + 1)).is_err());
    }

    #[test]
    fn scope_templates_require_one_placeholder_and_scope_characters() {
        assert!(validate_scope_template(LORE_TEMPLATE).is_ok());
        assert!(validate_scope_template("{value}").is_ok());
        assert!(validate_scope_template("https://api.example.com/{value}.read").is_ok());
        for template in [
            "",
            "lore-repo",
            "lore-{value}-{value}",
            "lore repo {value}",
            "lore-\"{value}\"",
            "lore\\{value}",
            "lore-{value}\u{e9}",
        ] {
            assert!(validate_scope_template(template).is_err(), "{template:?}");
        }
        let too_long = format!(
            "{}{VALUE_PLACEHOLDER}",
            "a".repeat(MAX_SCOPE_TEMPLATE_BYTES)
        );
        assert!(validate_scope_template(&too_long).is_err());
    }
}
