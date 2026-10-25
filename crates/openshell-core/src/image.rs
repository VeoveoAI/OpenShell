// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Default workload image selection, and the OCI image reference grammar.

/// Default sandbox workload image.
///
/// `OpenShell` uses a version-qualified NVIDIA Ubuntu Noble image so a fresh
/// installation does not depend on a separately maintained image catalog.
pub const DEFAULT_SANDBOX_BASE_IMAGE: &str = "nvcr.io/nvidia/base/ubuntu:24.04";

/// Return the default sandbox image reference.
///
/// Used by all compute drivers as the fallback image when none is specified in
/// the sandbox spec.
#[must_use]
pub fn default_sandbox_image() -> String {
    DEFAULT_SANDBOX_BASE_IMAGE.to_string()
}

/// An OCI image reference split by the distribution reference grammar,
/// `[domain/]path[:tag][@digest]`, with a `sha256` or `sha512` digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageReference<'a> {
    /// The reference without its tag and digest, such as
    /// `registry.example.com:5000/team/tools`.
    pub repository: &'a str,
    pub tag: Option<&'a str>,
    /// The digest, such as `sha256:<64 lowercase hexadecimal digits>`.
    pub digest: Option<&'a str>,
}

impl<'a> ImageReference<'a> {
    /// Split `reference`, or `None` when it is not an image reference.
    #[must_use]
    pub fn parse(reference: &'a str) -> Option<Self> {
        let (named, digest) = match reference.split_once('@') {
            Some((named, digest)) => (named, Some(digest)),
            None => (reference, None),
        };
        // A tag follows the last ':' after the last '/', so a registry port is not a tag.
        let path_start = named.rfind('/').map_or(0, |slash| slash + 1);
        let (repository, tag) = named[path_start..]
            .rfind(':')
            .map_or((named, None), |colon| {
                let colon = path_start + colon;
                (&named[..colon], Some(&named[colon + 1..]))
            });
        (is_image_repository(repository)
            && tag.is_none_or(is_image_tag)
            && digest.is_none_or(is_image_digest))
        .then_some(Self {
            repository,
            tag,
            digest,
        })
    }
}

/// Whether `value` is an image repository: `[domain/]path`, a reference without a tag or
/// digest.
#[must_use]
pub fn is_image_repository(value: &str) -> bool {
    let components = value.split('/').collect::<Vec<_>>();
    let path = if components.len() > 1 && is_image_domain(components[0]) {
        &components[1..]
    } else {
        &components[..]
    };
    value.len() <= MAX_IMAGE_NAME_LEN
        && path
            .iter()
            .all(|component| is_image_path_component(component))
}

/// The longest image name the distribution reference grammar admits.
const MAX_IMAGE_NAME_LEN: usize = 255;

/// `domain := host [':' port]`, where `host` is dot-separated labels of letters,
/// digits and inner hyphens, or a bracketed IPv6 address.
fn is_image_domain(value: &str) -> bool {
    let (host, port) = match value.rsplit_once(':') {
        Some((host, port)) if !host.starts_with('[') || host.ends_with(']') => (host, Some(port)),
        _ => (value, None),
    };
    let host_valid = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .map_or_else(
            || {
                host.split('.').all(|label| {
                    let bytes = label.as_bytes();
                    bytes.first().is_some_and(u8::is_ascii_alphanumeric)
                        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
                        && bytes
                            .iter()
                            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
                })
            },
            |ipv6| ipv6.parse::<std::net::Ipv6Addr>().is_ok(),
        );
    host_valid
        && port.is_none_or(|port| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()))
}

/// `path-component := [a-z0-9]+ (separator [a-z0-9]+)*`, with
/// `separator := [_.] | '__' | [-]+`.
fn is_image_path_component(value: &str) -> bool {
    let alphanumeric = |byte: &u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    let bytes = value.as_bytes();
    bytes.first().is_some_and(alphanumeric)
        && bytes.last().is_some_and(alphanumeric)
        && value
            .split(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
            .all(|separator| {
                matches!(separator, "" | "." | "_" | "__")
                    || separator.bytes().all(|byte| byte == b'-')
            })
}

/// `tag := [A-Za-z0-9_][A-Za-z0-9_.-]{0,127}`.
fn is_image_tag(value: &str) -> bool {
    let word = |byte: &u8| byte.is_ascii_alphanumeric() || *byte == b'_';
    let bytes = value.as_bytes();
    (1..=128).contains(&bytes.len())
        && word(&bytes[0])
        && bytes[1..]
            .iter()
            .all(|byte| word(byte) || matches!(byte, b'.' | b'-'))
}

/// A `sha256` or `sha512` digest in lowercase hexadecimal.
fn is_image_digest(value: &str) -> bool {
    let hex = |encoded: &str, length: usize| {
        encoded.len() == length
            && encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    match value.split_once(':') {
        Some(("sha256", encoded)) => hex(encoded, 64),
        Some(("sha512", encoded)) => hex(encoded, 128),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_image_is_version_qualified_nvidia_ubuntu() {
        assert_eq!(default_sandbox_image(), "nvcr.io/nvidia/base/ubuntu:24.04");
    }

    #[test]
    fn image_references_split_into_repository_tag_and_digest() {
        let digest = format!("sha256:{}", "0123456789abcdef".repeat(4));
        let pinned = format!("registry.example.com:5000/team/tools:1.0@{digest}");
        assert_eq!(
            ImageReference::parse(&pinned),
            Some(ImageReference {
                repository: "registry.example.com:5000/team/tools",
                tag: Some("1.0"),
                digest: Some(&digest),
            })
        );
        assert_eq!(
            ImageReference::parse("localhost:5000/tools"),
            Some(ImageReference {
                repository: "localhost:5000/tools",
                tag: None,
                digest: None,
            })
        );
        assert!(ImageReference::parse("Tools").is_none());
        assert!(ImageReference::parse("tools@sha256:0123").is_none());
        assert!(is_image_repository("registry.example.com:5000/team/tools"));
        assert!(!is_image_repository(
            "registry.example.com:5000/team/tools:1.0"
        ));
        assert!(!is_image_repository(&format!("tools@{digest}")));
        assert!(!is_image_repository(""));
    }
}
