// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Startup-fixed gateway coordinates for the reserved native service namespace.
//!
//! DNS belongs to the trusted supervisor resolver, never workload resolver state.
//! Policy still owns logical hostname, port and executable admission. Each runtime
//! generation retains one validated address set; a DNS failure prevents startup.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use crate::policy_dns::{
    AddressFamily, NormalizedName, ResolveError, SocketTrustedResolver, TrustedResolver,
};
use openshell_core::config::DEFAULT_SERVICE_ROUTING_DOMAIN;
use url::{Host, Url};

#[derive(Debug, thiserror::Error)]
pub(crate) enum NativeServiceResolutionError {
    #[error("configured native gateway HTTPS endpoint is invalid")]
    InvalidEndpoint,
    #[error("native gateway trusted resolver configuration is unavailable")]
    ResolverConfiguration,
    #[error("native gateway trusted DNS resolution failed")]
    Dns(#[from] ResolveError),
    #[error("native gateway trusted DNS returned no address")]
    NoAddress,
    #[error("native gateway trusted DNS returned an invalid destination address")]
    InvalidAddress,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeServiceIngress {
    sockets: Arc<[SocketAddr]>,
}

impl NativeServiceIngress {
    /// Keep local runtime coordinates tied to the isolation backend's exact IP.
    pub(crate) fn from_endpoint(
        endpoint: Option<&str>,
        backend_ip: Option<IpAddr>,
    ) -> Option<Self> {
        let endpoint = sanitized_https_endpoint(endpoint?).ok()?;
        let ip = match endpoint.host()? {
            Host::Ipv4(ip) => IpAddr::V4(ip),
            Host::Ipv6(ip) => IpAddr::V6(ip),
            Host::Domain(host) if host.eq_ignore_ascii_case("localhost") => {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            }
            Host::Domain(_) => return None,
        };
        let checked_ip = normalized_ip(ip);
        if Some(ip) != backend_ip
            || checked_ip.is_multicast()
            || (openshell_core::net::is_always_blocked_ip(checked_ip) && !checked_ip.is_loopback())
        {
            return None;
        }
        Some(Self {
            sockets: vec![SocketAddr::new(ip, endpoint.port_or_known_default()?)].into(),
        })
    }

    /// Resolve only the trusted configured gateway origin, before policy DNS starts.
    /// `NoData` for one family is normal; any actual DNS failure is a startup error.
    pub(crate) async fn resolve(
        endpoint: Option<&str>,
        backend_ip: Option<IpAddr>,
    ) -> Result<Option<Self>, NativeServiceResolutionError> {
        let Some(raw) = endpoint else { return Ok(None) };
        // Plain-HTTP development gateways do not provide HTTPS native ingress.
        let parsed = Url::parse(raw).map_err(|_| NativeServiceResolutionError::InvalidEndpoint)?;
        if parsed.scheme() == "http" {
            return Ok(None);
        }
        let parsed = sanitized_https_endpoint(raw)?;
        let Some(Host::Domain(host)) = parsed.host() else {
            return Ok(Self::from_endpoint(Some(raw), backend_ip));
        };
        if host.eq_ignore_ascii_case("localhost") {
            return Ok(Self::from_endpoint(Some(raw), backend_ip));
        }
        let port = parsed
            .port_or_known_default()
            .ok_or(NativeServiceResolutionError::InvalidEndpoint)?;
        let name = NormalizedName::parse(host)
            .map_err(|_| NativeServiceResolutionError::InvalidEndpoint)?;
        let resolver = SocketTrustedResolver::new(
            crate::policy_dns::trusted_resolver_from_resolv_conf()
                .map_err(|_| NativeServiceResolutionError::ResolverConfiguration)?,
        );
        Self::resolve_name(&name, port, &resolver).await.map(Some)
    }

    async fn resolve_name(
        name: &NormalizedName,
        port: u16,
        resolver: &impl TrustedResolver,
    ) -> Result<Self, NativeServiceResolutionError> {
        let (ipv4, ipv6) = tokio::join!(
            resolver.resolve(name, AddressFamily::Ipv4),
            resolver.resolve(name, AddressFamily::Ipv6),
        );
        let mut sockets = std::collections::BTreeSet::new();
        for (family, answer) in [(AddressFamily::Ipv4, ipv4), (AddressFamily::Ipv6, ipv6)] {
            let answer = match answer {
                Ok(answer) => answer,
                Err(ResolveError::NoData) => continue,
                Err(error) => return Err(error.into()),
            };
            for ip in answer.addresses {
                let checked_ip = normalized_ip(ip);
                if !family.accepts(ip)
                    || checked_ip.is_multicast()
                    || openshell_core::net::is_always_blocked_ip(checked_ip)
                {
                    return Err(NativeServiceResolutionError::InvalidAddress);
                }
                sockets.insert(SocketAddr::new(checked_ip, port));
            }
        }
        if sockets.is_empty() {
            return Err(NativeServiceResolutionError::NoAddress);
        }
        Ok(Self {
            sockets: sockets.into_iter().collect::<Vec<_>>().into(),
        })
    }

    pub(crate) fn port(&self) -> u16 {
        self.sockets[0].port()
    }
    pub(crate) fn sockets(&self) -> &[SocketAddr] {
        &self.sockets
    }

    /// The configured gateway CA applies only to validated native destinations.
    pub(crate) fn permits_tls(&self, host: &str, port: u16, addresses: &[SocketAddr]) -> bool {
        port == self.port()
            && !addresses.is_empty()
            && addresses
                .iter()
                .all(|address| self.sockets.contains(address))
            && (self.pin(host, port).is_some() || crate::proxy::is_host_gateway_alias(host))
    }

    pub(crate) fn pin(&self, host: &str, port: u16) -> Option<NativeServiceDestination> {
        let host = normalize_host(host);
        let label = host.strip_suffix(&format!(".{DEFAULT_SERVICE_ROUTING_DOMAIN}"))?;
        if port != self.port()
            || label.is_empty()
            || label.len() > 63
            || !label.as_bytes().first()?.is_ascii_alphanumeric()
            || !label.as_bytes().last()?.is_ascii_alphanumeric()
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return None;
        }
        Some(NativeServiceDestination {
            host,
            sockets: self.sockets.clone(),
        })
    }
}

/// A logical hostname and port bound to the validated gateway address set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeServiceDestination {
    host: String,
    sockets: Arc<[SocketAddr]>,
}
impl NativeServiceDestination {
    pub(crate) fn matches(&self, host: &str, port: u16) -> bool {
        self.host == normalize_host(host) && self.sockets[0].port() == port
    }
    pub(crate) fn sockets(&self) -> &[SocketAddr] {
        &self.sockets
    }
    pub(crate) fn restrict_to(self, addresses: &[IpAddr]) -> Option<Self> {
        let sockets = self
            .sockets
            .iter()
            .copied()
            .filter(|socket| addresses.contains(&socket.ip()))
            .collect::<Vec<_>>();
        if sockets.is_empty() {
            return None;
        }
        Some(Self {
            host: self.host,
            sockets: sockets.into(),
        })
    }
}
fn sanitized_https_endpoint(raw: &str) -> Result<Url, NativeServiceResolutionError> {
    let endpoint = Url::parse(raw).map_err(|_| NativeServiceResolutionError::InvalidEndpoint)?;
    if endpoint.scheme() != "https"
        || endpoint.host().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || endpoint.path() != "/"
        || endpoint
            .port_or_known_default()
            .is_none_or(|port| port == 0)
    {
        return Err(NativeServiceResolutionError::InvalidEndpoint);
    }
    Ok(endpoint)
}
fn normalized_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        ip => ip,
    }
}
pub fn is_reserved_service_host(host: &str) -> bool {
    let host = normalize_host(host);
    host == DEFAULT_SERVICE_ROUTING_DOMAIN
        || host.ends_with(&format!(".{DEFAULT_SERVICE_ROUTING_DOMAIN}"))
}
fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    enum Answer {
        Records(Vec<IpAddr>),
        NoData,
        Timeout,
        Malformed,
        NxDomain,
    }
    struct Resolver {
        ipv4: Answer,
        ipv6: Answer,
    }
    impl TrustedResolver for Resolver {
        async fn resolve(
            &self,
            name: &NormalizedName,
            family: AddressFamily,
        ) -> Result<crate::policy_dns::TrustedAnswer, ResolveError> {
            assert_eq!(
                name.as_str(),
                "openshell.openshell.svc.cluster.local",
                "only the configured gateway name is resolved"
            );
            let answer = match family {
                AddressFamily::Ipv4 => &self.ipv4,
                AddressFamily::Ipv6 => &self.ipv6,
            };
            match answer {
                Answer::Records(addresses) => Ok(crate::policy_dns::TrustedAnswer {
                    addresses: addresses.clone(),
                    ttl: std::time::Duration::from_secs(10),
                }),
                Answer::NoData => Err(ResolveError::NoData),
                Answer::Timeout => Err(ResolveError::Timeout),
                Answer::Malformed => Err(ResolveError::Malformed),
                Answer::NxDomain => Err(ResolveError::NxDomain),
            }
        }
    }
    fn gateway_name() -> NormalizedName {
        NormalizedName::parse("openshell.openshell.svc.cluster.local").unwrap()
    }
    fn addresses(values: &[&str]) -> Answer {
        Answer::Records(values.iter().map(|value| value.parse().unwrap()).collect())
    }

    #[tokio::test]
    async fn native_service_dns_retains_dual_stack_set_and_distinguishes_nodata_from_failure() {
        let resolver = Resolver {
            ipv4: addresses(&["10.43.0.10", "10.43.0.10"]),
            ipv6: addresses(&["fd00::10"]),
        };
        let ingress = NativeServiceIngress::resolve_name(&gateway_name(), 8080, &resolver)
            .await
            .unwrap();
        assert_eq!(
            ingress.sockets(),
            &[
                "10.43.0.10:8080".parse().unwrap(),
                "[fd00::10]:8080".parse().unwrap()
            ]
        );
        let alias = "vv-services--provider--http.openshell.localhost";
        assert!(ingress.permits_tls(alias, 8080, ingress.sockets()));
        assert!(!ingress.permits_tls("unrelated.example", 8080, ingress.sockets()));
        assert!(!ingress.permits_tls(alias, 443, ingress.sockets()));
        assert!(!ingress.permits_tls(alias, 8080, &["10.43.0.11:8080".parse().unwrap()]));
        assert!(!ingress.permits_tls(alias, 8080, &[]));
        let pin = ingress.pin(alias, 8080).unwrap();
        assert!(!pin.matches("other.openshell.localhost", 8080));
        for resolver in [
            Resolver {
                ipv4: addresses(&["10.43.0.10"]),
                ipv6: Answer::NoData,
            },
            Resolver {
                ipv4: Answer::NoData,
                ipv6: addresses(&["fd00::10"]),
            },
        ] {
            assert_eq!(
                NativeServiceIngress::resolve_name(&gateway_name(), 8080, &resolver)
                    .await
                    .unwrap()
                    .sockets()
                    .len(),
                1
            );
        }
        for failure in [Answer::Timeout, Answer::Malformed, Answer::NxDomain] {
            let resolver = Resolver {
                ipv4: addresses(&["10.43.0.10"]),
                ipv6: failure,
            };
            assert!(
                matches!(
                    NativeServiceIngress::resolve_name(&gateway_name(), 8080, &resolver).await,
                    Err(NativeServiceResolutionError::Dns(_))
                ),
                "a successful family does not hide a resolver failure"
            );
        }
        let resolver = Resolver {
            ipv4: Answer::NoData,
            ipv6: Answer::NoData,
        };
        assert!(matches!(
            NativeServiceIngress::resolve_name(&gateway_name(), 8080, &resolver).await,
            Err(NativeServiceResolutionError::NoAddress)
        ));
        // A malformed resolver answer cannot smuggle another family's addresses.
        let resolver = Resolver {
            ipv4: addresses(&["fd00::10"]),
            ipv6: Answer::NoData,
        };
        assert!(matches!(
            NativeServiceIngress::resolve_name(&gateway_name(), 8080, &resolver).await,
            Err(NativeServiceResolutionError::InvalidAddress)
        ));
        for ip in ["127.0.0.1", "169.254.169.254", "0.0.0.0", "224.0.0.1"] {
            let resolver = Resolver {
                ipv4: addresses(&[ip]),
                ipv6: Answer::NoData,
            };
            assert!(matches!(
                NativeServiceIngress::resolve_name(&gateway_name(), 8080, &resolver).await,
                Err(NativeServiceResolutionError::InvalidAddress)
            ));
        }
    }

    #[tokio::test]
    async fn native_service_dns_pin_cannot_bypass_explicit_address_or_port_restrictions() {
        use crate::proxy::destination::{
            DestinationRequest, build_native_service_plan, filter_resolved_addresses,
            validate_destination,
        };
        let ingress = NativeServiceIngress::resolve_name(
            &gateway_name(),
            8080,
            &Resolver {
                ipv4: addresses(&["10.43.0.10", "10.43.0.11"]),
                ipv6: addresses(&["fd00::10"]),
            },
        )
        .await
        .unwrap();
        let alias = "vv-services--provider--http.openshell.localhost";
        let plan = build_native_service_plan(
            alias,
            8080,
            Some(ingress.clone()),
            &["10.43.0.10/32".into()],
        )
        .unwrap();
        let connector = validate_destination(DestinationRequest {
            host: alias,
            port: 8080,
            sandbox_entrypoint_pid: 0,
            plan: &plan,
        })
        .await
        .unwrap();
        assert_eq!(connector.addrs(), &["10.43.0.10:8080".parse().unwrap()]);
        assert!(
            filter_resolved_addresses(&plan, alias, 8080, &["10.43.0.11".parse().unwrap()])
                .is_err()
        );
        assert!(
            filter_resolved_addresses(
                &plan,
                "other.openshell.localhost",
                8080,
                &["10.43.0.10".parse().unwrap()]
            )
            .is_err()
        );
        assert!(
            build_native_service_plan(alias, 8080, Some(ingress.clone()), &["192.0.2.0/24".into()])
                .is_err()
        );
        assert!(build_native_service_plan(alias, 443, Some(ingress), &[]).is_err());
    }

    #[tokio::test]
    async fn native_service_dns_malformed_endpoint_is_denied_before_resolution() {
        for endpoint in [
            "not a URL",
            "https://user@gateway.example",
            "https://gateway.example/path",
            "https://gateway.example/?query",
            "https://gateway.example/#fragment",
            "https://gateway.example:0",
        ] {
            assert!(
                matches!(
                    NativeServiceIngress::resolve(Some(endpoint), None).await,
                    Err(NativeServiceResolutionError::InvalidEndpoint)
                ),
                "{endpoint}"
            );
        }
        assert!(
            NativeServiceIngress::resolve(None, None)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            NativeServiceIngress::resolve(Some("http://localhost:8080"), None)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            NativeServiceIngress::resolve(Some("https://localhost:8080"), None)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn native_service_ingress_requires_sanitized_matching_trusted_coordinates() {
        let ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        for endpoint in ["https://localhost:17670", "https://127.0.0.1:17670/"] {
            let ingress = NativeServiceIngress::from_endpoint(Some(endpoint), ip).unwrap();
            assert_eq!(ingress.sockets()[0], "127.0.0.1:17670".parse().unwrap());
        }
        assert_eq!(
            NativeServiceIngress::from_endpoint(Some("https://localhost"), ip)
                .unwrap()
                .sockets()[0]
                .port(),
            443
        );
        for endpoint in [
            "http://localhost:17670",
            "https://remote.example:17670",
            "https://user@localhost:17670",
            "https://localhost:17670/path",
            "https://localhost:17670/?query",
            "https://localhost:17670/#fragment",
            "https://localhost:0",
            "https://192.0.2.1:17670",
        ] {
            assert!(
                NativeServiceIngress::from_endpoint(Some(endpoint), ip).is_none(),
                "{endpoint}"
            );
        }
        assert!(NativeServiceIngress::from_endpoint(None, ip).is_none());
        assert!(
            NativeServiceIngress::from_endpoint(Some("https://localhost:17670"), None).is_none()
        );
        for address in ["169.254.169.254", "0.0.0.0", "224.0.0.1"] {
            let ip = address.parse().unwrap();
            assert!(
                NativeServiceIngress::from_endpoint(
                    Some(&format!("https://{address}:17670")),
                    Some(ip)
                )
                .is_none()
            );
        }
    }

    #[test]
    fn native_service_pins_one_label_and_exact_logical_host_and_port() {
        let ingress = NativeServiceIngress::from_endpoint(
            Some("https://localhost:17670"),
            Some("127.0.0.1".parse().unwrap()),
        )
        .unwrap();
        let pin = ingress
            .pin("Team--Hub.Openshell.Localhost.", 17670)
            .unwrap();
        assert!(pin.matches("team--hub.openshell.localhost", 17670));
        assert!(!pin.matches("other.openshell.localhost", 17670));
        assert!(!pin.matches("team--hub.openshell.localhost", 443));
        for host in [
            "openshell.localhost",
            "nested.team.openshell.localhost",
            "team.openshell.localhost.example",
            "team.fakeopenshell.localhost",
            "-team.openshell.localhost",
            "team_.openshell.localhost",
        ] {
            assert!(ingress.pin(host, 17670).is_none(), "{host}");
        }
        assert!(ingress.pin("team.openshell.localhost", 443).is_none());
    }
}
