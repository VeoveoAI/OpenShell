// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Startup-fixed routing coordinates for the gateway's reserved service namespace.
//!
//! These coordinates come from the trusted supervisor endpoint and isolation
//! backend, never authored policy or workload resolver state. Policy still owns
//! hostname, port and executable admission; the gateway owns endpoint existence.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use openshell_core::config::DEFAULT_SERVICE_ROUTING_DOMAIN;
use url::{Host, Url};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeServiceIngress {
    socket: SocketAddr,
}

impl NativeServiceIngress {
    pub(crate) fn from_endpoint(
        endpoint: Option<&str>,
        backend_ip: Option<IpAddr>,
    ) -> Option<Self> {
        let endpoint = Url::parse(endpoint?).ok()?;
        if endpoint.scheme() != "https"
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/"
        {
            return None;
        }
        let ip = match endpoint.host()? {
            Host::Ipv4(ip) => IpAddr::V4(ip),
            Host::Ipv6(ip) => IpAddr::V6(ip),
            Host::Domain(host) if host.eq_ignore_ascii_case("localhost") => {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            }
            Host::Domain(_) => return None,
        };
        let checked_ip = match ip {
            IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
            ip @ IpAddr::V4(_) => ip,
        };
        if Some(ip) != backend_ip
            || checked_ip.is_multicast()
            || (openshell_core::net::is_always_blocked_ip(checked_ip) && !checked_ip.is_loopback())
        {
            return None;
        }
        let port = endpoint.port_or_known_default().filter(|port| *port != 0)?;
        Some(Self {
            socket: SocketAddr::new(ip, port),
        })
    }

    pub(crate) fn socket(self) -> SocketAddr {
        self.socket
    }

    /// The configured gateway CA applies only after destination socket validation.
    pub(crate) fn permits_tls(self, host: &str, port: u16, addresses: &[SocketAddr]) -> bool {
        port == self.socket.port()
            && !addresses.is_empty()
            && addresses.iter().all(|address| *address == self.socket)
            && (self.pin(host, port).is_some() || crate::proxy::is_host_gateway_alias(host))
    }

    pub(crate) fn pin(self, host: &str, port: u16) -> Option<NativeServiceDestination> {
        let host = normalize_host(host);
        let label = host.strip_suffix(&format!(".{DEFAULT_SERVICE_ROUTING_DOMAIN}"))?;
        if port != self.socket.port()
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
            socket: self.socket,
        })
    }
}

/// A logical hostname and port bound to one trusted socket, not an IP exemption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeServiceDestination {
    host: String,
    socket: SocketAddr,
}

impl NativeServiceDestination {
    pub(crate) fn matches(&self, host: &str, port: u16) -> bool {
        self.host == normalize_host(host) && self.socket.port() == port
    }

    pub(crate) fn socket(&self) -> SocketAddr {
        self.socket
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

    #[test]
    fn native_service_ingress_requires_sanitized_matching_trusted_coordinates() {
        let ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        for endpoint in ["https://localhost:17670", "https://127.0.0.1:17670/"] {
            let ingress = NativeServiceIngress::from_endpoint(Some(endpoint), ip).unwrap();
            assert_eq!(ingress.socket(), "127.0.0.1:17670".parse().unwrap());
        }
        assert_eq!(
            NativeServiceIngress::from_endpoint(Some("https://localhost"), ip)
                .unwrap()
                .socket()
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
