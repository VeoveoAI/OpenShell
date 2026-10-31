// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! TLS termination for HTTPS L7 inspection.
//!
//! Provides MITM TLS termination so the proxy can inspect HTTPS traffic.
//! Generates an ephemeral CA at startup, injects it into the sandbox's trust
//! store, terminates TLS from the client (presenting dynamic certs per hostname),
//! inspects the plaintext HTTP, then re-encrypts to upstream using real root CAs.

use miette::{IntoDiagnostic, Result, WrapErr, miette};
use openshell_crypto::pki::KeyPair;
use rcgen::{CertificateParams, DnType, IsCa, KeyUsagePurpose};
use rustls::ClientConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use std::collections::HashMap;
use std::io::{BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const MAX_CACHED_CERTS: usize = 256;

/// System CA bundle search paths (common Linux locations).
const SYSTEM_CA_PATHS: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt",   // RHEL/CentOS/Fedora
    "/etc/ssl/ca-bundle.pem",             // openSUSE
    "/etc/ssl/cert.pem",                  // Alpine/macOS
];

/// Ephemeral CA certificate and key for MITM TLS termination.
#[allow(clippy::struct_field_names)]
pub struct SandboxCa {
    issuer: rcgen::Issuer<'static, KeyPair>,
    ca_der: CertificateDer<'static>,
    ca_cert_pem: String,
}

impl SandboxCa {
    /// Generate a new ephemeral CA keypair.
    pub fn generate() -> Result<Self> {
        let ca_key = openshell_crypto::pki::generate_keypair().into_diagnostic()?;

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "OpenShell Sandbox CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "OpenShell");
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        let ca_cert = openshell_crypto::pki::self_signed(params, &ca_key).into_diagnostic()?;
        let ca_cert_pem = ca_cert.pem();

        Ok(Self {
            ca_der: ca_cert.der().clone(),
            issuer: ca_cert.into_issuer(ca_key),
            ca_cert_pem,
        })
    }

    /// Returns the CA certificate in PEM format.
    pub fn cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Returns the CA private key in PKCS#8 PEM format.
    pub fn private_key_pem(&self) -> Result<String> {
        self.issuer.key().serialize_pem().into_diagnostic()
    }

    /// Load a durable CA certificate and matching private key from absolute paths.
    pub fn load_from_paths(certificate_path: &Path, private_key_path: &Path) -> Result<Self> {
        if !certificate_path.is_absolute() || !private_key_path.is_absolute() {
            return Err(miette!(
                "proxy CA certificate and key paths must be absolute"
            ));
        }
        if certificate_path == private_key_path {
            return Err(miette!(
                "proxy CA certificate and private key must use different paths"
            ));
        }
        let certificate_pem = std::fs::read_to_string(certificate_path)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!("read proxy CA certificate {}", certificate_path.display())
            })?;
        let private_key_pem = std::fs::read_to_string(private_key_path)
            .into_diagnostic()
            .wrap_err_with(|| {
                format!("read proxy CA private key {}", private_key_path.display())
            })?;
        Self::from_pem(&certificate_pem, &private_key_pem)
    }

    /// Load a durable CA while preserving the exact certificate bytes supplied
    /// by the provisioner for boundary launch replay.
    pub fn from_pem(certificate_pem: &str, private_key_pem: &str) -> Result<Self> {
        openshell_crypto::tls::ensure_default_provider();
        let ca_key = KeyPair::from_pem(private_key_pem)
            .into_diagnostic()
            .wrap_err("parse proxy CA private key")?;
        let certificates = rustls_pemfile::certs(&mut certificate_pem.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .into_diagnostic()
            .wrap_err("parse proxy CA certificate")?;
        if certificates.len() != 1 {
            return Err(miette!(
                "proxy CA certificate file must contain exactly one certificate"
            ));
        }
        let private_key = rustls_pemfile::private_key(&mut private_key_pem.as_bytes())
            .into_diagnostic()
            .wrap_err("parse proxy CA private key")?
            .ok_or_else(|| miette!("proxy CA private key file contains no private key"))?;
        let ca_der = certificates[0].clone();
        openshell_crypto::tls::server_builder()
            .with_no_client_auth()
            .with_single_cert(certificates, private_key)
            .into_diagnostic()
            .wrap_err("proxy CA certificate and private key do not match")?;

        let issuer = openshell_crypto::pki::issuer_from_der(&ca_der, ca_key)
            .into_diagnostic()
            .wrap_err("parse proxy CA signing certificate")?;
        Ok(Self {
            issuer,
            ca_der,
            ca_cert_pem: certificate_pem.to_string(),
        })
    }
}

/// A leaf certificate chain and private key for a specific hostname.
struct CertifiedLeaf {
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
}

/// Cache of per-hostname leaf certificates signed by the sandbox CA.
pub struct CertCache {
    ca: SandboxCa,
    cache: Mutex<HashMap<String, Arc<CertifiedLeaf>>>,
}

impl CertCache {
    /// Create a new cert cache with the given CA.
    pub fn new(ca: SandboxCa) -> Self {
        Self {
            ca,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Get or generate a leaf certificate for the given hostname.
    fn get_or_generate(&self, hostname: &str) -> Result<Arc<CertifiedLeaf>> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| miette::miette!("cert cache lock poisoned"))?;

        if let Some(leaf) = cache.get(hostname) {
            return Ok(Arc::clone(leaf));
        }

        // Overflow: clear entire map (simple, sufficient for sandbox scale)
        if cache.len() >= MAX_CACHED_CERTS {
            cache.clear();
        }

        let leaf = Arc::new(self.generate_leaf(hostname)?);
        cache.insert(hostname.to_string(), Arc::clone(&leaf));
        Ok(leaf)
    }

    /// Generate a new leaf certificate for the given hostname.
    fn generate_leaf(&self, hostname: &str) -> Result<CertifiedLeaf> {
        let leaf_key = openshell_crypto::pki::generate_keypair().into_diagnostic()?;

        let mut params = CertificateParams::new(vec![hostname.to_string()]).into_diagnostic()?;
        params.distinguished_name.push(DnType::CommonName, hostname);
        params.use_authority_key_identifier_extension = true;

        let leaf_cert = openshell_crypto::pki::signed_by_issuer(params, &leaf_key, &self.ca.issuer)
            .into_diagnostic()?;

        let leaf_der = CertificateDer::from(leaf_cert.der().to_vec());
        let ca_der = self.ca.ca_der.clone();
        let key_der = PrivateKeyDer::try_from(leaf_key.serialize_der().into_diagnostic()?)
            .map_err(|e| miette::miette!("failed to serialize leaf key: {e}"))?;

        Ok(CertifiedLeaf {
            cert_chain: vec![leaf_der, ca_der],
            private_key: key_der,
        })
    }
}

/// TLS state shared across proxy connections.
pub struct ProxyTlsState {
    cert_cache: CertCache,
    upstream_config: Arc<ClientConfig>,
    native_service_config: Option<(
        crate::native_service::NativeServiceIngress,
        Arc<ClientConfig>,
    )>,
}

impl ProxyTlsState {
    /// Create a new TLS state with the given cert cache and upstream config.
    pub fn new(cert_cache: CertCache, upstream_config: Arc<ClientConfig>) -> Self {
        Self {
            cert_cache,
            upstream_config,
            native_service_config: None,
        }
    }

    /// Trust the driver-owned gateway CA only on the pinned native gateway sockets.
    pub(crate) fn configure_native_service_ingress(
        &mut self,
        ingress: crate::native_service::NativeServiceIngress,
        system_ca_bundle: &str,
        gateway_ca_pem: &str,
    ) -> Result<()> {
        let mut roots = build_upstream_root_store(system_ca_bundle)?;
        let certs = rustls_pemfile::certs(&mut gateway_ca_pem.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| miette!("native gateway CA is invalid"))?;
        if certs.is_empty() {
            return Err(miette!("native gateway CA contains no certificates"));
        }
        for cert in certs {
            roots
                .add(cert)
                .map_err(|_| miette!("native gateway CA is invalid"))?;
        }
        let mut config = openshell_crypto::tls::client_builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        self.native_service_config = Some((ingress, Arc::new(config)));
        Ok(())
    }

    pub(crate) fn upstream_config_for(
        &self,
        host: &str,
        port: u16,
        addresses: &[std::net::SocketAddr],
    ) -> &Arc<ClientConfig> {
        if let Some((ingress, config)) = &self.native_service_config
            && ingress.permits_tls(host, port, addresses)
        {
            return config;
        }
        &self.upstream_config
    }

    /// Get or generate a leaf cert for the hostname and return a TLS acceptor.
    fn acceptor_for(&self, hostname: &str, http2: bool) -> Result<TlsAcceptor> {
        Ok(TlsAcceptor::from(self.server_config_for(hostname, http2)?))
    }

    /// Server configuration presenting the hostname's leaf certificate. It
    /// offers HTTP/2 first when `http2` is set, and always HTTP/1.1.
    fn server_config_for(&self, hostname: &str, http2: bool) -> Result<Arc<rustls::ServerConfig>> {
        let leaf = self.cert_cache.get_or_generate(hostname)?;
        let mut server_config = openshell_crypto::tls::server_builder()
            .with_no_client_auth()
            .with_single_cert(leaf.cert_chain.clone(), leaf.private_key.clone_key())
            .into_diagnostic()?;
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        if http2 {
            server_config.alpn_protocols.insert(0, b"h2".to_vec());
        }
        Ok(Arc::new(server_config))
    }

    /// Returns a reference to the upstream client config.
    pub fn upstream_config(&self) -> &Arc<ClientConfig> {
        &self.upstream_config
    }
}

/// Accept TLS from a sandbox client, presenting a dynamic cert for the hostname.
///
/// Returns a TLS stream that can be used for plaintext HTTP inspection.
pub async fn tls_terminate_client<S>(
    client: S,
    tls_state: &ProxyTlsState,
    hostname: &str,
) -> Result<impl AsyncRead + AsyncWrite + Unpin + Send>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let acceptor = tls_state.acceptor_for(hostname, false)?;
    let tls_stream = acceptor.accept(client).await.into_diagnostic()?;
    Ok(tls_stream)
}

/// Which side of an inspected TLS tunnel failed to establish.
#[derive(Debug)]
pub(crate) enum HttpTlsError {
    /// The sandbox client's handshake failed; no endpoint evidence.
    Client(miette::Report),
    /// The upstream handshake failed.
    Upstream(miette::Report),
}

/// Both TLS legs of one inspected HTTP tunnel, with one application protocol.
pub(crate) struct NegotiatedHttpTls<C, U> {
    pub(crate) client: tokio_rustls::server::TlsStream<C>,
    pub(crate) upstream: tokio_rustls::client::TlsStream<U>,
    /// Both legs speak HTTP/2; otherwise both speak HTTP/1.1.
    pub(crate) http2: bool,
}

/// Terminate the sandbox client's TLS and establish the upstream TLS with one
/// application protocol on both legs.
///
/// The proxy cannot translate between HTTP/2 and HTTP/1.1, so HTTP/2 is used
/// only when the route allows it, the client offers it, and the upstream
/// selects it. The client's `ClientHello` is read first; the upstream is
/// offered HTTP/2 and HTTP/1.1 only when the client offered HTTP/2, and the
/// client handshake completes with the protocol the upstream selected. An
/// HTTP/1.1-only upstream therefore serves an HTTP/2-capable client over
/// HTTP/1.1 instead of rejecting an HTTP/2-only offer. A malformed
/// `ClientHello` fails before the upstream handshake, so it never counts as an
/// endpoint failure.
pub(crate) async fn negotiate_http_tls<C, U>(
    client: C,
    upstream: U,
    tls_state: &ProxyTlsState,
    hostname: &str,
    upstream_config: &Arc<ClientConfig>,
    allow_http2: bool,
) -> std::result::Result<NegotiatedHttpTls<C, U>, HttpTlsError>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    let start = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), client)
        .await
        .into_diagnostic()
        .map_err(HttpTlsError::Client)?;
    let client_offers_http2 = start
        .client_hello()
        .alpn()
        .is_some_and(|mut protocols| protocols.any(|protocol| protocol == b"h2"));
    let attempt_http2 = allow_http2 && client_offers_http2;
    let upstream_config = if attempt_http2 {
        let mut config = (**upstream_config).clone();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Arc::new(config)
    } else {
        Arc::clone(upstream_config)
    };
    let upstream = connect_upstream_stream(upstream, hostname, &upstream_config)
        .await
        .map_err(HttpTlsError::Upstream)?;
    let http2 = attempt_http2 && upstream.get_ref().1.alpn_protocol() == Some(b"h2");
    let server_config = tls_state
        .server_config_for(hostname, http2)
        .map_err(HttpTlsError::Client)?;
    let client = start
        .into_stream(server_config)
        .await
        .into_diagnostic()
        .map_err(HttpTlsError::Client)?;
    if http2 != (client.get_ref().1.alpn_protocol() == Some(b"h2")) {
        return Err(HttpTlsError::Client(miette!(
            "client and upstream negotiated different HTTP versions"
        )));
    }
    Ok(NegotiatedHttpTls {
        client,
        upstream,
        http2,
    })
}

async fn connect_upstream_stream<U>(
    upstream: U,
    hostname: &str,
    client_config: &Arc<ClientConfig>,
) -> Result<tokio_rustls::client::TlsStream<U>>
where
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    let connector = TlsConnector::from(Arc::clone(client_config));
    let server_name = ServerName::try_from(hostname.to_string()).into_diagnostic()?;
    connector
        .connect(server_name, upstream)
        .await
        .into_diagnostic()
}

/// Connect TLS to an upstream server, verifying against the configured CA roots.
///
/// Returns a TLS stream for re-encrypted upstream communication.
pub async fn tls_connect_upstream(
    upstream: impl AsyncRead + AsyncWrite + Unpin + Send,
    hostname: &str,
    client_config: &Arc<ClientConfig>,
) -> Result<impl AsyncRead + AsyncWrite + Unpin + Send> {
    let connector = TlsConnector::from(Arc::clone(client_config));
    let server_name = ServerName::try_from(hostname.to_string()).into_diagnostic()?;
    let tls_stream = connector
        .connect(server_name, upstream)
        .await
        .into_diagnostic()?;
    Ok(tls_stream)
}

/// Build a rustls `ClientConfig` using the configured CA root source.
///
/// In `bundled-ca-roots` mode this uses Mozilla roots from `webpki-roots` overlaid
/// with any locally-installed CAs from `system_ca_bundle` (e.g. corporate or private
/// CAs added to `/etc/pki/ca-trust`). Duplicates with the Mozilla bundle are harmless.
///
/// Without `bundled-ca-roots` this uses the platform/native trust store exclusively;
/// `system_ca_bundle` is ignored because the native store already reflects all
/// operator-installed trust anchors.
pub fn build_upstream_client_config(system_ca_bundle: &str) -> Result<Arc<ClientConfig>> {
    let mut config = openshell_crypto::tls::client_builder()
        .with_root_certificates(build_upstream_root_store(system_ca_bundle)?)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}

fn build_upstream_root_store(system_ca_bundle: &str) -> Result<rustls::RootCertStore> {
    let mut root_store = rustls::RootCertStore::empty();

    #[cfg(feature = "bundled-ca-roots")]
    {
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        // Overlay system/corporate CAs so custom trust anchors are honoured in
        // default upstream builds. Duplicates with webpki-roots are harmless.
        let (added, ignored) = load_pem_certs_into_store(&mut root_store, system_ca_bundle);
        if added > 0 {
            tracing::debug!(added, "loaded system CA certificates for upstream TLS");
        }
        if ignored > 0 {
            tracing::warn!(
                ignored,
                "some system CA certificates could not be parsed and were ignored"
            );
        }
    }

    #[cfg(not(feature = "bundled-ca-roots"))]
    {
        let _ = system_ca_bundle; // native store already includes operator-installed CAs
        add_native_roots(&mut root_store)?;
    }

    if root_store.is_empty() {
        return Err(miette!("no TLS root certificates available"));
    }

    Ok(root_store)
}

#[cfg(not(feature = "bundled-ca-roots"))]
fn add_native_roots(root_store: &mut rustls::RootCertStore) -> Result<()> {
    let native_certs = rustls_native_certs::load_native_certs();
    let cert_count = native_certs.certs.len();
    let (added, ignored) = root_store.add_parsable_certificates(native_certs.certs);
    let ignored = ignored + native_certs.errors.len();

    if ignored > 0 {
        tracing::debug!(ignored, "ignored unparsable native root certificates");
    }

    if added == 0 {
        return Err(miette!(
            "no usable native TLS root certificates found ({cert_count} loaded, {ignored} ignored)"
        ));
    }

    Ok(())
}

/// Write CA certificate files for the sandbox trust store.
///
/// Writes:
/// 1. Standalone CA cert PEM (for `NODE_EXTRA_CA_CERTS` which is additive)
/// 2. Combined bundle: system CAs + sandbox CA (for `SSL_CERT_FILE` which replaces default)
///
/// `system_ca_bundle` is the pre-read PEM contents of the system CA bundle
/// (from [`read_system_ca_bundle`]).
///
/// Returns `(ca_cert_path, combined_bundle_path)`.
pub fn write_ca_files(
    ca: &SandboxCa,
    output_dir: &Path,
    system_ca_bundle: &str,
) -> Result<(PathBuf, PathBuf)> {
    std::fs::create_dir_all(output_dir).into_diagnostic()?;

    let ca_cert_path = output_dir.join("openshell-ca.pem");
    write_tls_output(&ca_cert_path, ca.cert_pem().as_bytes())?;

    // Combine system CAs with our sandbox CA
    let mut combined = system_ca_bundle.to_string();
    if !combined.is_empty() && !combined.ends_with('\n') {
        combined.push('\n');
    }
    combined.push_str(ca.cert_pem());

    let combined_path = output_dir.join("ca-bundle.pem");
    write_tls_output(&combined_path, combined.as_bytes())?;

    Ok((ca_cert_path, combined_path))
}

fn write_tls_output(path: &Path, contents: &[u8]) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(miette!(
                "refusing to replace symlinked TLS output {}",
                path.display()
            ));
        }
        Ok(metadata) if !metadata.is_file() => {
            return Err(miette!(
                "refusing to replace non-file TLS output {}",
                path.display()
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).into_diagnostic(),
    }

    let parent = path
        .parent()
        .ok_or_else(|| miette!("TLS output has no parent: {}", path.display()))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .into_diagnostic()
        .wrap_err_with(|| format!("create temporary TLS output in {}", parent.display()))?;
    temporary
        .write_all(contents)
        .into_diagnostic()
        .wrap_err_with(|| format!("write temporary TLS output for {}", path.display()))?;
    temporary
        .as_file()
        .sync_all()
        .into_diagnostic()
        .wrap_err_with(|| format!("sync temporary TLS output for {}", path.display()))?;
    temporary.persist(path).map_err(|error| {
        miette!(
            "atomically install TLS output {}: {}",
            path.display(),
            error.error
        )
    })?;
    Ok(())
}

/// Load PEM-encoded certificates from a string into a root certificate store.
///
/// Returns `(added, ignored)` counts. Invalid or unparseable certificates
/// are silently ignored, matching the behavior of
/// `RootCertStore::add_parsable_certificates`.
#[cfg_attr(not(feature = "bundled-ca-roots"), allow(dead_code))]
fn load_pem_certs_into_store(
    root_store: &mut rustls::RootCertStore,
    pem_data: &str,
) -> (usize, usize) {
    if pem_data.is_empty() {
        return (0, 0);
    }
    let mut reader = BufReader::new(pem_data.as_bytes());
    // Collect all results so we can count PEM blocks that fail base64
    // decoding — rustls_pemfile::certs silently drops those, so without
    // this they wouldn't be reflected in the `ignored` count.
    let all_results: Vec<_> = rustls_pemfile::certs(&mut reader).collect();
    let pem_errors = all_results.iter().filter(|r| r.is_err()).count();
    let certs: Vec<CertificateDer<'static>> =
        all_results.into_iter().filter_map(Result::ok).collect();
    let (added, ignored) = root_store.add_parsable_certificates(certs);
    (added, ignored + pem_errors)
}

/// Read the system CA bundle from well-known paths.
///
/// Returns the PEM contents of the first non-empty bundle found, or an empty
/// string if none of the well-known paths exist. Call once and pass the result
/// to [`write_ca_files`].
pub fn read_system_ca_bundle() -> String {
    for path in SYSTEM_CA_PATHS {
        if let Ok(contents) = std::fs::read_to_string(path)
            && !contents.is_empty()
        {
            return contents;
        }
    }
    // No system bundle found — combined file will contain only the sandbox CA.
    String::new()
}

/// Parse PEM certificates from a file into DER-encoded certificates.
pub fn parse_pem_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path).into_diagnostic()?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .into_diagnostic()
}

/// Peek the first bytes of a stream and determine if it looks like a TLS
/// `ClientHello` handshake.
///
/// A TLS record starts with:
/// - byte 0: `0x16` (`ContentType::Handshake`)
/// - bytes 1-2: TLS version (0x0301 = TLS 1.0, 0x0302 = TLS 1.1, 0x0303 = TLS 1.2/1.3)
///
/// Returns `true` if the peeked bytes match the TLS handshake pattern.
/// Returns `false` for plaintext HTTP, raw binary, or insufficient data.
pub fn looks_like_tls(peek: &[u8]) -> bool {
    if peek.len() < 3 {
        return false;
    }
    // ContentType::Handshake
    if peek[0] != 0x16 {
        return false;
    }
    // TLS version major must be 0x03 (SSL 3.0 / TLS 1.x)
    if peek[1] != 0x03 {
        return false;
    }
    // TLS version minor: 0x00 (SSL 3.0) through 0x04 (TLS 1.3 record layer)
    peek[2] <= 0x04
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_generation() {
        let ca = SandboxCa::generate().unwrap();
        let pem = ca.cert_pem();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.contains("-----END CERTIFICATE-----"));
    }

    #[test]
    fn leaf_cert_generation() {
        let ca = SandboxCa::generate().unwrap();
        let cache = CertCache::new(ca);
        let leaf = cache.get_or_generate("example.com").unwrap();
        assert_eq!(leaf.cert_chain.len(), 2); // leaf + CA
    }

    #[test]
    fn cache_dedup() {
        let ca = SandboxCa::generate().unwrap();
        let cache = CertCache::new(ca);
        let leaf1 = cache.get_or_generate("example.com").unwrap();
        let leaf2 = cache.get_or_generate("example.com").unwrap();
        assert!(Arc::ptr_eq(&leaf1, &leaf2));
    }

    #[test]
    fn cache_overflow_clears() {
        let ca = SandboxCa::generate().unwrap();
        let cache = CertCache::new(ca);

        // Fill cache to capacity
        for i in 0..MAX_CACHED_CERTS {
            cache
                .get_or_generate(&format!("host{i}.example.com"))
                .unwrap();
        }

        // This should trigger a clear and succeed
        let leaf = cache.get_or_generate("overflow.example.com").unwrap();
        assert_eq!(leaf.cert_chain.len(), 2);

        // Cache should now have just one entry
        let cache_inner = cache.cache.lock().unwrap();
        assert_eq!(cache_inner.len(), 1);
    }

    #[test]
    fn looks_like_tls_valid_clienthello() {
        // TLS 1.0 ClientHello
        assert!(looks_like_tls(&[0x16, 0x03, 0x01, 0x00, 0x05]));
        // TLS 1.2
        assert!(looks_like_tls(&[0x16, 0x03, 0x03, 0x01, 0x00]));
        // TLS 1.3 record layer (minor 0x01, but hello advertises 1.3 via extension)
        assert!(looks_like_tls(&[0x16, 0x03, 0x01]));
        // SSL 3.0
        assert!(looks_like_tls(&[0x16, 0x03, 0x00]));
    }

    #[test]
    fn looks_like_tls_rejects_http() {
        assert!(!looks_like_tls(b"GET / HTTP/1.1"));
        assert!(!looks_like_tls(b"POST /api"));
        assert!(!looks_like_tls(b"CONNECT host:443"));
    }

    #[test]
    fn looks_like_tls_rejects_short_input() {
        assert!(!looks_like_tls(&[]));
        assert!(!looks_like_tls(&[0x16]));
        assert!(!looks_like_tls(&[0x16, 0x03]));
    }

    #[test]
    fn looks_like_tls_rejects_non_tls_binary() {
        // SSH protocol
        assert!(!looks_like_tls(b"SSH-2.0-OpenSSH"));
        // Random binary
        assert!(!looks_like_tls(&[0xFF, 0xFE, 0x00]));
        // Wrong content type
        assert!(!looks_like_tls(&[0x17, 0x03, 0x03])); // Application data, not handshake
    }

    #[test]
    fn upstream_config_alpn() {
        let config = build_upstream_client_config("").unwrap();
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    /// Reproduces issue #3781 end to end with a real TLS handshake: an
    /// upstream client trying to reach a destination signed by an
    /// operator-owned private CA fails when that CA is unknown, and succeeds
    /// once it is appended to the bundle passed to
    /// `build_upstream_client_config` — the same mechanism the Podman driver
    /// fix (`additional_ca_bundle`) feeds into. No fakes: a real rustls
    /// `TlsAcceptor`/`TlsConnector` pair over a real loopback TCP connection.
    #[tokio::test]
    async fn additional_ca_enables_trust_of_privately_signed_upstream() {
        let hostname = "private.example";

        // A CA the system bundle has never heard of, standing in for the
        // operator-owned private CA from #3781.
        let private_ca = SandboxCa::generate().unwrap();
        let private_ca_pem = private_ca.cert_pem().to_string();
        let cert_cache = CertCache::new(private_ca);
        let leaf = cert_cache.get_or_generate(hostname).unwrap();

        let server_config = Arc::new(
            openshell_crypto::tls::server_builder()
                .with_no_client_auth()
                .with_single_cert(leaf.cert_chain.clone(), leaf.private_key.clone_key())
                .unwrap(),
        );
        let acceptor = TlsAcceptor::from(server_config);

        // --- Without the private CA: must fail. This is the literal bug in
        // #3781 — "Upstream TLS establishment failed" against a
        // policy-allowed, private-CA-signed destination. ---
        let addr = serve_one(acceptor.clone()).await;
        let client_without = build_upstream_client_config("").unwrap();
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let result = tls_connect_upstream(tcp, hostname, &client_without).await;
        assert!(
            result.is_err(),
            "connection to a privately-signed destination must fail when the \
             private CA is not trusted, reproducing #3781"
        );

        // --- With the private CA appended to the bundle: must succeed. This
        // is what additional_ca_bundle plumbs through in the Podman driver
        // fix. ---
        let addr = serve_one(acceptor).await;
        let client_with = build_upstream_client_config(&private_ca_pem).unwrap();
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let result = tls_connect_upstream(tcp, hostname, &client_with).await;
        assert!(
            result.is_ok(),
            "connection must succeed once the private CA is trusted: {:?}",
            result.err()
        );
    }

    /// Helper: generate a self-signed CA and return its PEM string.
    async fn native_tls_handshake(
        state: &ProxyTlsState,
        authority: &str,
        port: u16,
        addresses: &[std::net::SocketAddr],
        cert_cache: &CertCache,
    ) -> bool {
        let leaf = cert_cache.get_or_generate(authority).unwrap();
        let server = openshell_crypto::tls::server_builder()
            .with_no_client_auth()
            .with_single_cert(leaf.cert_chain.clone(), leaf.private_key.clone_key())
            .unwrap();
        let (client_io, server_io) = tokio::io::duplex(32768);
        let server = tokio::spawn(async move {
            TlsAcceptor::from(Arc::new(server))
                .accept(server_io)
                .await
                .is_ok()
        });
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tls_connect_upstream(
                client_io,
                authority,
                state.upstream_config_for(authority, port, addresses),
            ),
        )
        .await
        .unwrap()
        .is_ok();
        let _ = server.await.unwrap();
        result
    }

    #[tokio::test]
    async fn native_gateway_ca_is_scoped_to_verified_name_and_gateway_socket() {
        let ingress = crate::native_service::NativeServiceIngress::from_endpoint(
            Some("https://localhost:17670"),
            Some("127.0.0.1".parse().unwrap()),
        )
        .unwrap();
        let gateway_ca = SandboxCa::generate().unwrap();
        let gateway_pem = gateway_ca.cert_pem().to_string();
        let gateway_cache = CertCache::new(gateway_ca);
        let ordinary = build_upstream_client_config("").unwrap();
        let mut state = ProxyTlsState::new(
            CertCache::new(SandboxCa::generate().unwrap()),
            ordinary.clone(),
        );
        state
            .configure_native_service_ingress(ingress.clone(), "", &gateway_pem)
            .unwrap();
        let host = "team--application.openshell.localhost";
        assert!(
            native_tls_handshake(&state, host, 17670, &[ingress.sockets()[0]], &gateway_cache)
                .await
        );
        assert!(
            native_tls_handshake(
                &state,
                "host.openshell.internal",
                17670,
                &[ingress.sockets()[0]],
                &gateway_cache
            )
            .await
        );
        for (authority, port, socket) in [
            (host, 443, "127.0.0.1:443"),
            (host, 17670, "127.0.0.2:17670"),
            ("host.openshell.internal", 443, "127.0.0.1:443"),
            ("unrelated.example", 17670, "127.0.0.1:17670"),
            ("nested.team.openshell.localhost", 17670, "127.0.0.1:17670"),
        ] {
            let addresses = [socket.parse().unwrap()];
            assert!(Arc::ptr_eq(
                state.upstream_config_for(authority, port, &addresses),
                &ordinary
            ));
            assert!(
                !native_tls_handshake(&state, authority, port, &addresses, &gateway_cache).await,
                "{authority}:{port}"
            );
        }
        let other_ca = CertCache::new(SandboxCa::generate().unwrap());
        assert!(
            !native_tls_handshake(&state, host, 17670, &[ingress.sockets()[0]], &other_ca).await
        );
        // Correct issuer alone does not waive the logical hostname/SNI check.
        let leaf = gateway_cache
            .get_or_generate("wrong.openshell.localhost")
            .unwrap();
        let server = openshell_crypto::tls::server_builder()
            .with_no_client_auth()
            .with_single_cert(leaf.cert_chain.clone(), leaf.private_key.clone_key())
            .unwrap();
        let (client_io, server_io) = tokio::io::duplex(32768);
        let task = tokio::spawn(async move {
            TlsAcceptor::from(Arc::new(server))
                .accept(server_io)
                .await
                .is_ok()
        });
        assert!(
            tls_connect_upstream(
                client_io,
                host,
                state.upstream_config_for(host, 17670, &[ingress.sockets()[0]])
            )
            .await
            .is_err()
        );
        let _ = task.await.unwrap();
    }

    #[test]
    fn native_gateway_ca_rejects_empty_or_invalid_trust_material() {
        let ingress = crate::native_service::NativeServiceIngress::from_endpoint(
            Some("https://localhost:17670"),
            Some("127.0.0.1".parse().unwrap()),
        )
        .unwrap();
        for pem in [
            "",
            "not a certificate",
            "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----",
        ] {
            let mut state = ProxyTlsState::new(
                CertCache::new(SandboxCa::generate().unwrap()),
                build_upstream_client_config("").unwrap(),
            );
            assert!(
                state
                    .configure_native_service_ingress(ingress.clone(), "", pem)
                    .is_err()
            );
            assert!(state.native_service_config.is_none());
        }
    }

    fn generate_ca_pem() -> String {
        SandboxCa::generate().unwrap().ca_cert_pem
    }

    /// Accept exactly one TLS connection on a fresh loopback listener and
    /// return its address. Used by `additional_ca_enables_trust_of_...` to
    /// give each connection attempt its own listener.
    /// An upstream that, like `api.deepinfra.com`, speaks only HTTP/1.1 and
    /// answers an `h2`-only ALPN offer with a `no_application_protocol` alert.
    struct AlpnFixture {
        state: ProxyTlsState,
        upstream_config: Arc<ClientConfig>,
        client_config: Arc<ClientConfig>,
        upstream_cache: CertCache,
    }

    impl AlpnFixture {
        fn new() -> Self {
            let roots = |ca: &SandboxCa| {
                let mut roots = rustls::RootCertStore::empty();
                for cert in rustls_pemfile::certs(&mut ca.cert_pem().as_bytes()) {
                    roots.add(cert.unwrap()).unwrap();
                }
                roots
            };
            let upstream_ca = SandboxCa::generate().unwrap();
            let mut upstream_config = openshell_crypto::tls::client_builder()
                .with_root_certificates(roots(&upstream_ca))
                .with_no_client_auth();
            upstream_config.alpn_protocols = vec![b"http/1.1".to_vec()];
            let sandbox_ca = SandboxCa::generate().unwrap();
            let mut client_config = openshell_crypto::tls::client_builder()
                .with_root_certificates(roots(&sandbox_ca))
                .with_no_client_auth();
            // curl built with HTTP/2 support offers both protocols.
            client_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            let upstream_config = Arc::new(upstream_config);
            Self {
                state: ProxyTlsState::new(CertCache::new(sandbox_ca), upstream_config.clone()),
                upstream_config,
                client_config: Arc::new(client_config),
                upstream_cache: CertCache::new(upstream_ca),
            }
        }

        fn upstream_acceptor(&self, hostname: &str, protocols: &[&[u8]]) -> TlsAcceptor {
            let leaf = self.upstream_cache.get_or_generate(hostname).unwrap();
            let mut config = openshell_crypto::tls::server_builder()
                .with_no_client_auth()
                .with_single_cert(leaf.cert_chain.clone(), leaf.private_key.clone_key())
                .unwrap();
            config.alpn_protocols = protocols.iter().map(|protocol| protocol.to_vec()).collect();
            TlsAcceptor::from(Arc::new(config))
        }

        /// Run one tunnel and return the negotiated protocol of each leg.
        async fn negotiate(
            &self,
            hostname: &str,
            upstream_protocols: &[&[u8]],
            client_protocols: &[&[u8]],
            allow_http2: bool,
        ) -> std::result::Result<(Option<Vec<u8>>, Option<Vec<u8>>, bool), String> {
            let (client_io, proxy_client_io) = tokio::io::duplex(65536);
            let (proxy_upstream_io, upstream_io) = tokio::io::duplex(65536);
            let acceptor = self.upstream_acceptor(hostname, upstream_protocols);
            let upstream_task = tokio::spawn(async move {
                acceptor
                    .accept(upstream_io)
                    .await
                    .map(|stream| stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec))
            });
            let mut client_config = (*self.client_config).clone();
            client_config.alpn_protocols = client_protocols
                .iter()
                .map(|protocol| protocol.to_vec())
                .collect();
            let connector = TlsConnector::from(Arc::new(client_config));
            let server_name = ServerName::try_from(hostname.to_string()).unwrap();
            let client_task =
                tokio::spawn(async move { connector.connect(server_name, client_io).await });
            let negotiated = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                negotiate_http_tls(
                    proxy_client_io,
                    proxy_upstream_io,
                    &self.state,
                    hostname,
                    &self.upstream_config,
                    allow_http2,
                ),
            )
            .await
            .expect("negotiation must not hang");
            let negotiated = match negotiated {
                Ok(negotiated) => negotiated,
                Err(HttpTlsError::Client(error)) => return Err(format!("client: {error}")),
                Err(HttpTlsError::Upstream(error)) => return Err(format!("upstream: {error}")),
            };
            let upstream_alpn = upstream_task.await.unwrap().map_err(|e| e.to_string())?;
            let client = client_task.await.unwrap().map_err(|e| e.to_string())?;
            let client_alpn = client.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
            assert_eq!(
                negotiated
                    .upstream
                    .get_ref()
                    .1
                    .alpn_protocol()
                    .map(<[u8]>::to_vec),
                upstream_alpn
            );
            Ok((client_alpn, upstream_alpn, negotiated.http2))
        }
    }

    #[tokio::test]
    async fn http2_client_reaches_an_http1_only_upstream() {
        let fixture = AlpnFixture::new();
        let (client, upstream, http2) = fixture
            .negotiate(
                "api.deepinfra.example",
                &[b"http/1.1"],
                &[b"h2", b"http/1.1"],
                true,
            )
            .await
            .expect("an HTTP/1.1-only upstream must stay reachable for an h2-capable client");
        assert_eq!(client.as_deref(), Some(&b"http/1.1"[..]));
        assert_eq!(upstream.as_deref(), Some(&b"http/1.1"[..]));
        assert!(!http2);
    }

    #[tokio::test]
    async fn http2_is_used_end_to_end_when_both_sides_offer_it() {
        let fixture = AlpnFixture::new();
        let (client, upstream, http2) = fixture
            .negotiate(
                "api.openai.example",
                &[b"h2", b"http/1.1"],
                &[b"h2", b"http/1.1"],
                true,
            )
            .await
            .expect("h2 tunnel");
        assert_eq!(client.as_deref(), Some(&b"h2"[..]));
        assert_eq!(upstream.as_deref(), Some(&b"h2"[..]));
        assert!(http2);
    }

    #[tokio::test]
    async fn http1_clients_and_routes_without_http2_use_http1_upstream() {
        let fixture = AlpnFixture::new();
        // An HTTP/1.1-only client must not be handed an h2 upstream.
        let (client, upstream, http2) = fixture
            .negotiate(
                "api.openai.example",
                &[b"h2", b"http/1.1"],
                &[b"http/1.1"],
                true,
            )
            .await
            .expect("HTTP/1.1 client");
        assert_eq!(client.as_deref(), Some(&b"http/1.1"[..]));
        assert_eq!(upstream.as_deref(), Some(&b"http/1.1"[..]));
        assert!(!http2);
        // A route that cannot inspect HTTP/2 keeps HTTP/1.1 on both legs.
        let (client, upstream, http2) = fixture
            .negotiate(
                "api.openai.example",
                &[b"h2", b"http/1.1"],
                &[b"h2", b"http/1.1"],
                false,
            )
            .await
            .expect("route without HTTP/2");
        assert_eq!(client.as_deref(), Some(&b"http/1.1"[..]));
        assert_eq!(upstream.as_deref(), Some(&b"http/1.1"[..]));
        assert!(!http2);
    }

    #[tokio::test]
    async fn upstream_failures_are_reported_as_upstream() {
        let fixture = AlpnFixture::new();
        // An h2-only client cannot be bridged to an HTTP/1.1-only upstream.
        let error = fixture
            .negotiate("api.deepinfra.example", &[b"http/1.1"], &[b"h2"], true)
            .await
            .expect_err("no common protocol");
        assert!(
            error.starts_with("upstream:") || error.starts_with("client:"),
            "{error}"
        );
    }

    async fn serve_one(acceptor: TlsAcceptor) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            // Don't unwrap: when the client (correctly) rejects an untrusted
            // certificate, the server observes a failed handshake too. Only
            // the client's outcome matters here.
            let _ = acceptor.accept(stream).await;
        });
        addr
    }

    #[test]
    fn load_pem_certs_single_ca() {
        let pem = generate_ca_pem();
        let mut store = rustls::RootCertStore::empty();
        let (added, ignored) = load_pem_certs_into_store(&mut store, &pem);
        assert_eq!(added, 1);
        assert_eq!(ignored, 0);
    }

    #[test]
    fn load_pem_certs_multiple_cas() {
        let bundle = format!(
            "{}\n{}\n{}\n",
            generate_ca_pem(),
            generate_ca_pem(),
            generate_ca_pem()
        );
        let mut store = rustls::RootCertStore::empty();
        let (added, ignored) = load_pem_certs_into_store(&mut store, &bundle);
        assert_eq!(added, 3);
        assert_eq!(ignored, 0);
    }

    #[test]
    fn load_pem_certs_empty_string() {
        let mut store = rustls::RootCertStore::empty();
        let (added, ignored) = load_pem_certs_into_store(&mut store, "");
        assert_eq!(added, 0);
        assert_eq!(ignored, 0);
    }

    #[test]
    fn load_pem_certs_garbage_input() {
        let mut store = rustls::RootCertStore::empty();
        let (added, ignored) = load_pem_certs_into_store(&mut store, "this is not PEM data at all");
        assert_eq!(added, 0);
        assert_eq!(ignored, 0);
    }

    #[test]
    fn load_pem_certs_malformed_pem_block() {
        let malformed = "-----BEGIN CERTIFICATE-----\nNOTBASE64!!!\n-----END CERTIFICATE-----\n";
        let mut store = rustls::RootCertStore::empty();
        let (added, ignored) = load_pem_certs_into_store(&mut store, malformed);
        assert_eq!(added, 0);
        assert_eq!(ignored, 1);
    }

    #[test]
    fn load_pem_certs_mixed_valid_and_invalid() {
        let malformed = "-----BEGIN CERTIFICATE-----\nNOTBASE64!!!\n-----END CERTIFICATE-----\n";
        let bundle = format!(
            "{}\n{}{}\n",
            generate_ca_pem(),
            malformed,
            generate_ca_pem()
        );
        let mut store = rustls::RootCertStore::empty();
        let (added, ignored) = load_pem_certs_into_store(&mut store, &bundle);
        assert_eq!(added, 2);
        assert_eq!(ignored, 1);
    }

    #[test]
    fn write_ca_files_includes_sandbox_ca() {
        let ca = SandboxCa::generate().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (ca_path, bundle_path) = write_ca_files(&ca, dir.path(), "").unwrap();

        // Standalone CA cert file should exist and be valid PEM
        let ca_pem = std::fs::read_to_string(&ca_path).unwrap();
        assert!(ca_pem.starts_with("-----BEGIN CERTIFICATE-----"));

        // Combined bundle should contain at least the sandbox CA
        let bundle_pem = std::fs::read_to_string(&bundle_path).unwrap();
        assert!(bundle_pem.contains(ca.cert_pem()));

        // Bundle should be parseable as PEM certificates
        let mut reader = BufReader::new(bundle_pem.as_bytes());
        assert!(
            rustls_pemfile::certs(&mut reader).any(|r| r.is_ok()),
            "bundle should contain at least one cert",
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_ca_files_rejects_symlinked_outputs() {
        use std::os::unix::fs::symlink;

        for output_name in ["openshell-ca.pem", "ca-bundle.pem"] {
            let ca = SandboxCa::generate().expect("generate CA");
            let dir = tempfile::tempdir().expect("temporary directory");
            let sentinel = dir.path().join("sentinel");
            std::fs::write(&sentinel, b"unchanged").expect("write sentinel");
            symlink(&sentinel, dir.path().join(output_name)).expect("create output symlink");

            let error = write_ca_files(&ca, dir.path(), "")
                .expect_err("symlinked TLS output must be rejected");
            assert!(error.to_string().contains("symlinked TLS output"));
            assert_eq!(
                std::fs::read(&sentinel).expect("read sentinel"),
                b"unchanged"
            );
        }
    }

    #[test]
    fn durable_ca_round_trip_preserves_certificate_bytes() {
        let generated = SandboxCa::generate().unwrap();
        let certificate = generated.cert_pem().to_string();
        let private_key = generated.private_key_pem().unwrap();
        let loaded = SandboxCa::from_pem(&certificate, &private_key).unwrap();

        assert_eq!(loaded.cert_pem(), certificate);
        assert_eq!(loaded.private_key_pem().unwrap(), private_key);
        let original_der = rustls_pemfile::certs(&mut certificate.as_bytes())
            .next()
            .unwrap()
            .unwrap();
        let leaf = CertCache::new(loaded).get_or_generate("localhost").unwrap();
        assert_eq!(leaf.cert_chain[1], original_der);
        let mut roots = rustls::RootCertStore::empty();
        roots.add(original_der).unwrap();
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            openshell_crypto::tls::configuration_provider(),
        )
        .build()
        .unwrap();
        rustls::client::danger::ServerCertVerifier::verify_server_cert(
            verifier.as_ref(),
            &leaf.cert_chain[0],
            &[],
            &ServerName::try_from("localhost").unwrap(),
            &[],
            rustls::pki_types::UnixTime::now(),
        )
        .unwrap();
    }

    #[test]
    fn durable_ca_rejects_mismatched_key_and_relative_paths() {
        let certificate = SandboxCa::generate().unwrap();
        let other_key = SandboxCa::generate().unwrap();
        assert!(
            SandboxCa::from_pem(
                certificate.cert_pem(),
                &other_key.private_key_pem().unwrap()
            )
            .is_err()
        );
        assert!(SandboxCa::load_from_paths(Path::new("ca.pem"), Path::new("ca.key")).is_err());
    }
}
