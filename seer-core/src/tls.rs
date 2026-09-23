//! Inspection-only TLS handshake and certificate checks shared by
//! [`crate::ssl`] and [`crate::status`], so the two cannot disagree about the
//! same certificate.
//!
//! Both probes handshake with a server to *read* the certificate chain it
//! presents — expired, self-signed and wrong-host chains included, since
//! reporting on those is the point. Chain trust is therefore never judged
//! here: [`InspectOnly`] accepts any presented chain and callers draw their
//! own date/hostname conclusions from the parsed certificates. The handshake
//! signature is still verified against the leaf's key, so the peer must hold
//! the key of the certificate it presents.
//!
//! rustls runs on the aws-lc-rs provider reqwest and hickory already use,
//! selected explicitly (never rustls' process-wide default). It speaks only
//! TLS 1.2/1.3 with AEAD suites and verifies signatures only from keys that
//! provider supports (e.g. RSA 2048–8192 bits); a server outside that set
//! cannot be inspected and fails with a descriptive error.
//!
//! Single attempt, with the caller's timeout bounding the TCP connect and the
//! handshake separately — like the rest of `ssl`/`status`, a probe must not
//! retry-mask flakiness.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{aws_lc_rs, verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    AlertDescription, CertificateError, ClientConfig, DigitallySignedStruct, ProtocolVersion,
    SignatureScheme,
};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::{GeneralName, X509Certificate};

use crate::error::{Result, SeerError};

/// What a server presented during an inspection handshake.
#[derive(Debug)]
pub(crate) struct PresentedChain {
    /// The end-entity certificate (DER).
    pub leaf: CertificateDer<'static>,
    /// The rest of the chain (DER), in the order the server sent it.
    pub intermediates: Vec<CertificateDer<'static>>,
    /// Negotiated protocol version, e.g. `"TLSv1.3"`.
    pub protocol: Option<String>,
}

/// Handshakes with `host` (the SNI name) and returns what it presented.
///
/// `addrs` must already be SSRF-vetted — callers pass what
/// [`crate::net::resolve_public_host`] returned — so the TCP connection is
/// pinned to the validated addresses with no second lookup to rebind. The
/// connect and the handshake are each bounded by `timeout` (surfacing as
/// [`SeerError::Timeout`]); any other failure is wrapped by `err`, keeping
/// each caller's own error variant.
pub(crate) async fn inspect(
    host: &str,
    addrs: &[SocketAddr],
    timeout: Duration,
    err: fn(String) -> SeerError,
) -> Result<PresentedChain> {
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| err(format!("invalid TLS server name '{host}': {e}")))?;
    let config = inspect_config().map_err(|e| err(format!("TLS setup failed: {e}")))?;

    let tcp = tokio::time::timeout(timeout, TcpStream::connect(addrs))
        .await
        .map_err(|_| SeerError::Timeout(format!("connection to {host} timed out")))?
        .map_err(|e| err(format!("failed to connect to {host}: {e}")))?;
    let tls = tokio::time::timeout(
        timeout,
        TlsConnector::from(Arc::new(config)).connect(server_name, tcp),
    )
    .await
    .map_err(|_| SeerError::Timeout(format!("TLS handshake with {host} timed out")))?
    .map_err(|e| {
        err(format!(
            "TLS handshake with {host} failed: {}",
            describe_failure(&e)
        ))
    })?;

    let (_, conn) = tls.get_ref();
    let mut certs = conn.peer_certificates().unwrap_or_default().iter().cloned();
    let leaf = certs
        .next()
        .ok_or_else(|| err(format!("{host} presented no certificate")))?;
    Ok(PresentedChain {
        leaf,
        intermediates: certs.collect(),
        protocol: conn.protocol_version().map(protocol_name),
    })
}

fn protocol_name(version: ProtocolVersion) -> String {
    match version {
        ProtocolVersion::TLSv1_3 => "TLSv1.3".to_string(),
        ProtocolVersion::TLSv1_2 => "TLSv1.2".to_string(),
        other => format!("{other:?}"),
    }
}

/// A fresh config per probe, so there is no session resumption and every
/// inspection sees the chain the server presents now.
fn inspect_config() -> std::result::Result<ClientConfig, rustls::Error> {
    let provider = Arc::new(aws_lc_rs::default_provider());
    Ok(ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InspectOnly(provider)))
        .with_no_client_auth())
}

/// Accepts any presented chain (see the module docs) while still verifying
/// the handshake signature with the provider's algorithms.
#[derive(Debug)]
struct InspectOnly(Arc<CryptoProvider>);

impl ServerCertVerifier for InspectOnly {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Renders a failed handshake, naming the two can't-inspect cases (see the
/// module docs) instead of leaving a bare alert or verifier code.
fn describe_failure(e: &std::io::Error) -> String {
    let tls = e
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>());
    let hint = match tls {
        Some(
            rustls::Error::PeerIncompatible(_)
            | rustls::Error::AlertReceived(
                AlertDescription::HandshakeFailure
                | AlertDescription::ProtocolVersion
                | AlertDescription::InsufficientSecurity,
            ),
        ) => "; the server may offer only protocol versions or cipher suites older than TLS 1.2 with AEAD, which cannot be inspected",
        Some(rustls::Error::InvalidCertificate(
            CertificateError::BadSignature
            | CertificateError::UnsupportedSignatureAlgorithmContext { .. }
            | CertificateError::UnsupportedSignatureAlgorithmForPublicKeyContext { .. },
        )) => "; its handshake signature could not be verified with the certificate's key (e.g. an RSA key below 2048 bits), so the certificate cannot be inspected",
        _ => "",
    };
    format!("{e}{hint}")
}

/// Whether `cert` identifies `host`, per RFC 6125 §6.4.4.
///
/// dNSName SANs are the DNS-IDs: when a certificate carries any, they alone
/// decide, so a CN that happens to name `host` cannot rescue a cert issued for
/// other hosts. The subject CN is a legacy fallback consulted only when there
/// is no DNS-ID — an iPAddress SAN is not one. An IP-literal `host` also
/// matches an equal iPAddress SAN.
pub(crate) fn cert_matches_host(cert: &X509Certificate<'_>, host: &str) -> bool {
    let host_ip = host.parse::<IpAddr>().ok();
    let mut has_dns_id = false;
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            match name {
                GeneralName::DNSName(pattern) => {
                    has_dns_id = true;
                    if hostname_matches_pattern(host, pattern) {
                        return true;
                    }
                }
                GeneralName::IPAddress(bytes)
                    if san_ip(bytes).is_some_and(|ip| Some(ip) == host_ip) =>
                {
                    return true;
                }
                _ => {}
            }
        }
    }
    !has_dns_id
        && cert
            .subject()
            .iter_common_name()
            .filter_map(|cn| cn.as_str().ok())
            .any(|cn| hostname_matches_pattern(host, cn))
}

/// Exact (case-insensitive) or single-label wildcard match per RFC 6125:
/// `*.example.com` matches `a.example.com` but not `example.com` or
/// `a.b.example.com`.
fn hostname_matches_pattern(host: &str, pattern: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let pattern = pattern.to_ascii_lowercase();
    match pattern.strip_prefix("*.") {
        Some(rest) => host
            .split_once('.')
            .is_some_and(|(_, host_rest)| host_rest == rest),
        None => host == pattern,
    }
}

/// Decodes an iPAddress SAN: 4 bytes are IPv4, 16 are IPv6, anything else is
/// malformed.
pub(crate) fn san_ip(bytes: &[u8]) -> Option<IpAddr> {
    match <[u8; 4]>::try_from(bytes) {
        Ok(v4) => Some(IpAddr::from(v4)),
        Err(_) => <[u8; 16]>::try_from(bytes).ok().map(IpAddr::from),
    }
}

/// The certificate's `notBefore`/`notAfter` in UTC, or `None` when either is
/// outside chrono's range.
pub(crate) fn validity_window(
    cert: &X509Certificate<'_>,
) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    let validity = cert.validity();
    Some((
        DateTime::from_timestamp(validity.not_before.timestamp(), 0)?,
        DateTime::from_timestamp(validity.not_after.timestamp(), 0)?,
    ))
}

/// Loopback TLS fixture shared with the `ssl`/`status` tests. Each server
/// handles one handshake on 127.0.0.1; tests hand its address straight to
/// [`inspect`], standing in for the SSRF-vetted addresses production callers
/// pass (the guard itself refuses loopback).
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::server::{ClientHello, ResolvesServerCert};
    use rustls::sign::CertifiedKey;
    use tokio::net::TcpListener;

    // Test-only P-256 fixture generated with openssl (valid until 2126).
    /// Leaf `CN=chain.test` (SAN `DNS:chain.test`) issued by [`CA_DER`].
    pub const LEAF_DER: &str = "MIIBlTCCATqgAwIBAgIUKCxCli0Q1PLwYxTyhtrD7HdFRA4wCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMU2VlciBUZXN0IENBMCAXDTI2MDkyMzAwMTY1OVoYDzIxMjYwODMwMDAxNjU5WjAVMRMwEQYDVQQDDApjaGFpbi50ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEe38KVS2JShSXb/EYFoJil5p0+heKLvI+tGWwhPoCryt3V7qbkTJ7bC1yIHREfe98PReO/qk6aDNAANp1rFRhUqNkMGIwFQYDVR0RBA4wDIIKY2hhaW4udGVzdDAJBgNVHRMEAjAAMB0GA1UdDgQWBBScBoa2qgkylsi8p9t6KzPWkAiCSDAfBgNVHSMEGDAWgBS5XFcFWtxJoNW7VNP1rNYWHSPidjAKBggqhkjOPQQDAgNJADBGAiEA36loQCn3xzgYDPwuvBqM3D+JbCj8/hhidrslPRkPe+kCIQDc8ON6Yd3LaofqIyhdtOwDL3IYuwznsV/80HEvL0wTmw==";
    /// Self-signed `CN=Seer Test CA`.
    pub const CA_DER: &str = "MIIBlTCCATugAwIBAgIUXHqMG+rB4YKf5efSu60kFPZBDuIwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMU2VlciBUZXN0IENBMCAXDTI2MDkyMzAwMTY1OVoYDzIxMjYwODMwMDAxNjU5WjAXMRUwEwYDVQQDDAxTZWVyIFRlc3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARUFxG40M198DPG4bIfgcLvUPcQzKGd/w/o4GHlMDFUPIBto1POKq1YNKqLxR58ZtChPUJdrXHBTMhxqtAsohlKo2MwYTAdBgNVHQ4EFgQUuVxXBVrcSaDVu1TT9azWFh0j4nYwHwYDVR0jBBgwFoAUuVxXBVrcSaDVu1TT9azWFh0j4nYwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwCgYIKoZIzj0EAwIDSAAwRQIgIJP7q0DrLeCFafAIv7nsFlryvsUJiP90VJtGG7oJADUCIQD8hLibiUqPk8HkJAyZIeVKx7kcijpb2Xc9TEW2HE90NQ==";
    /// Self-signed `CN=victim.example`, SAN `DNS:other.example`.
    pub const CN_VICTIM_SAN_OTHER: &str = "MIIBoDCCAUegAwIBAgIUdStRrtt0ycIGUV74700+xRrFcJ0wCgYIKoZIzj0EAwIwGTEXMBUGA1UEAwwOdmljdGltLmV4YW1wbGUwHhcNMjYwOTIyMTcwMzA4WhcNMzYwOTE5MTcwMzA4WjAZMRcwFQYDVQQDDA52aWN0aW0uZXhhbXBsZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJPCvcjh/aeA2qb1taFaBCxI/ue4srU8jUNjjvQW9IKMqdsUluEGjW7fcYSa8w/79MWZ/naVmgZKQs/eSXCU/AWjbTBrMB0GA1UdDgQWBBSG5So71BSr3DZri66kQaPKzWbjNDAfBgNVHSMEGDAWgBSG5So71BSr3DZri66kQaPKzWbjNDAPBgNVHRMBAf8EBTADAQH/MBgGA1UdEQQRMA+CDW90aGVyLmV4YW1wbGUwCgYIKoZIzj0EAwIDRwAwRAIgEnAMNQMytsawL+CuV7N9z/ftwHVzdFunp+oG7QjIou4CIHsf9vyIXQUPs5iBrhprcRiwyuZQWy0mZyRdavp4Kgbh";
    /// Self-signed `CN=victim.example`, no SAN extension.
    pub const CN_VICTIM_NO_SAN: &str = "MIIBhzCCAS2gAwIBAgIUeGkzmcc68l5FOH5NOBgS3Ybcg4gwCgYIKoZIzj0EAwIwGTEXMBUGA1UEAwwOdmljdGltLmV4YW1wbGUwHhcNMjYwOTIyMTcwMzA4WhcNMzYwOTE5MTcwMzA4WjAZMRcwFQYDVQQDDA52aWN0aW0uZXhhbXBsZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABC6rgHiHBhd3vxpcRHm7VH2YgCybc0Bl4ewS1lMjdtM5+R+pX/STje36olq5IDx9AEJfxtdRMvtiWp9jfb5vdB6jUzBRMB0GA1UdDgQWBBS5JfZqENT0bfsAazBNLiAVb77UdzAfBgNVHSMEGDAWgBS5JfZqENT0bfsAazBNLiAVb77UdzAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQD5zMnpSHSVr3vSmZM0vh0R345Rg3wc+OgeZwmsDxDJQQIgBNJ0CS0bpChCAQls0oFZUPD6u7iX7uBOD/QRPZ2Ub1k=";
    /// Self-signed `CN=victim.example`, SAN `IP:203.0.113.7` only.
    pub const CN_VICTIM_SAN_IP: &str = "MIIBmTCCAUCgAwIBAgIUNLKX5hfp150WybxH1TK4/buhJpkwCgYIKoZIzj0EAwIwGTEXMBUGA1UEAwwOdmljdGltLmV4YW1wbGUwIBcNMjYwOTIzMDAxNzA0WhgPMjEyNjA4MzAwMDE3MDRaMBkxFzAVBgNVBAMMDnZpY3RpbS5leGFtcGxlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE34KvRRWyPfrfW30NuPRHBL/o0xYniAlVPTcjaEbsksvvSTPk0uPM2FA9GSrD8YQa+BqxdfCjZ3vMARvA95A9e6NkMGIwHQYDVR0OBBYEFCUaB8nqqyd/yXM9pZGqBITswjqTMB8GA1UdIwQYMBaAFCUaB8nqqyd/yXM9pZGqBITswjqTMA8GA1UdEwEB/wQFMAMBAf8wDwYDVR0RBAgwBocEywBxBzAKBggqhkjOPQQDAgNHADBEAiBpAbhxdLJCQWa6M9mMTKL+iXYo1FMxb0BZYOTngYts5wIgIDTiVbjBH69Uozws5X7IxMhoeF7dNXNaSzo+Fnd2zEM=";
    /// PKCS#8 key of [`LEAF_DER`] — a throwaway that exists only for these tests.
    const LEAF_KEY_DER: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgHNpHBJ98pEtKA4x23Lzt4GnSrLJuQ2ViB0QAUGcID3GhRANCAAR7fwpVLYlKFJdv8RgWgmKXmnT6F4ou8j60ZbCE+gKvK3dXupuRMntsLXIgdER973w9F47+qTpoM0AA2nWsVGFS";

    pub fn cert(b64: &str) -> CertificateDer<'static> {
        CertificateDer::from(STANDARD.decode(b64).unwrap())
    }

    /// Presents a fixed chain, signing with the leaf key whether or not it
    /// matches (so tests can also present a certificate the server can't prove).
    #[derive(Debug)]
    struct Presents(Arc<CertifiedKey>);

    impl ResolvesServerCert for Presents {
        fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            Some(self.0.clone())
        }
    }

    /// Serves one handshake presenting `chain`, limited to `versions`.
    pub async fn serve_once(
        chain: &[&str],
        versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> SocketAddr {
        let provider = Arc::new(aws_lc_rs::default_provider());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            STANDARD.decode(LEAF_KEY_DER).unwrap(),
        ));
        let key = provider.key_provider.load_private_key(key).unwrap();
        let chain = chain.iter().map(|c| cert(c)).collect();
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Presents(Arc::new(CertifiedKey::new(chain, key)))));
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(tcp).await;
        });
        addr
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use x509_parser::prelude::FromDer;

    const TIMEOUT: Duration = Duration::from_secs(5);

    #[test]
    fn host_identity_follows_rfc_6125() {
        let matches = |b64: &str, host: &str| {
            let der = cert(b64);
            let (_, x509) = X509Certificate::from_der(&der).unwrap();
            cert_matches_host(&x509, host)
        };
        // DNS-ID SANs decide alone: a matching CN can't rescue a cert whose
        // SANs name other hosts.
        assert!(!matches(CN_VICTIM_SAN_OTHER, "victim.example"));
        assert!(matches(CN_VICTIM_SAN_OTHER, "other.example"));
        // No SAN at all: the legacy CN fallback applies.
        assert!(matches(CN_VICTIM_NO_SAN, "victim.example"));
        assert!(!matches(CN_VICTIM_NO_SAN, "other.example"));
        // Regression: an iPAddress SAN is not a DNS-ID, so it must not switch
        // the CN fallback off (`seer ssl` did, `seer status` didn't) — and it
        // does match an IP-literal host.
        assert!(matches(CN_VICTIM_SAN_IP, "victim.example"));
        assert!(matches(CN_VICTIM_SAN_IP, "203.0.113.7"));
        assert!(!matches(CN_VICTIM_SAN_IP, "203.0.113.8"));
    }

    #[test]
    fn hostname_patterns_match_exactly_or_one_wildcard_label() {
        assert!(hostname_matches_pattern("example.com", "example.com"));
        assert!(hostname_matches_pattern("EXAMPLE.COM", "example.com"));
        assert!(hostname_matches_pattern("example.com", "EXAMPLE.COM"));
        assert!(!hostname_matches_pattern("evil.com", "example.com"));
        assert!(hostname_matches_pattern("a.example.com", "*.example.com"));
        assert!(hostname_matches_pattern("A.EXAMPLE.COM", "*.example.com"));
        // The apex doesn't match its wildcard, which covers exactly one label.
        assert!(!hostname_matches_pattern("example.com", "*.example.com"));
        assert!(!hostname_matches_pattern(
            "a.b.example.com",
            "*.example.com"
        ));
        assert!(!hostname_matches_pattern("b.other.com", "*.example.com"));
        assert!(!hostname_matches_pattern("localhost", "*.example.com"));
    }

    #[tokio::test]
    async fn returns_the_chain_as_presented_and_the_negotiated_protocol() {
        for (version, name) in [
            (&rustls::version::TLS13, "TLSv1.3"),
            (&rustls::version::TLS12, "TLSv1.2"),
        ] {
            let addr = serve_once(&[LEAF_DER, CA_DER], &[version]).await;
            // The SNI name never resolves: the connection goes to `addr` only.
            let presented = inspect("chain.test", &[addr], TIMEOUT, SeerError::SslError)
                .await
                .unwrap();
            assert_eq!(presented.leaf, cert(LEAF_DER));
            assert_eq!(presented.intermediates, vec![cert(CA_DER)]);
            assert_eq!(presented.protocol.as_deref(), Some(name));
        }
    }

    #[tokio::test]
    async fn handshake_signature_is_still_verified() {
        // The CA certificate presented with the leaf's key: any chain is
        // accepted, but the peer must hold the key of the cert it presents.
        let addr = serve_once(&[CA_DER], rustls::DEFAULT_VERSIONS).await;
        let err = inspect("chain.test", &[addr], TIMEOUT, SeerError::CertificateError)
            .await
            .unwrap_err();
        assert!(matches!(err, SeerError::CertificateError(_)), "got {err:?}");
        assert!(err.to_string().contains("signature could not be verified"));
    }

    #[tokio::test]
    async fn legacy_only_server_gets_a_descriptive_error() {
        // What a server with no TLS 1.2+/AEAD suite in common answers to our
        // ClientHello: a fatal handshake_failure alert record.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let _ = tcp.read(&mut [0u8; 1024]).await;
            let _ = tcp.write_all(&[21, 3, 3, 0, 2, 2, 40]).await;
        });

        let err = inspect("legacy.test", &[addr], TIMEOUT, SeerError::SslError)
            .await
            .unwrap_err();
        assert!(matches!(err, SeerError::SslError(_)), "got {err:?}");
        let msg = err.to_string();
        assert!(msg.contains("HandshakeFailure"), "got: {msg}");
        assert!(msg.contains("older than TLS 1.2"), "got: {msg}");
    }

    #[tokio::test]
    async fn a_stalled_handshake_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _held = listener.accept().await;
            std::future::pending::<()>().await;
        });

        let err = inspect(
            "stall.test",
            &[addr],
            Duration::from_millis(200),
            SeerError::SslError,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SeerError::Timeout(_)), "got {err:?}");
    }
}
