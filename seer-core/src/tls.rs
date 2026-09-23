//! Inspection-only TLS handshake shared by [`crate::ssl`] and [`crate::status`].
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

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{aws_lc_rs, verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    AlertDescription, CertificateError, ClientConfig, DigitallySignedStruct, SignatureScheme,
};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::error::{Result, SeerError};

/// What a server presented during an inspection handshake.
#[derive(Debug)]
pub(crate) struct PresentedChain {
    /// The end-entity certificate (DER).
    pub leaf: CertificateDer<'static>,
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
    let leaf = conn
        .peer_certificates()
        .and_then(|certs| certs.first().cloned())
        .ok_or_else(|| err(format!("{host} presented no certificate")))?;
    Ok(PresentedChain { leaf })
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

#[cfg(test)]
mod tests {
    //! Hermetic: each test serves one handshake on 127.0.0.1 and hands its
    //! address to `inspect` directly, standing in for the SSRF-vetted
    //! addresses callers pass (the guard itself refuses loopback).

    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::server::{ClientHello, ResolvesServerCert};
    use rustls::sign::CertifiedKey;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // Test-only P-256 fixture generated with openssl (valid until 2126).
    /// Leaf `CN=chain.test` (SAN `DNS:chain.test`) issued by [`CA_DER`].
    const LEAF_DER: &str = "MIIBlTCCATqgAwIBAgIUKCxCli0Q1PLwYxTyhtrD7HdFRA4wCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMU2VlciBUZXN0IENBMCAXDTI2MDkyMzAwMTY1OVoYDzIxMjYwODMwMDAxNjU5WjAVMRMwEQYDVQQDDApjaGFpbi50ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEe38KVS2JShSXb/EYFoJil5p0+heKLvI+tGWwhPoCryt3V7qbkTJ7bC1yIHREfe98PReO/qk6aDNAANp1rFRhUqNkMGIwFQYDVR0RBA4wDIIKY2hhaW4udGVzdDAJBgNVHRMEAjAAMB0GA1UdDgQWBBScBoa2qgkylsi8p9t6KzPWkAiCSDAfBgNVHSMEGDAWgBS5XFcFWtxJoNW7VNP1rNYWHSPidjAKBggqhkjOPQQDAgNJADBGAiEA36loQCn3xzgYDPwuvBqM3D+JbCj8/hhidrslPRkPe+kCIQDc8ON6Yd3LaofqIyhdtOwDL3IYuwznsV/80HEvL0wTmw==";
    /// Self-signed `CN=Seer Test CA`.
    const CA_DER: &str = "MIIBlTCCATugAwIBAgIUXHqMG+rB4YKf5efSu60kFPZBDuIwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMU2VlciBUZXN0IENBMCAXDTI2MDkyMzAwMTY1OVoYDzIxMjYwODMwMDAxNjU5WjAXMRUwEwYDVQQDDAxTZWVyIFRlc3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARUFxG40M198DPG4bIfgcLvUPcQzKGd/w/o4GHlMDFUPIBto1POKq1YNKqLxR58ZtChPUJdrXHBTMhxqtAsohlKo2MwYTAdBgNVHQ4EFgQUuVxXBVrcSaDVu1TT9azWFh0j4nYwHwYDVR0jBBgwFoAUuVxXBVrcSaDVu1TT9azWFh0j4nYwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwCgYIKoZIzj0EAwIDSAAwRQIgIJP7q0DrLeCFafAIv7nsFlryvsUJiP90VJtGG7oJADUCIQD8hLibiUqPk8HkJAyZIeVKx7kcijpb2Xc9TEW2HE90NQ==";
    /// PKCS#8 key of [`LEAF_DER`] — a throwaway that exists only for these tests.
    const LEAF_KEY_DER: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgHNpHBJ98pEtKA4x23Lzt4GnSrLJuQ2ViB0QAUGcID3GhRANCAAR7fwpVLYlKFJdv8RgWgmKXmnT6F4ou8j60ZbCE+gKvK3dXupuRMntsLXIgdER973w9F47+qTpoM0AA2nWsVGFS";

    const TIMEOUT: Duration = Duration::from_secs(5);

    fn cert(b64: &str) -> CertificateDer<'static> {
        CertificateDer::from(STANDARD.decode(b64).unwrap())
    }

    /// Presents `chain`, signing with the leaf key whether or not it matches.
    #[derive(Debug)]
    struct Presents(Arc<CertifiedKey>);

    impl ResolvesServerCert for Presents {
        fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            Some(self.0.clone())
        }
    }

    /// Serves one handshake presenting `chain`, limited to `versions`.
    async fn serve_once(
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

    #[tokio::test]
    async fn reads_the_presented_leaf_from_the_given_address() {
        let addr = serve_once(&[LEAF_DER, CA_DER], rustls::DEFAULT_VERSIONS).await;
        // The SNI name never resolves: the connection goes to `addr` only.
        let presented = inspect("chain.test", &[addr], TIMEOUT, SeerError::SslError)
            .await
            .unwrap();
        assert_eq!(presented.leaf, cert(LEAF_DER));
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
