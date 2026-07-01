//! SSL certificate chain inspection.
//!
//! Provides detailed SSL/TLS certificate information including the certificate
//! chain, Subject Alternative Names (SANs), key details, and validity status.
//!
//! Retry boundary (deliberate): single-attempt, like [`crate::status`] — a
//! certificate inspection is a point-in-time observation, and retrying would
//! hide intermittent TLS failures from the user. Transient-failure tolerance
//! belongs to callers (e.g. watch mode).

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_native_tls::TlsConnector;
use tracing::{debug, instrument};
use x509_parser::oid_registry::Oid;
use x509_parser::prelude::*;

use crate::caa::{self, CaaPolicy};
use crate::dns::DnsResolver;
use crate::error::{Result, SeerError};
use crate::net::resolve_public_host;
use crate::validation::normalize_domain;

/// Default timeout for SSL operations (10 seconds).
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Minimum acceptable RSA key size in bits (NIST SP 800-57 / CA/B Forum).
const RSA_MIN_KEY_BITS: u32 = 2048;
/// Minimum acceptable elliptic-curve key size in bits.
const EC_MIN_KEY_BITS: u32 = 256;
/// Days-until-expiry threshold below which a still-valid cert is flagged.
const CERT_EXPIRING_SOON_DAYS: i64 = 30;

/// Derives security-posture [`CertWarning`]s from an already-parsed leaf
/// certificate plus the computed validity/hostname signals. Pure — no network
/// calls — so it is unit-testable in isolation.
fn derive_cert_warnings(
    leaf: &CertDetail,
    is_valid: bool,
    hostname_verified: bool,
    days_until_expiry: i64,
) -> Vec<CertWarning> {
    let mut warnings = Vec::new();
    let critical = |message: String| CertWarning {
        severity: CertWarningSeverity::Critical,
        message,
    };
    let warn = |message: String| CertWarning {
        severity: CertWarningSeverity::Warning,
        message,
    };

    // Weak public key.
    if let (Some(kt), Some(bits)) = (leaf.key_type.as_deref(), leaf.key_bits) {
        match kt {
            "RSA" if bits < RSA_MIN_KEY_BITS => warnings.push(critical(format!(
                "RSA key size {bits} is below the {RSA_MIN_KEY_BITS}-bit minimum"
            ))),
            "EC" if bits < EC_MIN_KEY_BITS => warnings.push(critical(format!(
                "EC key size {bits} is below the {EC_MIN_KEY_BITS}-bit minimum"
            ))),
            _ => {}
        }
    }

    // Deprecated signature algorithm (SHA-1 / MD5).
    if let Some(sig) = leaf.signature_algorithm.as_deref() {
        let lower = sig.to_lowercase();
        if lower.contains("sha-1") || lower.contains("sha1") || lower.contains("md5") {
            warnings.push(critical(format!(
                "Certificate uses deprecated signature algorithm: {sig}"
            )));
        }
    }

    // Self-signed (issuer equals subject).
    if leaf.subject == leaf.issuer {
        warnings.push(warn(
            "Certificate is self-signed (issuer equals subject)".to_string(),
        ));
    }

    // Leaf certificate marked as a CA (basic-constraints misuse).
    if leaf.is_ca {
        warnings.push(warn(
            "Leaf certificate is marked as a CA certificate".to_string(),
        ));
    }

    // Validity window.
    if days_until_expiry < 0 {
        warnings.push(critical(format!(
            "Certificate expired {} day(s) ago",
            -days_until_expiry
        )));
    } else if !is_valid {
        // Date-valid check failed but not past expiry → notBefore is future.
        warnings.push(critical(
            "Certificate is not yet valid (notBefore is in the future)".to_string(),
        ));
    } else if days_until_expiry <= CERT_EXPIRING_SOON_DAYS {
        warnings.push(warn(format!(
            "Certificate expires in {days_until_expiry} day(s)"
        )));
    }

    // Hostname mismatch.
    if !hostname_verified {
        warnings.push(critical(
            "Certificate does not match the requested hostname".to_string(),
        ));
    }

    warnings
}

/// Full SSL certificate report for a domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslReport {
    /// The domain that was inspected
    pub domain: String,
    /// Certificate chain from leaf to root (as many as the server provides)
    pub chain: Vec<CertDetail>,
    /// TLS protocol version (best-effort detection)
    pub protocol_version: Option<String>,
    /// Subject Alternative Names from the leaf certificate
    pub san_names: Vec<String>,
    /// Whether the leaf certificate is within its validity period.
    ///
    /// This reflects ONLY the date-range check (`notBefore <= now <=
    /// notAfter`) of the leaf certificate. It does NOT verify the certificate
    /// chain's trust (this checker uses `danger_accept_invalid_certs(true)` to
    /// inspect broken/self-signed certs) nor that the certificate matches the
    /// requested hostname — see [`SslReport::hostname_verified`]. A
    /// date-valid cert may still be self-signed, issued by an untrusted CA, or
    /// presented for the wrong host.
    pub is_valid: bool,
    /// Whether the leaf certificate's SAN dNSNames (or CN as a legacy
    /// fallback) match the requested domain, per RFC 6125 (exact and
    /// single-label wildcard matches).
    ///
    /// This is an additive signal independent of `is_valid`. Chain trust is
    /// NOT verified here: a `true` value means the cert was presented for the
    /// right host, not that it was issued by a trusted CA.
    #[serde(default)]
    pub hostname_verified: bool,
    /// Days until the leaf certificate expires
    pub days_until_expiry: i64,
    /// CAA (Certification Authority Authorization) policy for the domain
    /// plus a comparison against the presented certificate's issuer.
    ///
    /// CAA is consulted by CAs at *issuance time*, not by clients at
    /// *validation time*, so a mismatch here is informational — see the
    /// `note` field on [`CaaPolicy`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caa: Option<CaaPolicy>,
    /// Security-posture warnings derived from the leaf certificate: weak keys,
    /// deprecated signatures, self-signed / CA-marked leaves, expiry, and
    /// hostname mismatch. Empty when the leaf presents no notable issues.
    ///
    /// These are pure post-processing of already-parsed fields (no extra
    /// network calls) — a summary so consumers don't have to eyeball key sizes
    /// and algorithms.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<CertWarning>,
}

/// Severity of a [`CertWarning`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertWarningSeverity {
    /// A trust-affecting problem (weak key, deprecated signature, expired,
    /// hostname mismatch).
    Critical,
    /// A notable-but-not-fatal signal (self-signed, CA-marked leaf, expiring
    /// soon).
    Warning,
}

/// A single security-posture warning about a certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertWarning {
    /// How serious the finding is.
    pub severity: CertWarningSeverity,
    /// Human-readable description of the finding.
    pub message: String,
}

/// Detailed information about a single certificate in the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertDetail {
    /// Certificate subject (e.g., "CN=example.com")
    pub subject: String,
    /// Certificate issuer (e.g., "CN=R3, O=Let's Encrypt")
    pub issuer: String,
    /// Certificate validity start date
    pub valid_from: DateTime<Utc>,
    /// Certificate expiration date
    pub valid_until: DateTime<Utc>,
    /// Serial number in hexadecimal
    pub serial_number: String,
    /// Signature algorithm (e.g., "sha256WithRSAEncryption")
    pub signature_algorithm: Option<String>,
    /// Whether this is a Certificate Authority certificate
    pub is_ca: bool,
    /// Public key type (e.g., "RSA", "EC")
    pub key_type: Option<String>,
    /// Public key size in bits
    pub key_bits: Option<u32>,
}

/// Client for performing SSL certificate chain inspection.
#[derive(Debug, Clone)]
pub struct SslChecker {
    /// Cached DNS resolver used for CAA lookups alongside the TLS probe.
    dns_resolver: DnsResolver,
    /// Timeout for the TCP connect and TLS handshake.
    timeout: Duration,
}

impl Default for SslChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl SslChecker {
    /// Creates a new SslChecker instance.
    pub fn new() -> Self {
        Self {
            dns_resolver: DnsResolver::new(),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Sets the timeout for the TCP connect and TLS handshake.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self.dns_resolver = DnsResolver::new().with_timeout(timeout);
        self
    }

    /// Inspects the SSL certificate chain for the given domain.
    ///
    /// Connects to port 443, performs a TLS handshake, and extracts detailed
    /// certificate information including the full chain, SANs, and key details.
    ///
    /// # Arguments
    /// * `domain` - The domain name to inspect (e.g., "example.com")
    ///
    /// # Returns
    /// * `Ok(SslReport)` - Detailed SSL certificate information
    /// * `Err(SeerError)` - If connection or certificate parsing fails
    #[instrument(skip(self), fields(domain = %domain))]
    pub async fn check(&self, domain: &str) -> Result<SslReport> {
        let domain = normalize_domain(domain)?;

        debug!(domain = %domain, "Checking SSL certificate chain");

        // CAA query runs concurrently with the TLS probe — it is advisory
        // and never fails the report (a resolver error yields an empty
        // policy).
        let caa_future = caa::lookup_caa(&self.dns_resolver, &domain);

        // Resolve + SSRF check. `resolve_public_host` already falls back to
        // hickory (Google DNS) when the OS resolver fails — important for
        // hosts where Tailscale Split-DNS or a corp resolver pins the
        // domain to a nameserver that can't answer for it.
        let resolve_future = resolve_public_host(&domain, 443);

        let (caa_policy, socket_addrs) = tokio::join!(caa_future, resolve_future);
        let socket_addrs = socket_addrs.map_err(|e| {
            SeerError::SslError(format!(
                "could not resolve {} for SSL inspection: {}",
                domain, e
            ))
        })?;

        // Build TLS connector - accept invalid certs so we can inspect them
        let connector = native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| SeerError::SslError(format!("Failed to create TLS connector: {}", e)))?;
        let connector = TlsConnector::from(connector);

        // TCP connect with timeout — connect to pre-resolved address to prevent DNS rebinding
        let stream =
            tokio::time::timeout(self.timeout, TcpStream::connect(socket_addrs.as_slice()))
                .await
                .map_err(|_| SeerError::Timeout("SSL connection timed out".to_string()))?
                .map_err(|e| {
                    SeerError::SslError(format!("Failed to connect to {}:443: {}", domain, e))
                })?;

        // TLS handshake with timeout
        let tls_stream = tokio::time::timeout(self.timeout, connector.connect(&domain, stream))
            .await
            .map_err(|_| SeerError::Timeout("TLS handshake timed out".to_string()))?
            .map_err(|e| SeerError::SslError(format!("TLS handshake failed: {}", e)))?;

        // Get the peer certificate (leaf)
        let cert = tls_stream
            .get_ref()
            .peer_certificate()
            .map_err(|e| SeerError::SslError(format!("Failed to get certificate: {}", e)))?
            .ok_or_else(|| SeerError::SslError("No certificate presented".to_string()))?;

        let der = cert
            .to_der()
            .map_err(|e| SeerError::SslError(format!("Failed to encode certificate: {}", e)))?;

        // Parse leaf certificate with x509-parser
        let (_, x509) = X509Certificate::from_der(&der)
            .map_err(|e| SeerError::SslError(format!("Failed to parse certificate: {}", e)))?;

        // Extract SANs from the leaf certificate
        let san_names = extract_sans(&x509);

        // Build the certificate chain
        // native-tls only exposes the leaf cert directly; we parse what we have
        let leaf_detail = parse_cert_detail(&x509)?;

        let now = Utc::now();
        let days_until_expiry = (leaf_detail.valid_until - now).num_days();
        let is_valid = now >= leaf_detail.valid_from && now <= leaf_detail.valid_until;

        // Hostname verification: does the leaf cert's SAN (or CN fallback)
        // match the requested domain? This is independent of `is_valid` and of
        // chain trust (which is not verified here — see the field docs). Lets
        // consumers tell a date-valid-but-wrong-host cert apart from a real
        // match. Per RFC 6125 §6.4.4 the CN is consulted ONLY when the cert
        // presents no identifier SANs at all; if any dNSName/IPAddress SAN is
        // present the CN must be ignored, otherwise a cert whose SANs cover
        // other hosts but whose CN happens to match would falsely verify.
        let hostname_verified = san_names
            .iter()
            .any(|san| hostname_matches_pattern(&domain, san))
            || (san_names.is_empty() && subject_cn_matches_host(&x509, &domain));

        // Annotate the CAA policy with the issuer comparison before
        // attaching it to the report.
        let mut caa_policy = caa_policy;
        caa_policy.issuer_match = Some(caa::classify_issuer(&leaf_detail.issuer, &caa_policy));

        // Derive posture warnings from the parsed leaf (pure post-processing).
        let warnings =
            derive_cert_warnings(&leaf_detail, is_valid, hostname_verified, days_until_expiry);

        Ok(SslReport {
            domain,
            chain: vec![leaf_detail],
            protocol_version: None,
            san_names,
            is_valid,
            hostname_verified,
            days_until_expiry,
            caa: Some(caa_policy),
            warnings,
        })
    }
}

/// Returns true if `host` matches the certificate name `pattern`, supporting
/// exact (case-insensitive) matches and single-label wildcards per RFC 6125
/// (`*.example.com` matches `a.example.com` but not `example.com` or
/// `a.b.example.com`).
fn hostname_matches_pattern(host: &str, pattern: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let pattern = pattern.to_ascii_lowercase();
    if let Some(rest) = pattern.strip_prefix("*.") {
        let Some(dot) = host.find('.') else {
            return false;
        };
        let host_rest = &host[dot + 1..];
        host_rest == rest
    } else {
        host == pattern
    }
}

/// Legacy CN fallback for hostname verification: checks the leaf certificate's
/// subject Common Name(s) against `host`. SAN dNSNames are authoritative per
/// RFC 6125; CN is only consulted when the certificate presents no identifier
/// SANs at all (the caller gates this on `san_names.is_empty()`).
fn subject_cn_matches_host(cert: &X509Certificate, host: &str) -> bool {
    for cn in cert.subject().iter_common_name() {
        if let Ok(s) = cn.as_str() {
            if hostname_matches_pattern(host, s) {
                return true;
            }
        }
    }
    false
}

/// Extracts Subject Alternative Names from a certificate.
fn extract_sans(cert: &X509Certificate) -> Vec<String> {
    let mut sans = Vec::new();
    if let Ok(Some(ext)) = cert.subject_alternative_name() {
        for name in &ext.value.general_names {
            match name {
                GeneralName::DNSName(dns) => {
                    sans.push(dns.to_string());
                }
                GeneralName::IPAddress(ip_bytes) => {
                    sans.push(format_ip_san(ip_bytes));
                }
                _ => {}
            }
        }
    }
    sans
}

/// Renders an IPAddress SAN from its raw bytes into canonical text form.
///
/// A 4-byte value becomes dotted-quad IPv4; a 16-byte value becomes a
/// zero-compressed IPv6 address (e.g. `::1`, not `0000:0000:...:0001`) by going
/// through `std::net::Ipv6Addr`'s `Display`. Any other length is unexpected for
/// an IPAddress general name, so it falls back to a debug rendering of the bytes
/// rather than guessing.
fn format_ip_san(ip_bytes: &[u8]) -> String {
    match ip_bytes.len() {
        4 => {
            let octets: [u8; 4] = [ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]];
            std::net::Ipv4Addr::from(octets).to_string()
        }
        16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(ip_bytes);
            std::net::Ipv6Addr::from(octets).to_string()
        }
        _ => format!("{:?}", ip_bytes),
    }
}

/// Parses detailed information from an X.509 certificate.
fn parse_cert_detail(cert: &X509Certificate) -> Result<CertDetail> {
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();

    let valid_from = asn1_time_to_chrono(cert.validity().not_before)?;
    let valid_until = asn1_time_to_chrono(cert.validity().not_after)?;

    let serial_number = cert.serial.to_str_radix(16);

    let signature_algorithm = oid_to_name(&cert.signature_algorithm.algorithm);

    let is_ca = cert.is_ca();

    // Extract public key info
    let spki = cert.public_key();
    let (key_type, key_bits) = extract_key_info(spki);

    Ok(CertDetail {
        subject,
        issuer,
        valid_from,
        valid_until,
        serial_number,
        signature_algorithm,
        is_ca,
        key_type,
        key_bits,
    })
}

/// Extracts key type and size from a SubjectPublicKeyInfo.
fn extract_key_info(spki: &SubjectPublicKeyInfo) -> (Option<String>, Option<u32>) {
    use x509_parser::public_key::PublicKey;
    let oid = &spki.algorithm.algorithm;
    let key_type = oid_to_key_type(oid);
    let key_bits = match spki.parsed() {
        Ok(PublicKey::RSA(rsa)) => Some(rsa.key_size() as u32),
        Ok(PublicKey::EC(ec)) => Some(ec.key_size() as u32),
        _ => None,
    };
    (key_type, key_bits)
}

/// Maps common OIDs to human-readable algorithm names.
fn oid_to_name(oid: &Oid) -> Option<String> {
    let oid_str = format!("{}", oid);
    match oid_str.as_str() {
        "1.2.840.113549.1.1.11" => Some("SHA-256 with RSA".to_string()),
        "1.2.840.113549.1.1.12" => Some("SHA-384 with RSA".to_string()),
        "1.2.840.113549.1.1.13" => Some("SHA-512 with RSA".to_string()),
        "1.2.840.113549.1.1.5" => Some("SHA-1 with RSA".to_string()),
        "1.2.840.113549.1.1.14" => Some("SHA-224 with RSA".to_string()),
        "1.2.840.10045.4.3.2" => Some("ECDSA with SHA-256".to_string()),
        "1.2.840.10045.4.3.3" => Some("ECDSA with SHA-384".to_string()),
        "1.2.840.10045.4.3.4" => Some("ECDSA with SHA-512".to_string()),
        "1.3.101.112" => Some("Ed25519".to_string()),
        "1.3.101.113" => Some("Ed448".to_string()),
        _ => Some(oid_str),
    }
}

/// Maps public key algorithm OIDs to human-readable key type names.
fn oid_to_key_type(oid: &Oid) -> Option<String> {
    let oid_str = format!("{}", oid);
    match oid_str.as_str() {
        "1.2.840.113549.1.1.1" => Some("RSA".to_string()),
        "1.2.840.10045.2.1" => Some("EC".to_string()),
        "1.3.101.112" => Some("Ed25519".to_string()),
        "1.3.101.113" => Some("Ed448".to_string()),
        _ => Some(oid_str),
    }
}

/// Converts an x509-parser ASN1Time to a chrono DateTime.
fn asn1_time_to_chrono(time: ASN1Time) -> Result<DateTime<Utc>> {
    let timestamp = time.timestamp();
    DateTime::from_timestamp(timestamp, 0)
        .ok_or_else(|| SeerError::SslError("invalid certificate timestamp".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssl_checker_creation() {
        let _checker = SslChecker::new();
        let _default_checker = SslChecker::default();
    }

    #[test]
    fn test_oid_to_name() {
        let oid = Oid::from(&[1, 2, 840, 113549, 1, 1, 11][..]).unwrap();
        assert_eq!(oid_to_name(&oid), Some("SHA-256 with RSA".to_string()));
    }

    #[test]
    fn test_oid_to_key_type() {
        let oid = Oid::from(&[1, 2, 840, 113549, 1, 1, 1][..]).unwrap();
        assert_eq!(oid_to_key_type(&oid), Some("RSA".to_string()));
    }

    /// Live-network sanity check: a real public site with valid TLS
    /// completes a full chain inspection. Exercises the
    /// [`resolve_public_host`] code path in `net.rs` (hickory fallback
    /// engages if the test environment has a broken OS resolver) and the
    /// rest of the TLS handshake + cert-parse pipeline.
    #[tokio::test]
    #[ignore = "requires network — performs a real TLS handshake"]
    async fn check_live_example_com_succeeds() {
        let report = SslChecker::new().check("example.com").await.unwrap();
        assert_eq!(report.domain, "example.com");
        assert!(!report.chain.is_empty(), "expected at least a leaf cert");
        assert!(
            report.is_valid,
            "example.com's leaf cert should be currently valid"
        );
    }

    #[test]
    fn test_ssl_report_serialization() {
        let report = SslReport {
            domain: "example.com".to_string(),
            chain: vec![CertDetail {
                subject: "CN=example.com".to_string(),
                issuer: "CN=R3, O=Let's Encrypt".to_string(),
                valid_from: Utc::now(),
                valid_until: Utc::now(),
                serial_number: "abc123".to_string(),
                signature_algorithm: Some("SHA-256 with RSA".to_string()),
                is_ca: false,
                key_type: Some("RSA".to_string()),
                key_bits: Some(2048),
            }],
            protocol_version: None,
            san_names: vec!["example.com".to_string(), "*.example.com".to_string()],
            is_valid: true,
            hostname_verified: true,
            days_until_expiry: 90,
            caa: None,
            warnings: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("example.com"));
        assert!(json.contains("SHA-256 with RSA"));
        assert!(json.contains("\"is_valid\":true"));
        assert!(json.contains("\"hostname_verified\":true"));
    }

    #[test]
    fn format_ip_san_renders_canonical_addresses() {
        // IPv4: dotted quad.
        assert_eq!(format_ip_san(&[192, 168, 0, 1]), "192.168.0.1");
        // IPv6 ::1 — must be zero-compressed, NOT 0000:0000:...:0001.
        let mut loopback = [0u8; 16];
        loopback[15] = 1;
        assert_eq!(format_ip_san(&loopback), "::1");
        // A fuller IPv6 address still round-trips through canonical form.
        // 2001:db8::1
        let mut addr = [0u8; 16];
        addr[0] = 0x20;
        addr[1] = 0x01;
        addr[2] = 0x0d;
        addr[3] = 0xb8;
        addr[15] = 1;
        assert_eq!(format_ip_san(&addr), "2001:db8::1");
    }

    fn sample_leaf() -> CertDetail {
        CertDetail {
            subject: "CN=example.com".to_string(),
            issuer: "CN=R3, O=Let's Encrypt".to_string(),
            valid_from: Utc::now(),
            valid_until: Utc::now(),
            serial_number: "abc123".to_string(),
            signature_algorithm: Some("SHA-256 with RSA".to_string()),
            is_ca: false,
            key_type: Some("RSA".to_string()),
            key_bits: Some(2048),
        }
    }

    #[test]
    fn derive_cert_warnings_clean_cert_has_none() {
        let w = derive_cert_warnings(&sample_leaf(), true, true, 90);
        assert!(w.is_empty(), "clean cert should have no warnings: {:?}", w);
    }

    #[test]
    fn derive_cert_warnings_flags_weak_rsa_key() {
        let mut leaf = sample_leaf();
        leaf.key_bits = Some(1024);
        let w = derive_cert_warnings(&leaf, true, true, 90);
        assert!(w.iter().any(|x| x.message.contains("RSA key size 1024")
            && x.severity == CertWarningSeverity::Critical));
    }

    #[test]
    fn derive_cert_warnings_flags_sha1_signature() {
        let mut leaf = sample_leaf();
        leaf.signature_algorithm = Some("SHA-1 with RSA".to_string());
        let w = derive_cert_warnings(&leaf, true, true, 90);
        assert!(w
            .iter()
            .any(|x| x.message.to_lowercase().contains("deprecated signature")));
    }

    #[test]
    fn derive_cert_warnings_flags_self_signed_expired_and_mismatch() {
        let mut leaf = sample_leaf();
        leaf.issuer = leaf.subject.clone();
        let w = derive_cert_warnings(&leaf, false, false, -3);
        assert!(w.iter().any(|x| x.message.contains("self-signed")));
        assert!(w.iter().any(|x| x.message.contains("expired 3 day(s) ago")));
        assert!(w.iter().any(|x| x.message.contains("does not match")));
    }

    #[test]
    fn derive_cert_warnings_flags_expiring_soon_as_warning() {
        let w = derive_cert_warnings(&sample_leaf(), true, true, 10);
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].severity, CertWarningSeverity::Warning);
        assert!(w[0].message.contains("expires in 10 day(s)"));
    }

    #[test]
    fn derive_cert_warnings_flags_ca_marked_leaf() {
        let mut leaf = sample_leaf();
        leaf.is_ca = true;
        let w = derive_cert_warnings(&leaf, true, true, 90);
        assert!(w.iter().any(|x| x.message.contains("marked as a CA")));
    }

    #[test]
    fn hostname_matches_pattern_exact_and_wildcard() {
        assert!(hostname_matches_pattern("example.com", "example.com"));
        assert!(hostname_matches_pattern("EXAMPLE.COM", "example.com"));
        // Single-label wildcard.
        assert!(hostname_matches_pattern("a.example.com", "*.example.com"));
        // Apex must not match a wildcard (RFC 6125).
        assert!(!hostname_matches_pattern("example.com", "*.example.com"));
        // Wildcard matches only one label.
        assert!(!hostname_matches_pattern(
            "a.b.example.com",
            "*.example.com"
        ));
        // Mismatched host.
        assert!(!hostname_matches_pattern("evil.test", "example.com"));
    }
}
