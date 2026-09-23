//! Domain health checking (HTTP status, SSL, expiration, DNS resolution).
//!
//! Retry boundary (deliberate): checks here are single-attempt, unlike the
//! WHOIS/RDAP clients. This module's job is to OBSERVE a domain's health at a
//! point in time — automatic retries would mask exactly the flakiness a
//! health probe exists to surface. Callers that want tolerance to transient
//! failures (e.g. watch mode) own that policy at their layer.

use std::time::Duration;

use chrono::Utc;
use native_tls::TlsConnector;
use regex::Regex;
use std::sync::LazyLock;
use tokio::net::TcpStream;
use tracing::{debug, instrument};

use super::types::{CertificateInfo, DnsResolution, DomainExpiration, StatusResponse};
use crate::caa::{self, CaaPolicy};
use crate::dns::{DnsResolver, RecordData, RecordType};
use crate::error::{Result, SeerError};
use crate::http::GuardedFetcher;
use crate::lookup::SmartLookup;
use crate::validation::normalize_host;

/// Default timeout for HTTP and TLS operations (10 seconds).
/// Balances responsiveness with allowing slow servers to respond.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Pre-compiled regex for extracting HTML title.
static TITLE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)<title[^>]*>([^<]+)</title>").expect("Invalid regex for HTML title extraction")
});

/// Client for checking domain status (HTTP, SSL, expiration)
#[derive(Debug, Clone)]
pub struct StatusClient {
    timeout: Duration,
    /// Cached DNS resolver reused across status checks.
    dns_resolver: DnsResolver,
    /// Reusable SmartLookup for domain expiration checks.
    smart_lookup: SmartLookup,
}

impl Default for StatusClient {
    fn default() -> Self {
        Self::new()
    }
}

impl StatusClient {
    /// Creates a new StatusClient with default settings.
    pub fn new() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            dns_resolver: DnsResolver::new(),
            smart_lookup: SmartLookup::new(),
        }
    }

    /// Builds a client honoring `~/.seer/config.toml` settings.
    ///
    /// Reads `timeouts.http_secs` (clamped to 1–120s by
    /// [`crate::config::SeerConfig::load`]) for the HTTP/TLS probes, plus
    /// `timeouts.dns_secs`, `timeouts.whois_secs`, and `timeouts.rdap_secs`
    /// for the internal DNS resolver and expiration lookup — matching the
    /// [`crate::availability::AvailabilityChecker::from_config`] precedent of
    /// per-protocol timeouts on every sub-client.
    pub fn from_config(config: &crate::config::SeerConfig) -> Self {
        Self {
            timeout: config.http_timeout(),
            dns_resolver: DnsResolver::from_config(config),
            smart_lookup: SmartLookup::from_config(config),
        }
    }

    /// Sets the timeout for HTTP and TLS operations.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Checks the status of a domain (HTTP, SSL, expiration, DNS).
    #[instrument(skip(self), fields(domain = %domain))]
    pub async fn check(&self, domain: &str) -> Result<StatusResponse> {
        // Normalize domain format (doesn't require DNS resolution). The exact
        // host is kept — `www.example.com` can serve a different site and
        // certificate than the apex; the expiration lookup reduces it to the
        // registration on its own.
        let domain = normalize_host(domain)?;
        debug!("Checking status for domain: {}", domain);

        let mut response = StatusResponse::new(domain.clone());

        // Fetch HTTP status, SSL cert info, domain expiration, DNS
        // resolution, and CAA policy concurrently. HTTP and SSL checks
        // include SSRF protection internally; CAA never fails the request
        // (a resolver error yields an empty policy).
        let (http_result, cert_result, expiry_result, dns_result, caa_policy) = tokio::join!(
            self.fetch_http_info(&domain),
            self.fetch_certificate_info(&domain),
            self.fetch_domain_expiration(&domain),
            self.fetch_dns_resolution(&domain),
            caa::lookup_caa(&self.dns_resolver, &domain),
        );

        // Apply HTTP info
        match http_result {
            Ok((status, status_text, title)) => {
                response.http_status = Some(status);
                response.http_status_text = Some(status_text);
                response.title = title;
            }
            Err(e) => response.errors.push(super::types::StatusError {
                check: "http".to_string(),
                message: e.to_string(),
            }),
        }

        // Apply certificate info and tag the CAA policy with the issuer
        // comparison if a cert was retrieved.
        let mut caa_policy: CaaPolicy = caa_policy;
        match cert_result {
            Ok(cert_info) => {
                caa_policy.issuer_match =
                    Some(caa::classify_issuer(&cert_info.issuer, &caa_policy));
                response.certificate = Some(cert_info);
            }
            Err(e) => response.errors.push(super::types::StatusError {
                check: "ssl".to_string(),
                message: e.to_string(),
            }),
        }
        response.caa = Some(caa_policy);

        // Expiration and DNS never add a sub-check error: a failed lookup
        // folds into "unknown" (no expiration / no records).
        response.domain_expiration = expiry_result;
        response.dns_resolution = Some(dns_result);

        Ok(response)
    }

    /// Fetches the HTTP status code and page title of `https://{domain}/`.
    ///
    /// Goes through [`GuardedFetcher`], the SSRF-guarded GET shared with
    /// `headers`/`takeover`: redirects are followed manually with the guard
    /// re-run and the validated IPs pinned at every hop (DNS-rebinding
    /// defense), and the body read is capped and timeout-bounded.
    ///
    /// # Security Note
    /// This path uses reqwest's default (validating) TLS configuration — a
    /// bad certificate surfaces as a typed `SeerError::HttpError` and the
    /// status check reports it as a failed "http" sub-check instead of
    /// silently returning attacker-controlled body content as "successful".
    /// The SSL inspection path in `ssl.rs` (and `fetch_certificate_info`
    /// below) intentionally relaxes verification because inspecting an
    /// invalid cert is the whole point of that code; this path MUST NOT.
    ///
    /// The page title is remote content and should be treated as untrusted.
    async fn fetch_http_info(&self, domain: &str) -> Result<(u16, String, Option<String>)> {
        let fetcher = GuardedFetcher::new().with_timeout(self.timeout);
        http_info(&fetcher, &format!("https://{domain}/")).await
    }

    /// Fetches SSL certificate information using native-tls.
    ///
    /// # Security Note
    /// This connection uses `danger_accept_invalid_certs(true)` to inspect certificates
    /// even when invalid. Data retrieved (issuer, subject, dates) comes from an
    /// unauthenticated TLS connection and may have been tampered with by a MITM.
    async fn fetch_certificate_info(&self, domain: &str) -> Result<CertificateInfo> {
        // SSRF protection: resolve and reject reserved IPs before connecting.
        // Use crate::net::resolve_public_host so we get the Hickory fallback
        // when the OS resolver is broken (corporate Macs, Tailscale split-DNS,
        // etc.) — the same path every other outbound-connect uses.
        let socket_addrs = crate::net::resolve_public_host(domain, 443)
            .await
            .map_err(|e| SeerError::CertificateError(e.to_string()))?;

        let connector = TlsConnector::builder()
            .danger_accept_invalid_certs(true) // We want to see the cert even if invalid
            .build()
            .map_err(|e| SeerError::CertificateError(e.to_string()))?;

        let connector = tokio_native_tls::TlsConnector::from(connector);

        // Connect directly to the validated socket address to prevent DNS
        // rebinding (TOCTOU) between validation and connect.
        let stream =
            tokio::time::timeout(self.timeout, TcpStream::connect(socket_addrs.as_slice()))
                .await
                .map_err(|_| SeerError::Timeout(format!("connection to {} timed out", domain)))?
                .map_err(|e| SeerError::CertificateError(e.to_string()))?;

        // Use the domain as SNI hostname for the TLS handshake.
        let tls_stream = tokio::time::timeout(self.timeout, connector.connect(domain, stream))
            .await
            .map_err(|_| SeerError::Timeout(format!("TLS handshake with {} timed out", domain)))?
            .map_err(|e| SeerError::CertificateError(e.to_string()))?;

        // Get the peer certificate
        let cert = tls_stream
            .get_ref()
            .peer_certificate()
            .map_err(|e| SeerError::CertificateError(e.to_string()))?
            .ok_or_else(|| SeerError::CertificateError("no certificate found".to_string()))?;

        // Parse certificate info
        let der = cert
            .to_der()
            .map_err(|e| SeerError::CertificateError(e.to_string()))?;

        parse_certificate_der(&der, domain)
    }

    /// Fetches domain expiration info using WHOIS/RDAP; `None` when the lookup
    /// fails (which must not fail the whole status check) or has no date.
    async fn fetch_domain_expiration(&self, domain: &str) -> Option<DomainExpiration> {
        let result = self.smart_lookup.lookup(domain).await.ok()?;
        let (expiration_date, registrar) = result.expiration_info();
        let expiration_date = expiration_date?;
        Some(DomainExpiration {
            expiration_date,
            days_until_expiry: crate::dates::days_until(expiration_date, Utc::now()),
            registrar,
        })
    }

    /// Fetches DNS root record resolution (A, AAAA, CNAME, NS). A failed
    /// query contributes no records rather than an error.
    async fn fetch_dns_resolution(&self, domain: &str) -> DnsResolution {
        let resolver = &self.dns_resolver;

        // Query all record types concurrently
        let (a_result, aaaa_result, cname_result, ns_result) = tokio::join!(
            resolver.resolve(domain, RecordType::A, None),
            resolver.resolve(domain, RecordType::AAAA, None),
            resolver.resolve(domain, RecordType::CNAME, None),
            resolver.resolve(domain, RecordType::NS, None)
        );

        // Extract A records
        let a_records: Vec<String> = a_result
            .unwrap_or_default()
            .into_iter()
            .filter_map(|r| {
                if let RecordData::A { address } = r.data {
                    Some(address)
                } else {
                    None
                }
            })
            .collect();

        // Extract AAAA records
        let aaaa_records: Vec<String> = aaaa_result
            .unwrap_or_default()
            .into_iter()
            .filter_map(|r| {
                if let RecordData::AAAA { address } = r.data {
                    Some(address)
                } else {
                    None
                }
            })
            .collect();

        // Extract CNAME target (trim trailing dot)
        let cname_target: Option<String> =
            cname_result.unwrap_or_default().into_iter().find_map(|r| {
                if let RecordData::CNAME { target } = r.data {
                    Some(target.trim_end_matches('.').to_string())
                } else {
                    None
                }
            });

        // Extract NS records (trim trailing dots)
        let nameservers: Vec<String> = ns_result
            .unwrap_or_default()
            .into_iter()
            .filter_map(|r| {
                if let RecordData::NS { nameserver } = r.data {
                    Some(nameserver.trim_end_matches('.').to_string())
                } else {
                    None
                }
            })
            .collect();

        // Domain resolves if it has A/AAAA records or a CNAME
        let resolves = !a_records.is_empty() || !aaaa_records.is_empty() || cname_target.is_some();

        DnsResolution {
            a_records,
            aaaa_records,
            cname_target,
            nameservers,
            resolves,
        }
    }
}

/// GETs `url` and returns `(status code, reason phrase, page title)`.
///
/// The body is read only for a 2xx `text/html` response, where it feeds the
/// title; any other final response reports its status straight from the
/// headers, so a body that stalls or errors cannot fail the sub-check.
async fn http_info(fetcher: &GuardedFetcher, url: &str) -> Result<(u16, String, Option<String>)> {
    let (response, _) = fetcher.send(url).await?;
    let status = response.status();
    let is_html = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.contains("text/html"));
    let title = if status.is_success() && is_html {
        extract_title(&fetcher.read_body(response).await?)
    } else {
        None
    };
    let reason = status.canonical_reason().unwrap_or("Unknown").to_string();
    Ok((status.as_u16(), reason, title))
}

/// Extracts the title from HTML content.
///
/// Strips ASCII control characters (NUL, ESC, etc.) at extraction time so
/// the value is safe for every downstream sink — JSON (which would happily
/// encode `\u0000` and pass it to an LLM via the MCP server), the human
/// formatter (which sanitises again at render time), and the bulk-CSV
/// writer. Without the strip, a crafted `<title>Foo\x00Bar</title>` reaches
/// the LLM context window.
fn extract_title(html: &str) -> Option<String> {
    TITLE_REGEX
        .captures(html)
        .and_then(|caps| caps.get(1))
        .map(|m| {
            // Strip ALL control characters. A raw `\n` or `\t` inside a
            // `<title>` element is meaningless HTML whitespace (browsers
            // collapse it to a single space); preserving them would
            // produce multi-line JSON field values and break CSV column
            // alignment downstream.
            m.as_str()
                .chars()
                .filter(|c| !c.is_control())
                .collect::<String>()
                .trim()
                .to_string()
        })
        .filter(|s| !s.is_empty())
}

/// Parses certificate information from DER-encoded certificate using x509-parser.
fn parse_certificate_der(der: &[u8], domain: &str) -> Result<CertificateInfo> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| SeerError::CertificateError(format!("failed to parse certificate: {}", e)))?;

    // Extract issuer — combine CN and O when both exist. Intermediate CA
    // certs commonly have a short CN like "E7" or "R3"; without the
    // organization the human-readable name is unhelpful and the CAA
    // comparison cannot match the CA's well-known name.
    let issuer = format_issuer_name(cert.issuer()).unwrap_or_else(|| "Unknown Issuer".to_string());

    // Extract subject - prefer CN, fall back to O (Organization)
    let subject =
        extract_name_from_x509(cert.subject()).unwrap_or_else(|| "Unknown Subject".to_string());

    // Extract validity dates
    let valid_from = asn1_time_to_chrono(cert.validity().not_before)?;
    let valid_until = asn1_time_to_chrono(cert.validity().not_after)?;

    let now = Utc::now();
    let days_until_expiry = crate::dates::days_until(valid_until, now);
    let is_valid = now >= valid_from && now <= valid_until;

    // Hostname verification is performed manually because the TLS connector
    // was configured with danger_accept_invalid_certs(true) to allow cert
    // inspection on mildly-broken sites. Without this check any cert — even
    // one issued for an unrelated domain — would be accepted.
    let hostname_verified = cert_matches_hostname(&cert, domain);

    Ok(CertificateInfo {
        issuer,
        subject,
        valid_from,
        valid_until,
        days_until_expiry,
        is_valid,
        hostname_verified,
    })
}

/// Matches a hostname against a certificate name pattern.
///
/// Supports exact matches (case-insensitive) and single-label wildcards
/// per RFC 6125 — `*.example.com` matches `a.example.com` but not
/// `example.com` or `a.b.example.com`.
fn hostname_matches_pattern(host: &str, pattern: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let pattern = pattern.to_ascii_lowercase();
    if let Some(rest) = pattern.strip_prefix("*.") {
        // Wildcard: must match exactly one label, and must contain a dot
        let Some(dot) = host.find('.') else {
            return false;
        };
        let host_rest = &host[dot + 1..];
        host_rest == rest
    } else {
        host == pattern
    }
}

/// Checks whether a certificate's SAN dNSName entries (or CN as fallback)
/// match the queried hostname.
///
/// Per RFC 6125 §6.4.4, SAN dNSName is the authoritative source and the CN
/// is consulted ONLY when the certificate carries no dNSName SAN at all —
/// otherwise a cert whose SANs cover other hosts but whose CN happens to
/// name this one would falsely verify. Mirrors `ssl.rs`, so `seer status`
/// and `seer ssl` cannot disagree about the same certificate.
fn cert_matches_hostname(cert: &x509_parser::certificate::X509Certificate<'_>, host: &str) -> bool {
    use x509_parser::prelude::*;

    // SAN dNSName entries (preferred per RFC 6125)
    let mut has_dns_san = false;
    if let Ok(Some(san_ext)) = cert.tbs_certificate.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            if let GeneralName::DNSName(n) = name {
                has_dns_san = true;
                if hostname_matches_pattern(host, n) {
                    return true;
                }
            }
        }
    }
    if has_dns_san {
        return false;
    }

    // CN fallback (legacy) — only for certificates without dNSName SANs.
    for cn in cert.subject().iter_common_name() {
        if let Ok(s) = cn.as_str() {
            if hostname_matches_pattern(host, s) {
                return true;
            }
        }
    }

    false
}

/// Builds a human-readable issuer label, combining Organization and Common
/// Name when both exist. Used for the cert's issuer rather than the bare
/// CN so users see "Let's Encrypt (E7)" rather than "E7".
fn format_issuer_name(name: &x509_parser::prelude::X509Name) -> Option<String> {
    use x509_parser::oid_registry;
    let cn = extract_oid_value(name, &oid_registry::OID_X509_COMMON_NAME);
    let org = extract_oid_value(name, &oid_registry::OID_X509_ORGANIZATION_NAME);
    match (org, cn) {
        (Some(o), Some(c)) if o != c => Some(format!("{} ({})", o, c)),
        (Some(o), _) => Some(o),
        (None, Some(c)) => Some(c),
        (None, None) => None,
    }
}

/// Pulls the first attribute matching `oid` out of an X.509 name.
fn extract_oid_value(
    name: &x509_parser::prelude::X509Name,
    oid: &x509_parser::der_parser::oid::Oid<'static>,
) -> Option<String> {
    for rdn in name.iter() {
        for attr in rdn.iter() {
            if attr.attr_type() == oid {
                if let Some(s) = extract_attr_string(attr.attr_value()) {
                    return Some(s);
                }
            }
        }
    }
    None
}

/// Extracts the Common Name or Organization from an X.509 name.
fn extract_name_from_x509(name: &x509_parser::prelude::X509Name) -> Option<String> {
    use x509_parser::prelude::*;

    // Try Common Name first (OID 2.5.4.3)
    for rdn in name.iter() {
        for attr in rdn.iter() {
            if attr.attr_type() == &oid_registry::OID_X509_COMMON_NAME {
                if let Some(s) = extract_attr_string(attr.attr_value()) {
                    return Some(s);
                }
            }
        }
    }

    // Fall back to Organization (OID 2.5.4.10)
    for rdn in name.iter() {
        for attr in rdn.iter() {
            if attr.attr_type() == &oid_registry::OID_X509_ORGANIZATION_NAME {
                if let Some(s) = extract_attr_string(attr.attr_value()) {
                    return Some(s);
                }
            }
        }
    }

    None
}

/// Extracts a string from an ASN.1 attribute value, handling different encodings.
fn extract_attr_string(value: &x509_parser::der_parser::asn1_rs::Any) -> Option<String> {
    // Try as_str() first (handles PrintableString, IA5String, etc.)
    if let Ok(s) = value.as_str() {
        return Some(s.to_string());
    }

    // Try UTF8String explicitly
    if let Ok(utf8) = value.as_utf8string() {
        return Some(utf8.string().to_string());
    }

    // Try raw bytes as UTF-8
    if let Ok(s) = std::str::from_utf8(value.data) {
        return Some(s.to_string());
    }

    None
}

/// Converts an x509-parser ASN1Time to a chrono DateTime.
fn asn1_time_to_chrono(time: x509_parser::time::ASN1Time) -> Result<chrono::DateTime<Utc>> {
    let timestamp = time.timestamp();
    chrono::DateTime::from_timestamp(timestamp, 0)
        .ok_or_else(|| SeerError::CertificateError("invalid certificate timestamp".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_config_applies_http_timeout() {
        let mut config = crate::config::SeerConfig::default();
        config.timeouts.http_secs = 55;
        let client = StatusClient::from_config(&config);
        assert_eq!(client.timeout, Duration::from_secs(55));
    }

    #[test]
    fn hostname_matches_pattern_exact() {
        assert!(hostname_matches_pattern("example.com", "example.com"));
        assert!(hostname_matches_pattern("EXAMPLE.COM", "example.com"));
        assert!(hostname_matches_pattern("example.com", "EXAMPLE.COM"));
        assert!(!hostname_matches_pattern("evil.com", "example.com"));
        assert!(!hostname_matches_pattern("example.com", "evil.com"));
    }

    #[test]
    fn hostname_matches_pattern_wildcard() {
        assert!(hostname_matches_pattern("a.example.com", "*.example.com"));
        assert!(hostname_matches_pattern("A.EXAMPLE.COM", "*.example.com"));
        // Apex must not match wildcard (RFC 6125)
        assert!(!hostname_matches_pattern("example.com", "*.example.com"));
        // Wildcard only covers a single label
        assert!(!hostname_matches_pattern(
            "a.b.example.com",
            "*.example.com"
        ));
        assert!(!hostname_matches_pattern("b.other.com", "*.example.com"));
    }

    #[test]
    fn hostname_matches_pattern_wildcard_requires_dot() {
        // A bare host with no dot cannot match a wildcard pattern
        assert!(!hostname_matches_pattern("localhost", "*.example.com"));
    }

    /// Self-signed P-256 cert: CN=victim.example, SAN=DNS:other.example.
    const CERT_CN_VICTIM_SAN_OTHER: &str = "MIIBoDCCAUegAwIBAgIUdStRrtt0ycIGUV74700+xRrFcJ0wCgYIKoZIzj0EAwIwGTEXMBUGA1UEAwwOdmljdGltLmV4YW1wbGUwHhcNMjYwOTIyMTcwMzA4WhcNMzYwOTE5MTcwMzA4WjAZMRcwFQYDVQQDDA52aWN0aW0uZXhhbXBsZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJPCvcjh/aeA2qb1taFaBCxI/ue4srU8jUNjjvQW9IKMqdsUluEGjW7fcYSa8w/79MWZ/naVmgZKQs/eSXCU/AWjbTBrMB0GA1UdDgQWBBSG5So71BSr3DZri66kQaPKzWbjNDAfBgNVHSMEGDAWgBSG5So71BSr3DZri66kQaPKzWbjNDAPBgNVHRMBAf8EBTADAQH/MBgGA1UdEQQRMA+CDW90aGVyLmV4YW1wbGUwCgYIKoZIzj0EAwIDRwAwRAIgEnAMNQMytsawL+CuV7N9z/ftwHVzdFunp+oG7QjIou4CIHsf9vyIXQUPs5iBrhprcRiwyuZQWy0mZyRdavp4Kgbh";
    /// Self-signed P-256 cert: CN=victim.example, no SAN extension.
    const CERT_CN_VICTIM_NO_SAN: &str = "MIIBhzCCAS2gAwIBAgIUeGkzmcc68l5FOH5NOBgS3Ybcg4gwCgYIKoZIzj0EAwIwGTEXMBUGA1UEAwwOdmljdGltLmV4YW1wbGUwHhcNMjYwOTIyMTcwMzA4WhcNMzYwOTE5MTcwMzA4WjAZMRcwFQYDVQQDDA52aWN0aW0uZXhhbXBsZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABC6rgHiHBhd3vxpcRHm7VH2YgCybc0Bl4ewS1lMjdtM5+R+pX/STje36olq5IDx9AEJfxtdRMvtiWp9jfb5vdB6jUzBRMB0GA1UdDgQWBBS5JfZqENT0bfsAazBNLiAVb77UdzAfBgNVHSMEGDAWgBS5JfZqENT0bfsAazBNLiAVb77UdzAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQD5zMnpSHSVr3vSmZM0vh0R345Rg3wc+OgeZwmsDxDJQQIgBNJ0CS0bpChCAQls0oFZUPD6u7iX7uBOD/QRPZ2Ub1k=";

    fn cert_info(b64: &str, host: &str) -> CertificateInfo {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let der = STANDARD.decode(b64).unwrap();
        parse_certificate_der(&der, host).unwrap()
    }

    #[test]
    fn cn_is_ignored_when_the_cert_has_dns_sans() {
        // RFC 6125 §6.4.4: a matching CN must not rescue a cert whose SANs
        // name other hosts. `seer ssl` already applied this; status did not.
        assert!(!cert_info(CERT_CN_VICTIM_SAN_OTHER, "victim.example").hostname_verified);
        assert!(cert_info(CERT_CN_VICTIM_SAN_OTHER, "other.example").hostname_verified);
        // Legacy cert with no SAN at all still falls back to the CN.
        assert!(cert_info(CERT_CN_VICTIM_NO_SAN, "victim.example").hostname_verified);
        assert!(!cert_info(CERT_CN_VICTIM_NO_SAN, "other.example").hostname_verified);
    }

    // --- http_info (hermetic: wiremock on 127.0.0.1 via the test seam) ----

    #[tokio::test]
    async fn http_info_reads_title_only_for_html_success() {
        use wiremock::matchers::path;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(path("/"))
            .respond_with(ResponseTemplate::new(301).insert_header("location", "/home"))
            .mount(&server)
            .await;
        Mock::given(path("/home"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                "<html><title> Home\u{0}Page </title></html>",
                "text/html; charset=utf-8",
            ))
            .mount(&server)
            .await;
        Mock::given(path("/json"))
            .respond_with(ResponseTemplate::new(200).set_body_raw("<title>x</title>", "text/plain"))
            .mount(&server)
            .await;

        let fetcher = GuardedFetcher::new().allowing_private_hosts();
        let info = http_info(&fetcher, &format!("{}/", server.uri()))
            .await
            .unwrap();
        assert_eq!(info, (200, "OK".to_string(), Some("HomePage".to_string())));

        let info = http_info(&fetcher, &format!("{}/json", server.uri()))
            .await
            .unwrap();
        assert_eq!(info, (200, "OK".to_string(), None));

        // Non-2xx reports the status without a title.
        let info = http_info(&fetcher, &format!("{}/missing", server.uri()))
            .await
            .unwrap();
        assert_eq!(info, (404, "Not Found".to_string(), None));
    }
}
