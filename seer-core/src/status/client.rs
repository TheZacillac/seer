use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

use chrono::Utc;
use native_tls::TlsConnector;
use once_cell::sync::Lazy;
use regex::Regex;
use reqwest::{Client, Url};
use tokio::net::TcpStream;
use tracing::{debug, instrument};

use super::types::{CertificateInfo, DnsResolution, DomainExpiration, StatusResponse};
use crate::caa::{self, CaaPolicy};
use crate::dns::{DnsResolver, RecordData, RecordType};
use crate::error::{Result, SeerError};
use crate::lookup::SmartLookup;
use crate::validation::{describe_reserved_ip, normalize_domain};

/// Default timeout for HTTP and TLS operations (10 seconds).
/// Balances responsiveness with allowing slow servers to respond.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REDIRECTS: usize = 5;

/// Pre-compiled regex for extracting HTML title.
static TITLE_REGEX: Lazy<Regex> = Lazy::new(|| {
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

    /// Sets the timeout for HTTP and TLS operations.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Checks the status of a domain (HTTP, SSL, expiration, DNS).
    #[instrument(skip(self), fields(domain = %domain))]
    pub async fn check(&self, domain: &str) -> Result<StatusResponse> {
        // Normalize domain format (doesn't require DNS resolution)
        let domain = normalize_domain(domain)?;
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

        // Apply domain expiration info
        match expiry_result {
            Ok(expiry_info) => response.domain_expiration = expiry_info,
            Err(e) => response.errors.push(super::types::StatusError {
                check: "expiration".to_string(),
                message: e.to_string(),
            }),
        }

        // Apply DNS resolution info
        match dns_result {
            Ok(dns_info) => response.dns_resolution = Some(dns_info),
            Err(e) => response.errors.push(super::types::StatusError {
                check: "dns".to_string(),
                message: e.to_string(),
            }),
        }

        Ok(response)
    }

    /// Fetches the HTTP status code and page title.
    ///
    /// Redirects are followed manually with IP validation at each hop.
    /// Resolved IPs are pinned on the HTTP client via `resolve_to_addrs` to
    /// prevent DNS rebinding attacks (TOCTOU between validation and connect).
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
    /// Redirect targets are validated for SSRF but the HTTP response body
    /// (page title) comes from an unauthenticated connection and should be
    /// treated as untrusted.
    async fn fetch_http_info(&self, domain: &str) -> Result<(u16, String, Option<String>)> {
        let mut url = Url::parse(&format!("https://{}", domain))
            .map_err(|e| SeerError::HttpError(format!("invalid URL: {}", e)))?;
        let mut visited = HashSet::new();

        for _ in 0..=MAX_REDIRECTS {
            let validated_addrs = validate_url_target(&url).await?;

            if !visited.insert(url.clone()) {
                return Err(SeerError::HttpError("redirect loop detected".to_string()));
            }

            // Build a per-hop client that pins the validated IPs so reqwest
            // cannot re-resolve the hostname to a different (potentially
            // private) address (DNS rebinding protection).
            let host = url
                .host_str()
                .ok_or_else(|| SeerError::HttpError("missing URL host".to_string()))?;
            let client = Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .user_agent(concat!("Seer/", env!("CARGO_PKG_VERSION")))
                .resolve_to_addrs(host, &validated_addrs)
                .build()
                .map_err(|e| SeerError::HttpError(format!("failed to build HTTP client: {}", e)))?;

            let response = client
                .get(url.clone())
                .timeout(self.timeout)
                .send()
                .await
                .map_err(|e| SeerError::HttpError(e.to_string()))?;

            if response.status().is_redirection() {
                let location = response.headers().get(reqwest::header::LOCATION);
                let location = location.and_then(|v| v.to_str().ok()).ok_or_else(|| {
                    SeerError::HttpError("redirect missing location header".to_string())
                })?;
                let next_url = url
                    .join(location)
                    .or_else(|_| Url::parse(location))
                    .map_err(|e| SeerError::HttpError(format!("invalid redirect URL: {}", e)))?;
                url = next_url;
                continue;
            }

            let status = response.status();
            let status_code = status.as_u16();
            let status_text = status.canonical_reason().unwrap_or("Unknown").to_string();

            // Only try to get title for successful HTML responses
            let title = if status.is_success() {
                let content_type = response
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");

                if content_type.contains("text/html") {
                    // Stream at most 64 KB for title extraction. Streaming
                    // (rather than `response.bytes().await`) prevents a
                    // malicious server from forcing us to buffer a huge
                    // body before the cap is applied.
                    const MAX_TITLE_BODY: usize = 64 * 1024;
                    use futures::StreamExt;
                    let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);
                    let mut stream = response.bytes_stream();
                    while let Some(chunk) = stream.next().await {
                        let chunk = chunk
                            .map_err(|e| SeerError::HttpError(format!("body chunk: {}", e)))?;
                        let remaining = MAX_TITLE_BODY.saturating_sub(buf.len());
                        if remaining == 0 {
                            break;
                        }
                        let take = remaining.min(chunk.len());
                        buf.extend_from_slice(&chunk[..take]);
                        if buf.len() >= MAX_TITLE_BODY {
                            break;
                        }
                    }
                    let body = String::from_utf8_lossy(&buf);
                    extract_title(&body)
                } else {
                    None
                }
            } else {
                None
            };

            return Ok((status_code, status_text, title));
        }

        Err(SeerError::HttpError("too many redirects".to_string()))
    }

    /// Fetches SSL certificate information using native-tls.
    ///
    /// # Security Note
    /// This connection uses `danger_accept_invalid_certs(true)` to inspect certificates
    /// even when invalid. Data retrieved (issuer, subject, dates) comes from an
    /// unauthenticated TLS connection and may have been tampered with by a MITM.
    async fn fetch_certificate_info(&self, domain: &str) -> Result<CertificateInfo> {
        // SSRF protection: resolve domain and check IPs before connecting
        let addr = format!("{}:443", domain);
        let socket_addrs: Vec<_> = tokio::net::lookup_host(&addr)
            .await
            .map_err(|e| SeerError::CertificateError(format!("DNS lookup failed: {}", e)))?
            .collect();

        if socket_addrs.is_empty() {
            return Err(SeerError::CertificateError(format!(
                "DNS lookup returned no addresses for {}",
                domain
            )));
        }

        for socket_addr in &socket_addrs {
            if let Some(reason) = describe_reserved_ip(&socket_addr.ip()) {
                return Err(SeerError::CertificateError(format!(
                    "cannot connect to {}: {} — {}",
                    domain,
                    socket_addr.ip(),
                    reason
                )));
            }
        }

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

    /// Fetches domain expiration info using WHOIS/RDAP.
    async fn fetch_domain_expiration(&self, domain: &str) -> Result<Option<DomainExpiration>> {
        match self.smart_lookup.lookup(domain).await {
            Ok(result) => {
                let (expiration_date, registrar) = result.expiration_info();

                if let Some(exp_date) = expiration_date {
                    let days_until_expiry = (exp_date - Utc::now()).num_days();
                    Ok(Some(DomainExpiration {
                        expiration_date: exp_date,
                        days_until_expiry,
                        registrar,
                    }))
                } else {
                    Ok(None)
                }
            }
            Err(_) => Ok(None), // Don't fail the whole status check if WHOIS fails
        }
    }

    /// Fetches DNS root record resolution (A, AAAA, CNAME, NS).
    async fn fetch_dns_resolution(&self, domain: &str) -> Result<DnsResolution> {
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

        Ok(DnsResolution {
            a_records,
            aaaa_records,
            cname_target,
            nameservers,
            resolves,
        })
    }
}

// Domain normalization and validation is now handled by the validation module

/// Extracts the title from HTML content.
fn extract_title(html: &str) -> Option<String> {
    TITLE_REGEX
        .captures(html)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Validates that a URL target is safe (no private/reserved IPs, no credentials,
/// supported scheme) and returns the resolved socket addresses.
///
/// The caller should pin these addresses on the HTTP client to prevent DNS
/// rebinding between validation and the actual connection.
async fn validate_url_target(url: &Url) -> Result<Vec<SocketAddr>> {
    let scheme = url.scheme();
    if scheme != "https" && scheme != "http" {
        return Err(SeerError::HttpError(format!(
            "unsupported URL scheme: {}",
            scheme
        )));
    }

    if !url.username().is_empty() || url.password().is_some() {
        return Err(SeerError::HttpError(
            "URL credentials are not allowed".to_string(),
        ));
    }

    let host = url
        .host_str()
        .ok_or_else(|| SeerError::HttpError("missing URL host".to_string()))?;
    let port = url.port_or_known_default().unwrap_or(443);

    // Only allow standard HTTP/HTTPS ports to prevent port scanning via redirects
    if port != 80 && port != 443 {
        return Err(SeerError::HttpError(format!(
            "non-standard port {} is not allowed in redirects",
            port
        )));
    }

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if let Some(reason) = describe_reserved_ip(&ip) {
            return Err(SeerError::HttpError(format!(
                "cannot connect to {}: {} — {}",
                host, ip, reason
            )));
        }
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    let addr = format!("{}:{}", host, port);
    let socket_addrs: Vec<_> = tokio::net::lookup_host(&addr)
        .await
        .map_err(|e| SeerError::HttpError(format!("DNS lookup failed: {}", e)))?
        .collect();

    if socket_addrs.is_empty() {
        return Err(SeerError::HttpError(format!(
            "DNS lookup returned no addresses for {}",
            host
        )));
    }

    for socket_addr in &socket_addrs {
        if let Some(reason) = describe_reserved_ip(&socket_addr.ip()) {
            return Err(SeerError::HttpError(format!(
                "cannot connect to {}: {} — {}",
                host,
                socket_addr.ip(),
                reason
            )));
        }
    }

    Ok(socket_addrs)
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
    let days_until_expiry = (valid_until - now).num_days();
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
/// Per RFC 6125, SAN dNSName is the authoritative source; CN is only checked
/// as a legacy fallback.
fn cert_matches_hostname(cert: &x509_parser::certificate::X509Certificate<'_>, host: &str) -> bool {
    use x509_parser::prelude::*;

    // SAN dNSName entries (preferred per RFC 6125)
    if let Ok(Some(san_ext)) = cert.tbs_certificate.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            if let GeneralName::DNSName(n) = name {
                if hostname_matches_pattern(host, n) {
                    return true;
                }
            }
        }
    }

    // CN fallback (legacy)
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
}
