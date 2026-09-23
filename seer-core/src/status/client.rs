//! Domain health checking (HTTP status, SSL, expiration, DNS resolution).
//!
//! Retry boundary (deliberate): checks here are single-attempt, unlike the
//! WHOIS/RDAP clients. This module's job is to OBSERVE a domain's health at a
//! point in time — automatic retries would mask exactly the flakiness a
//! health probe exists to surface. Callers that want tolerance to transient
//! failures (e.g. watch mode) own that policy at their layer.

use std::time::Duration;

use chrono::Utc;
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

static_regex! {
    /// Pre-compiled regex for extracting HTML title.
    TITLE_REGEX = r"(?i)<title[^>]*>([^<]+)</title>";
}

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

    /// Fetches the leaf certificate's details via the inspection handshake
    /// ([`crate::tls::inspect`]).
    ///
    /// # Security Note
    /// The handshake accepts any presented chain so invalid certificates can
    /// be inspected. Chain trust is not verified, so the data retrieved
    /// (issuer, subject, dates) may come from a MITM's own certificate.
    async fn fetch_certificate_info(&self, domain: &str) -> Result<CertificateInfo> {
        // SSRF protection: resolve and reject reserved IPs before connecting.
        // Use crate::net::resolve_public_host so we get the Hickory fallback
        // when the OS resolver is broken (corporate Macs, Tailscale split-DNS,
        // etc.) — the same path every other outbound-connect uses. The
        // handshake connects to exactly these addresses (no DNS rebinding).
        let socket_addrs = crate::net::resolve_public_host(domain, 443)
            .await
            .map_err(|e| SeerError::CertificateError(e.to_string()))?;

        let presented = crate::tls::inspect(
            domain,
            &socket_addrs,
            self.timeout,
            SeerError::CertificateError,
        )
        .await?;
        parse_certificate_der(&presented.leaf, domain)
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

        // Each query answers only its own type, so the A|AAAA accessor splits
        // the two lists exactly.
        let addresses = |result: Result<Vec<crate::dns::DnsRecord>>| -> Vec<String> {
            result
                .unwrap_or_default()
                .iter()
                .filter_map(|r| r.data.address().map(str::to_string))
                .collect()
        };
        let a_records = addresses(a_result);
        let aaaa_records = addresses(aaaa_result);

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

    let (valid_from, valid_until) = crate::tls::validity_window(&cert)
        .ok_or_else(|| SeerError::CertificateError("invalid certificate timestamp".to_string()))?;

    let now = Utc::now();
    let days_until_expiry = crate::dates::days_until(valid_until, now);
    let is_valid = now >= valid_from && now <= valid_until;

    // Hostname verification is performed manually because the inspection
    // handshake accepts any presented chain to allow cert inspection on
    // mildly-broken sites. Without this check any cert — even one issued for
    // an unrelated domain — would be accepted. The rule is shared with
    // `ssl.rs`, so `seer status` and `seer ssl` cannot disagree.
    let hostname_verified = crate::tls::cert_matches_host(&cert, domain);

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

/// Extracts the Common Name, falling back to the Organization.
fn extract_name_from_x509(name: &x509_parser::prelude::X509Name) -> Option<String> {
    use x509_parser::oid_registry;
    extract_oid_value(name, &oid_registry::OID_X509_COMMON_NAME)
        .or_else(|| extract_oid_value(name, &oid_registry::OID_X509_ORGANIZATION_NAME))
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

    /// A/AAAA/CNAME/NS extraction over the full resolve path, against the
    /// loopback DNS fixture.
    #[tokio::test]
    async fn dns_resolution_splits_address_families() {
        use crate::dns::test_support::{mock_dns_resolver_default, spawn_mock_dns, MockMode};

        let port = spawn_mock_dns(MockMode::Zone).await;
        let client = StatusClient {
            dns_resolver: mock_dns_resolver_default(port),
            ..StatusClient::new()
        };
        let dns = client.fetch_dns_resolution("seer.test").await;
        assert_eq!(dns.a_records, ["192.0.2.1", "192.0.2.2"]);
        assert_eq!(dns.aaaa_records, ["2001:db8::1"]);
        assert_eq!(dns.cname_target, None);
        assert_eq!(dns.nameservers, ["ns1.seer.test"]);
        assert!(dns.resolves);
    }

    /// The hostname verdict comes from the rule shared with `ssl.rs`
    /// (`tls::cert_matches_host`, which carries the RFC 6125 cases).
    #[test]
    fn certificate_hostname_uses_the_shared_rule() {
        use crate::tls::test_support::{cert, CN_VICTIM_SAN_IP, CN_VICTIM_SAN_OTHER};

        let verified = |b64, host| {
            parse_certificate_der(&cert(b64), host)
                .unwrap()
                .hostname_verified
        };
        assert!(!verified(CN_VICTIM_SAN_OTHER, "victim.example"));
        assert!(verified(CN_VICTIM_SAN_IP, "victim.example"));
        // An IP-literal host now matches an iPAddress SAN, as in `seer ssl`.
        assert!(verified(CN_VICTIM_SAN_IP, "203.0.113.7"));
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
