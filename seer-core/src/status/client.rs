use std::time::Duration;

use chrono::Utc;
use native_tls::TlsConnector;
use once_cell::sync::Lazy;
use regex::Regex;
use tokio::net::TcpStream;
use tracing::{debug, instrument};

/// Pre-compiled regex for extracting HTML title
static TITLE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)<title[^>]*>([^<]+)</title>")
        .expect("Invalid regex for HTML title extraction")
});

use super::types::{CertificateInfo, DnsResolution, DomainExpiration, StatusResponse};
use crate::dns::{DnsResolver, RecordData, RecordType};
use crate::error::{Result, SeerError};
use crate::lookup::SmartLookup;
use crate::validation::{is_private_or_reserved_ip, normalize_domain};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Client for checking domain status (HTTP, SSL, expiration)
#[derive(Debug, Clone)]
pub struct StatusClient {
    timeout: Duration,
}

impl Default for StatusClient {
    fn default() -> Self {
        Self::new()
    }
}

impl StatusClient {
    /// Create a new StatusClient with default settings
    pub fn new() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Set the timeout for HTTP and TLS operations
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Check the status of a domain
    #[instrument(skip(self), fields(domain = %domain))]
    pub async fn check(&self, domain: &str) -> Result<StatusResponse> {
        // Normalize domain format (doesn't require DNS resolution)
        let domain = normalize_domain(domain)?;
        debug!("Checking status for domain: {}", domain);

        let mut response = StatusResponse::new(domain.clone());

        // Fetch HTTP status, SSL cert info, domain expiration, and DNS resolution concurrently
        // HTTP and SSL checks include SSRF protection internally
        let (http_result, cert_result, expiry_result, dns_result) = tokio::join!(
            self.fetch_http_info(&domain),
            self.fetch_certificate_info(&domain),
            self.fetch_domain_expiration(&domain),
            self.fetch_dns_resolution(&domain)
        );

        // Apply HTTP info
        if let Ok((status, status_text, title)) = http_result {
            response.http_status = Some(status);
            response.http_status_text = Some(status_text);
            response.title = title;
        }

        // Apply certificate info
        if let Ok(cert_info) = cert_result {
            response.certificate = Some(cert_info);
        }

        // Apply domain expiration info
        if let Ok(expiry_info) = expiry_result {
            response.domain_expiration = expiry_info;
        }

        // Apply DNS resolution info
        if let Ok(dns_info) = dns_result {
            response.dns_resolution = Some(dns_info);
        }

        Ok(response)
    }

    /// Fetch HTTP status code and page title
    async fn fetch_http_info(&self, domain: &str) -> Result<(u16, String, Option<String>)> {
        // SSRF protection: resolve domain and check IPs before connecting
        let addr = format!("{}:443", domain);
        let socket_addrs: Vec<_> = tokio::net::lookup_host(&addr)
            .await
            .map_err(|e| SeerError::HttpError(format!("DNS lookup failed: {}", e)))?
            .collect();

        for socket_addr in &socket_addrs {
            if is_private_or_reserved_ip(&socket_addr.ip()) {
                return Err(SeerError::HttpError(format!(
                    "Domain resolves to private/reserved IP: {}",
                    socket_addr.ip()
                )));
            }
        }

        let url = format!("https://{}", domain);

        let client = reqwest::Client::builder()
            .timeout(self.timeout)
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .map_err(|e| SeerError::HttpError(e.to_string()))?;

        let response = client
            .get(&url)
            .header("User-Agent", concat!("Seer/", env!("CARGO_PKG_VERSION")))
            .send()
            .await
            .map_err(|e| SeerError::HttpError(e.to_string()))?;

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
                let body = response
                    .text()
                    .await
                    .map_err(|e| SeerError::HttpError(e.to_string()))?;
                extract_title(&body)
            } else {
                None
            }
        } else {
            None
        };

        Ok((status_code, status_text, title))
    }

    /// Fetch SSL certificate information using native-tls
    async fn fetch_certificate_info(&self, domain: &str) -> Result<CertificateInfo> {
        // SSRF protection: resolve domain and check IPs before connecting
        let addr = format!("{}:443", domain);
        let socket_addrs: Vec<_> = tokio::net::lookup_host(&addr)
            .await
            .map_err(|e| SeerError::CertificateError(format!("DNS lookup failed: {}", e)))?
            .collect();

        for socket_addr in &socket_addrs {
            if is_private_or_reserved_ip(&socket_addr.ip()) {
                return Err(SeerError::CertificateError(format!(
                    "Domain resolves to private/reserved IP: {}",
                    socket_addr.ip()
                )));
            }
        }

        let connector = TlsConnector::builder()
            .danger_accept_invalid_certs(true) // We want to see the cert even if invalid
            .build()
            .map_err(|e| SeerError::CertificateError(e.to_string()))?;

        let connector = tokio_native_tls::TlsConnector::from(connector);

        let stream = tokio::time::timeout(self.timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| SeerError::Timeout(format!("Connection to {} timed out", domain)))?
            .map_err(|e| SeerError::CertificateError(e.to_string()))?;

        let tls_stream = tokio::time::timeout(self.timeout, connector.connect(domain, stream))
            .await
            .map_err(|_| SeerError::Timeout(format!("TLS handshake with {} timed out", domain)))?
            .map_err(|e| SeerError::CertificateError(e.to_string()))?;

        // Get the peer certificate
        let cert = tls_stream
            .get_ref()
            .peer_certificate()
            .map_err(|e| SeerError::CertificateError(e.to_string()))?
            .ok_or_else(|| SeerError::CertificateError("No certificate found".to_string()))?;

        // Parse certificate info
        let der = cert
            .to_der()
            .map_err(|e| SeerError::CertificateError(e.to_string()))?;

        parse_certificate_der(&der, domain)
    }

    /// Fetch domain expiration info using WHOIS/RDAP
    async fn fetch_domain_expiration(&self, domain: &str) -> Result<Option<DomainExpiration>> {
        let lookup = SmartLookup::new();

        match lookup.lookup(domain).await {
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

    /// Fetch DNS root record resolution (A, AAAA, CNAME, NS)
    async fn fetch_dns_resolution(&self, domain: &str) -> Result<DnsResolution> {
        let resolver = DnsResolver::new();

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
        let cname_target: Option<String> = cname_result
            .unwrap_or_default()
            .into_iter()
            .find_map(|r| {
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

/// Extract the title from HTML content
fn extract_title(html: &str) -> Option<String> {
    TITLE_REGEX
        .captures(html)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Parse certificate information from DER-encoded certificate using x509-parser
fn parse_certificate_der(der: &[u8], _domain: &str) -> Result<CertificateInfo> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| SeerError::CertificateError(format!("Failed to parse certificate: {}", e)))?;

    // Extract issuer - prefer CN, fall back to O (Organization)
    let issuer = extract_name_from_x509(cert.issuer())
        .unwrap_or_else(|| "Unknown Issuer".to_string());

    // Extract subject - prefer CN, fall back to O (Organization)
    let subject = extract_name_from_x509(cert.subject())
        .unwrap_or_else(|| "Unknown Subject".to_string());

    // Extract validity dates
    let valid_from = asn1_time_to_chrono(cert.validity().not_before)?;
    let valid_until = asn1_time_to_chrono(cert.validity().not_after)?;

    let now = Utc::now();
    let days_until_expiry = (valid_until - now).num_days();
    let is_valid = now >= valid_from && now <= valid_until;

    Ok(CertificateInfo {
        issuer,
        subject,
        valid_from,
        valid_until,
        days_until_expiry,
        is_valid,
    })
}

/// Extract Common Name or Organization from X.509 name
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

/// Extract string from ASN.1 attribute value, handling different encodings
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

/// Convert x509-parser ASN1Time to chrono DateTime
fn asn1_time_to_chrono(time: x509_parser::time::ASN1Time) -> Result<chrono::DateTime<Utc>> {
    let timestamp = time.timestamp();
    chrono::DateTime::from_timestamp(timestamp, 0)
        .ok_or_else(|| SeerError::CertificateError("Invalid certificate timestamp".to_string()))
}
