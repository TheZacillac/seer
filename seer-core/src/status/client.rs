use std::time::Duration;

use chrono::Utc;
use native_tls::TlsConnector;
use regex::Regex;
use tokio::net::TcpStream;
use tracing::{debug, instrument};

use super::types::{CertificateInfo, DomainExpiration, StatusResponse};
use crate::error::{Result, SeerError};
use crate::lookup::SmartLookup;
use crate::validation::normalize_domain;

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
        // Validate domain format (individual checks handle connection failures gracefully)
        let domain = normalize_domain(domain)?;
        debug!("Checking status for domain: {}", domain);

        let mut response = StatusResponse::new(domain.clone());

        // Fetch HTTP status and title concurrently with SSL cert info
        let (http_result, cert_result, expiry_result) = tokio::join!(
            self.fetch_http_info(&domain),
            self.fetch_certificate_info(&domain),
            self.fetch_domain_expiration(&domain)
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

        Ok(response)
    }

    /// Fetch HTTP status code and page title
    async fn fetch_http_info(&self, domain: &str) -> Result<(u16, String, Option<String>)> {
        let url = format!("https://{}", domain);

        let client = reqwest::Client::builder()
            .timeout(self.timeout)
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .map_err(|e| SeerError::HttpError(e.to_string()))?;

        let response = client
            .get(&url)
            .header("User-Agent", "Seer/0.1.0")
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
        let connector = TlsConnector::builder()
            .danger_accept_invalid_certs(true) // We want to see the cert even if invalid
            .build()
            .map_err(|e| SeerError::CertificateError(e.to_string()))?;

        let connector = tokio_native_tls::TlsConnector::from(connector);

        let addr = format!("{}:443", domain);
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
}

// Domain normalization and validation is now handled by the validation module

/// Extract the title from HTML content
fn extract_title(html: &str) -> Option<String> {
    let re = Regex::new(r"(?i)<title[^>]*>([^<]+)</title>").ok()?;
    re.captures(html)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Parse certificate information from DER-encoded certificate
fn parse_certificate_der(der: &[u8], _domain: &str) -> Result<CertificateInfo> {
    // Validate the DER is a proper certificate
    let _ = native_tls::Certificate::from_der(der)
        .map_err(|e| SeerError::CertificateError(e.to_string()))?;

    // Parse the DER manually to extract dates and names
    // This is a simplified parser for X.509 certificates
    let (issuer, subject, valid_from, valid_until) = parse_x509_basic(der)?;

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

/// Basic X.509 certificate parser to extract issuer, subject, and validity dates
fn parse_x509_basic(
    der: &[u8],
) -> Result<(String, String, chrono::DateTime<Utc>, chrono::DateTime<Utc>)> {
    // This is a simplified parser that extracts common certificate fields
    // by looking for known ASN.1 patterns

    let issuer = extract_cn_from_der(der, true).unwrap_or_else(|| "Unknown Issuer".to_string());
    let subject = extract_cn_from_der(der, false).unwrap_or_else(|| "Unknown Subject".to_string());

    // Extract validity dates
    let (valid_from, valid_until) = extract_validity_from_der(der)?;

    Ok((issuer, subject, valid_from, valid_until))
}

/// Extract Common Name from DER certificate (simplified)
fn extract_cn_from_der(der: &[u8], is_issuer: bool) -> Option<String> {
    // Look for the OID 2.5.4.3 (Common Name) followed by the value
    // OID encoding: 55 04 03 (2.5.4.3)
    let cn_oid = [0x55, 0x04, 0x03];

    let mut found_first = false;
    for i in 0..der.len().saturating_sub(10) {
        if der[i..].starts_with(&cn_oid) {
            if is_issuer && found_first {
                // Skip to subject's CN
                continue;
            }
            if !is_issuer && !found_first {
                found_first = true;
                continue;
            }

            // The CN value follows the OID
            // Skip OID (3 bytes) + type tag (1 byte) + length (1 byte)
            let start = i + 5;
            if start < der.len() {
                let len = der[i + 4] as usize;
                let end = (start + len).min(der.len());
                if let Ok(s) = std::str::from_utf8(&der[start..end]) {
                    return Some(s.to_string());
                }
            }
        }
    }

    // Fallback: look for Organization name if CN not found
    let org_oid = [0x55, 0x04, 0x0a]; // 2.5.4.10 (Organization)
    for i in 0..der.len().saturating_sub(10) {
        if der[i..].starts_with(&org_oid) {
            let start = i + 5;
            if start < der.len() {
                let len = der[i + 4] as usize;
                let end = (start + len).min(der.len());
                if let Ok(s) = std::str::from_utf8(&der[start..end]) {
                    return Some(s.to_string());
                }
            }
            break;
        }
    }

    None
}

/// Extract validity dates from DER certificate
fn extract_validity_from_der(
    der: &[u8],
) -> Result<(chrono::DateTime<Utc>, chrono::DateTime<Utc>)> {
    // Look for UTCTime (tag 0x17) or GeneralizedTime (tag 0x18) patterns
    // Validity is typically a SEQUENCE containing two time values

    let mut times: Vec<chrono::DateTime<Utc>> = Vec::new();

    let mut i = 0;
    while i < der.len().saturating_sub(15) && times.len() < 2 {
        // UTCTime: tag 0x17, typically 13 bytes (YYMMDDHHMMSSZ)
        if der[i] == 0x17 && i + 1 < der.len() {
            let len = der[i + 1] as usize;
            if len >= 13 && i + 2 + len <= der.len() {
                if let Ok(s) = std::str::from_utf8(&der[i + 2..i + 2 + len]) {
                    if let Some(dt) = parse_utc_time(s) {
                        times.push(dt);
                    }
                }
            }
        }
        // GeneralizedTime: tag 0x18, typically 15 bytes (YYYYMMDDHHMMSSZ)
        else if der[i] == 0x18 && i + 1 < der.len() {
            let len = der[i + 1] as usize;
            if len >= 15 && i + 2 + len <= der.len() {
                if let Ok(s) = std::str::from_utf8(&der[i + 2..i + 2 + len]) {
                    if let Some(dt) = parse_generalized_time(s) {
                        times.push(dt);
                    }
                }
            }
        }
        i += 1;
    }

    if times.len() >= 2 {
        Ok((times[0], times[1]))
    } else {
        Err(SeerError::CertificateError(
            "Could not parse certificate validity dates".to_string(),
        ))
    }
}

/// Parse UTCTime format (YYMMDDHHMMSSZ)
fn parse_utc_time(s: &str) -> Option<chrono::DateTime<Utc>> {
    use chrono::NaiveDateTime;

    let s = s.trim_end_matches('Z');
    if s.len() < 12 {
        return None;
    }

    let year: i32 = s[0..2].parse().ok()?;
    let year = if year >= 50 { 1900 + year } else { 2000 + year };
    let month: u32 = s[2..4].parse().ok()?;
    let day: u32 = s[4..6].parse().ok()?;
    let hour: u32 = s[6..8].parse().ok()?;
    let min: u32 = s[8..10].parse().ok()?;
    let sec: u32 = s[10..12].parse().ok()?;

    NaiveDateTime::parse_from_str(
        &format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", year, month, day, hour, min, sec),
        "%Y-%m-%d %H:%M:%S",
    )
    .ok()
    .map(|dt| dt.and_utc())
}

/// Parse GeneralizedTime format (YYYYMMDDHHMMSSZ)
fn parse_generalized_time(s: &str) -> Option<chrono::DateTime<Utc>> {
    use chrono::NaiveDateTime;

    let s = s.trim_end_matches('Z');
    if s.len() < 14 {
        return None;
    }

    let year: i32 = s[0..4].parse().ok()?;
    let month: u32 = s[4..6].parse().ok()?;
    let day: u32 = s[6..8].parse().ok()?;
    let hour: u32 = s[8..10].parse().ok()?;
    let min: u32 = s[10..12].parse().ok()?;
    let sec: u32 = s[12..14].parse().ok()?;

    NaiveDateTime::parse_from_str(
        &format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", year, month, day, hour, min, sec),
        "%Y-%m-%d %H:%M:%S",
    )
    .ok()
    .map(|dt| dt.and_utc())
}
