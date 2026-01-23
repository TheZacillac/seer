use std::collections::HashSet;
use std::sync::RwLock;
use std::time::Duration;
use once_cell::sync::Lazy;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, instrument, warn};

use super::parser::WhoisResponse;
use super::servers::{get_tld, get_whois_server};
use crate::error::{Result, SeerError};
use crate::validation::normalize_domain;

const WHOIS_PORT: u16 = 43;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE_SIZE: usize = 1024 * 1024; // 1MB
const MAX_REFERRAL_DEPTH: u8 = 3;
const IANA_WHOIS_SERVER: &str = "whois.iana.org";

/// Cache for dynamically discovered WHOIS servers
static DISCOVERED_SERVERS: Lazy<RwLock<std::collections::HashMap<String, String>>> =
    Lazy::new(|| RwLock::new(std::collections::HashMap::new()));

#[derive(Debug, Clone)]
pub struct WhoisClient {
    timeout: Duration,
}

impl Default for WhoisClient {
    fn default() -> Self {
        Self::new()
    }
}

impl WhoisClient {
    pub fn new() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    #[instrument(skip(self), fields(domain = %domain))]
    pub async fn lookup(&self, domain: &str) -> Result<WhoisResponse> {
        let domain = normalize_domain(domain)?;
        let tld = get_tld(&domain).ok_or_else(|| SeerError::InvalidDomain(domain.clone()))?;

        // Try static mapping first
        let whois_server = if let Some(server) = get_whois_server(tld) {
            server.to_string()
        } else {
            // Try cached discovered server
            if let Some(server) = get_cached_server(tld) {
                debug!(tld = %tld, server = %server, "Using cached WHOIS server");
                server
            } else {
                // Query IANA to discover the WHOIS server
                debug!(tld = %tld, "Querying IANA for WHOIS server");
                let server = self.discover_whois_server(tld).await?;
                cache_server(tld, &server);
                server
            }
        };

        let mut visited = HashSet::new();
        self.lookup_with_referrals(&domain, &whois_server, 0, &mut visited)
            .await
    }

    fn lookup_with_referrals<'a>(
        &'a self,
        domain: &'a str,
        whois_server: &'a str,
        depth: u8,
        visited: &'a mut HashSet<String>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<WhoisResponse>> + Send + 'a>>
    {
        Box::pin(async move {
            // Check for excessive referral depth
            if depth >= MAX_REFERRAL_DEPTH {
                warn!(depth = depth, server = %whois_server, "Max referral depth exceeded");
                return Err(SeerError::WhoisError(
                    "Maximum WHOIS referral depth exceeded".to_string(),
                ));
            }

            // Check for circular referrals
            let server_lower = whois_server.to_lowercase();
            if visited.contains(&server_lower) {
                warn!(server = %whois_server, "Circular WHOIS referral detected");
                return Err(SeerError::WhoisError(
                    "Circular WHOIS referral detected".to_string(),
                ));
            }
            visited.insert(server_lower);

            debug!(whois_server = %whois_server, depth = depth, "Querying WHOIS server");

            let raw_response = self.query_server(whois_server, domain).await?;
            let current_response = WhoisResponse::parse(domain, whois_server, &raw_response);

            // Check for referral to another WHOIS server
            if let Some(referral) = extract_referral(&raw_response) {
                if referral != whois_server && !visited.contains(&referral.to_lowercase()) {
                    debug!(referral = %referral, "Following referral");
                    match self
                        .lookup_with_referrals(domain, &referral, depth + 1, visited)
                        .await
                    {
                        Ok(referral_response) => {
                            // If referral indicates domain not found or has less data,
                            // prefer the current response which has registry data
                            if referral_response.is_available() || referral_response.indicates_not_found() {
                                debug!(
                                    referral = %referral,
                                    "Referral server indicates domain not found, using registry response"
                                );
                                return Ok(current_response);
                            }
                            return Ok(referral_response);
                        }
                        Err(e) => {
                            // If referral fails, use the current response if it has data
                            warn!(referral = %referral, error = %e, "Referral lookup failed, using registry response");
                            return Ok(current_response);
                        }
                    }
                }
            }

            Ok(current_response)
        })
    }

    pub async fn lookup_with_server(&self, domain: &str, server: &str) -> Result<WhoisResponse> {
        let domain = normalize_domain(domain)?;
        let raw_response = self.query_server(server, &domain).await?;
        Ok(WhoisResponse::parse(&domain, server, &raw_response))
    }

    async fn query_server(&self, server: &str, query: &str) -> Result<String> {
        let addr = format!("{}:{}", server, WHOIS_PORT);

        let mut stream = timeout(self.timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| SeerError::Timeout(format!("Connection to {} timed out", server)))?
            .map_err(|e| SeerError::WhoisError(format!("Failed to connect to {}: {}", server, e)))?;

        // Send query with CRLF
        let query_bytes = format!("{}\r\n", query);
        timeout(self.timeout, stream.write_all(query_bytes.as_bytes()))
            .await
            .map_err(|_| SeerError::Timeout("Write timed out".to_string()))?
            .map_err(|e| SeerError::WhoisError(format!("Failed to send query: {}", e)))?;

        // Read response
        let mut response = Vec::new();
        let mut buf = [0u8; 4096];

        loop {
            let read_result = timeout(self.timeout, stream.read(&mut buf)).await;

            match read_result {
                Ok(Ok(0)) => break, // EOF
                Ok(Ok(n)) => {
                    response.extend_from_slice(&buf[..n]);
                    if response.len() > MAX_RESPONSE_SIZE {
                        return Err(SeerError::WhoisError("Response too large".to_string()));
                    }
                }
                Ok(Err(e)) => {
                    return Err(SeerError::WhoisError(format!("Read error: {}", e)));
                }
                Err(_) => {
                    // Timeout on read - if we have data, return it
                    if !response.is_empty() {
                        break;
                    }
                    return Err(SeerError::Timeout("Read timed out".to_string()));
                }
            }
        }

        // Try UTF-8, fall back to Latin-1
        String::from_utf8(response.clone())
            .or_else(|_| Ok(response.iter().map(|&c| c as char).collect()))
            .map_err(|e: std::string::FromUtf8Error| {
                SeerError::WhoisError(format!("Failed to decode response: {}", e))
            })
    }

    /// Discovers the WHOIS server for a TLD by querying IANA
    async fn discover_whois_server(&self, tld: &str) -> Result<String> {
        let response = self.query_server(IANA_WHOIS_SERVER, tld).await?;

        // Parse IANA response to find the whois server
        // IANA response format includes a line like: "whois:        whois.nic.xyz"
        if let Some(server) = extract_iana_whois_server(&response) {
            return Ok(server);
        }

        // No WHOIS server found - check for registration URL in remarks
        if let Some(url) = extract_iana_registration_url(&response) {
            return Err(SeerError::WhoisServerNotFound(format!(
                "No WHOIS server for '.{}' - check whois directly via: {}",
                tld, url
            )));
        }

        Err(SeerError::WhoisServerNotFound(format!(
            "No WHOIS server found for TLD '{}'",
            tld
        )))
    }
}

/// Extracts the WHOIS server from an IANA response
fn extract_iana_whois_server(response: &str) -> Option<String> {
    for line in response.lines() {
        let line = line.trim();
        if line.to_lowercase().starts_with("whois:") {
            let server = line[6..].trim();
            if !server.is_empty() {
                return Some(server.to_lowercase());
            }
        }
    }
    None
}

/// Extracts the registration URL from an IANA response remarks field
fn extract_iana_registration_url(response: &str) -> Option<String> {
    for line in response.lines() {
        let line = line.trim();
        if line.to_lowercase().starts_with("remarks:") {
            let remarks = line[8..].trim();
            // Look for URL patterns in remarks
            if let Some(url_start) = remarks.find("http") {
                let url = &remarks[url_start..];
                // Extract URL (ends at whitespace or end of line)
                let url_end = url.find(char::is_whitespace).unwrap_or(url.len());
                return Some(url[..url_end].to_string());
            }
        }
    }
    None
}

/// Gets a cached WHOIS server for a TLD
fn get_cached_server(tld: &str) -> Option<String> {
    DISCOVERED_SERVERS
        .read()
        .ok()
        .and_then(|cache| cache.get(&tld.to_lowercase()).cloned())
}

/// Caches a discovered WHOIS server for a TLD
fn cache_server(tld: &str, server: &str) {
    if let Ok(mut cache) = DISCOVERED_SERVERS.write() {
        cache.insert(tld.to_lowercase(), server.to_string());
    }
}

fn extract_referral(response: &str) -> Option<String> {
    let patterns = [
        r"(?i)Registrar WHOIS Server:\s*(.+)",
        r"(?i)Whois Server:\s*(.+)",
        r"(?i)ReferralServer:\s*whois://(.+)",
    ];

    for pattern in &patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if let Some(caps) = re.captures(response) {
                if let Some(m) = caps.get(1) {
                    let server = m.as_str().trim().to_lowercase();
                    if !server.is_empty() && server.contains('.') {
                        return Some(server);
                    }
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_domain() {
        assert_eq!(normalize_domain("example.com").unwrap(), "example.com");
        assert_eq!(normalize_domain("EXAMPLE.COM").unwrap(), "example.com");
        assert_eq!(
            normalize_domain("https://www.example.com/path").unwrap(),
            "example.com"
        );
        assert!(normalize_domain("invalid").is_err());
    }
}
