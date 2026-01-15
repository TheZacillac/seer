use std::collections::HashSet;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, instrument, warn};

use super::parser::WhoisResponse;
use super::servers::{get_tld, get_whois_server};
use crate::error::{Result, SeerError};

const WHOIS_PORT: u16 = 43;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE_SIZE: usize = 1024 * 1024; // 1MB
const MAX_REFERRAL_DEPTH: u8 = 3;

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

        let whois_server = get_whois_server(tld)
            .ok_or_else(|| SeerError::WhoisServerNotFound(tld.to_string()))?;

        let mut visited = HashSet::new();
        self.lookup_with_referrals(&domain, whois_server, 0, &mut visited)
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

            // Check for referral to another WHOIS server
            if let Some(referral) = extract_referral(&raw_response) {
                if referral != whois_server && !visited.contains(&referral.to_lowercase()) {
                    debug!(referral = %referral, "Following referral");
                    return self
                        .lookup_with_referrals(domain, &referral, depth + 1, visited)
                        .await;
                }
            }

            Ok(WhoisResponse::parse(domain, whois_server, &raw_response))
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
}

fn normalize_domain(domain: &str) -> Result<String> {
    let domain = domain.trim().to_lowercase();

    // Remove protocol if present
    let domain = domain
        .strip_prefix("http://")
        .or_else(|| domain.strip_prefix("https://"))
        .unwrap_or(&domain);

    // Remove trailing slash and path
    let domain = domain.split('/').next().unwrap_or(&domain);

    // Remove www. prefix
    let domain = domain.strip_prefix("www.").unwrap_or(domain);

    // Validate domain format
    if domain.is_empty() || !domain.contains('.') {
        return Err(SeerError::InvalidDomain(domain.to_string()));
    }

    // Basic validation - alphanumeric, hyphens, and dots
    let valid = domain.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    if !valid {
        return Err(SeerError::InvalidDomain(domain.to_string()));
    }

    Ok(domain.to_string())
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
