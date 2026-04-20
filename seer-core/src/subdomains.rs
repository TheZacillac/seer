use std::collections::BTreeSet;

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use tracing::{debug, instrument};

use crate::error::{Result, SeerError};

/// Result of subdomain enumeration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainResult {
    pub domain: String,
    pub subdomains: Vec<String>,
    pub source: String,
    pub count: usize,
}

/// Enumerates subdomains using Certificate Transparency logs.
pub struct SubdomainEnumerator;

impl Default for SubdomainEnumerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared HTTP client for CT log queries (connection pooling).
///
/// Redirects are disabled: a compromised or hijacked crt.sh could otherwise
/// issue a 30x response that reqwest would follow by default, turning the
/// hardcoded CT-log fetch into an SSRF primitive. With `Policy::none()` any
/// redirect surfaces as an error instead of a silent re-target.
static HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("seer-domain-tool")
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Failed to create HTTP client")
});

impl SubdomainEnumerator {
    pub fn new() -> Self {
        Self
    }

    /// Discover subdomains for a domain using Certificate Transparency logs.
    ///
    /// Queries crt.sh, a public CT log aggregator, to find certificates issued
    /// for subdomains of the given domain. Returns a deduplicated, sorted list
    /// of discovered subdomains.
    ///
    /// # Arguments
    /// * `domain` - The domain name to enumerate subdomains for (e.g., "example.com")
    ///
    /// # Returns
    /// * `Ok(SubdomainResult)` - List of discovered subdomains
    /// * `Err(SeerError)` - If the CT log query fails
    #[instrument(skip(self), fields(domain = %domain))]
    pub async fn enumerate(&self, domain: &str) -> Result<SubdomainResult> {
        let domain = crate::validation::normalize_domain(domain)?;
        debug!(domain = %domain, "Enumerating subdomains via CT logs");

        // Query crt.sh (Certificate Transparency log aggregator)
        let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);

        // Maximum response size for CT log queries (10 MB).
        const MAX_CT_RESPONSE_SIZE: usize = 10 * 1024 * 1024;

        let response = HTTP_CLIENT
            .get(&url)
            .send()
            .await
            .map_err(|e| SeerError::HttpError(format!("CT log query failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(SeerError::HttpError(format!(
                "CT log returned status {}",
                response.status()
            )));
        }

        // Check Content-Length header before downloading
        if let Some(content_length) = response.content_length() {
            if content_length as usize > MAX_CT_RESPONSE_SIZE {
                return Err(SeerError::HttpError(format!(
                    "CT log response too large: {} bytes (limit: {} bytes)",
                    content_length, MAX_CT_RESPONSE_SIZE
                )));
            }
        }

        // Read body with size limit to guard against missing/lying Content-Length
        let bytes = response
            .bytes()
            .await
            .map_err(|e| SeerError::HttpError(format!("Failed to read CT log response: {}", e)))?;

        if bytes.len() > MAX_CT_RESPONSE_SIZE {
            return Err(SeerError::HttpError(format!(
                "CT log response too large: {} bytes (limit: {} bytes)",
                bytes.len(),
                MAX_CT_RESPONSE_SIZE
            )));
        }

        let entries: Vec<CtLogEntry> = serde_json::from_slice(&bytes)
            .map_err(|e| SeerError::HttpError(format!("Failed to parse CT log response: {}", e)))?;

        // Extract unique subdomain names
        let mut subdomains = BTreeSet::new();
        let suffix = format!(".{}", domain);

        for entry in &entries {
            // common_name and name_value may contain multiple domains separated by newlines
            for name in entry.common_name.split('\n') {
                let name = name.trim().to_lowercase();
                if (name.ends_with(&suffix) || name == domain) && !name.starts_with('*') {
                    subdomains.insert(name);
                }
            }
            if let Some(ref name_value) = entry.name_value {
                for name in name_value.split('\n') {
                    let name = name.trim().to_lowercase();
                    if (name.ends_with(&suffix) || name == domain) && !name.starts_with('*') {
                        subdomains.insert(name);
                    }
                }
            }
        }

        // Remove the base domain itself from the results
        subdomains.remove(&domain);

        // Filter subdomains through basic validation
        let subdomains: Vec<String> = subdomains
            .into_iter()
            .filter(|s| {
                // Must be ASCII alphanumeric, dots, hyphens, and wildcards
                let s = s.strip_prefix("*.").unwrap_or(s);
                !s.is_empty()
                    && s.len() <= 253
                    && s.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
                    && !s.contains("..")
                    && !s.starts_with('.')
                    && !s.starts_with('-')
            })
            .collect();
        let count = subdomains.len();

        Ok(SubdomainResult {
            domain,
            subdomains,
            source: "crt.sh (Certificate Transparency)".to_string(),
            count,
        })
    }
}

#[derive(Debug, Deserialize)]
struct CtLogEntry {
    #[serde(default)]
    common_name: String,
    #[serde(default)]
    name_value: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subdomain_result_serialization() {
        let result = SubdomainResult {
            domain: "example.com".to_string(),
            subdomains: vec![
                "api.example.com".to_string(),
                "mail.example.com".to_string(),
            ],
            source: "crt.sh (Certificate Transparency)".to_string(),
            count: 2,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("api.example.com"));
        assert!(json.contains("mail.example.com"));
        assert!(json.contains("crt.sh"));
    }

    #[test]
    fn test_subdomain_enumerator_default() {
        let enumerator = SubdomainEnumerator::default();
        // Just verify it can be constructed
        let _ = enumerator;
    }
}
