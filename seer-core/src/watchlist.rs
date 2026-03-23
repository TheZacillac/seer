//! Domain watchlist for monitoring expiration and health.
//!
//! Loads a list of domains from `~/.seer/watchlist.toml` and checks their
//! SSL certificates, domain expiration, and HTTP status.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Result, SeerError};
use crate::status::StatusClient;

/// Persistent list of domains to monitor.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Watchlist {
    #[serde(default)]
    pub domains: Vec<String>,
}

/// Status result for a single watched domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchResult {
    pub domain: String,
    pub ssl_days_remaining: Option<i64>,
    pub domain_days_remaining: Option<i64>,
    pub registrar: Option<String>,
    pub http_status: Option<u16>,
    pub issues: Vec<String>,
}

/// Aggregated report from checking all watched domains.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchReport {
    pub checked_at: DateTime<Utc>,
    pub results: Vec<WatchResult>,
    pub total: usize,
    pub warnings: usize,
    pub critical: usize,
}

impl Watchlist {
    /// Returns the path to the watchlist file (`~/.seer/watchlist.toml`).
    pub fn path() -> Option<PathBuf> {
        dirs_next::home_dir().map(|h| h.join(".seer").join("watchlist.toml"))
    }

    /// Loads the watchlist from disk, returning an empty list on any failure.
    pub fn load() -> Self {
        let Some(path) = Self::path() else {
            return Self::default();
        };
        if !path.exists() {
            return Self::default();
        }
        match std::fs::read_to_string(&path) {
            Ok(content) => toml::from_str(&content).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Persists the watchlist to disk.
    pub fn save(&self) -> Result<()> {
        let path = Self::path()
            .ok_or_else(|| SeerError::ConfigError("Cannot determine home directory".to_string()))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| SeerError::ConfigError(e.to_string()))?;
        }
        let content =
            toml::to_string_pretty(self).map_err(|e| SeerError::ConfigError(e.to_string()))?;
        std::fs::write(&path, content).map_err(|e| SeerError::ConfigError(e.to_string()))?;
        Ok(())
    }

    /// Adds a domain to the watchlist. Returns `Ok(true)` if the domain was newly added.
    pub fn add(&mut self, domain: &str) -> Result<bool> {
        let domain = crate::validation::normalize_domain(domain)?;
        if self.domains.contains(&domain) {
            return Ok(false);
        }
        self.domains.push(domain);
        self.domains.sort();
        Ok(true)
    }

    /// Removes a domain from the watchlist. Returns `true` if the domain was present.
    pub fn remove(&mut self, domain: &str) -> bool {
        let domain =
            crate::validation::normalize_domain(domain).unwrap_or_else(|_| domain.to_lowercase());
        let len_before = self.domains.len();
        self.domains.retain(|d| d != &domain);
        self.domains.len() < len_before
    }
}

/// Checks all given domains concurrently and produces a [`WatchReport`].
pub async fn check_watchlist(domains: &[String]) -> WatchReport {
    use futures::stream::{self, StreamExt};

    let client = StatusClient::new();

    let results: Vec<WatchResult> = stream::iter(domains)
        .map(|domain| {
            let client = &client;
            async move {
                let mut watch_result = WatchResult {
                    domain: domain.clone(),
                    ssl_days_remaining: None,
                    domain_days_remaining: None,
                    registrar: None,
                    http_status: None,
                    issues: vec![],
                };

                match client.check(domain).await {
                    Ok(status) => {
                        watch_result.http_status = status.http_status;

                        if let Some(ref cert) = status.certificate {
                            watch_result.ssl_days_remaining = Some(cert.days_until_expiry);
                            if cert.days_until_expiry < 30 {
                                watch_result.issues.push(format!(
                                    "SSL expires in {} days",
                                    cert.days_until_expiry
                                ));
                            }
                            if !cert.is_valid {
                                watch_result
                                    .issues
                                    .push("SSL certificate invalid".to_string());
                            }
                        }

                        if let Some(ref exp) = status.domain_expiration {
                            watch_result.domain_days_remaining = Some(exp.days_until_expiry);
                            watch_result.registrar = exp.registrar.clone();
                            if exp.days_until_expiry < 90 {
                                watch_result.issues.push(format!(
                                    "Domain expires in {} days",
                                    exp.days_until_expiry
                                ));
                            }
                        }

                        if let Some(status_code) = status.http_status {
                            if !(200..300).contains(&status_code) {
                                watch_result
                                    .issues
                                    .push(format!("HTTP status {}", status_code));
                            }
                        }
                    }
                    Err(e) => {
                        watch_result.issues.push(format!("Check failed: {}", e));
                    }
                }

                watch_result
            }
        })
        .buffer_unordered(10)
        .collect()
        .await;

    let total = results.len();
    let critical = results
        .iter()
        .filter(|r| {
            r.issues.iter().any(|i| {
                i.contains("invalid") || i.contains("failed") || {
                    // Check for expiry under 30 days
                    if let Some(ssl) = r.ssl_days_remaining {
                        if ssl < 30 {
                            return true;
                        }
                    }
                    if let Some(dom) = r.domain_days_remaining {
                        if dom < 30 {
                            return true;
                        }
                    }
                    false
                }
            })
        })
        .count();
    let warnings = results.iter().filter(|r| !r.issues.is_empty()).count();

    WatchReport {
        checked_at: Utc::now(),
        results,
        total,
        warnings,
        critical,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_watchlist_default() {
        let wl = Watchlist::default();
        assert!(wl.domains.is_empty());
    }

    #[test]
    fn test_watchlist_add_remove() {
        let mut wl = Watchlist::default();
        assert!(wl.add("example.com").unwrap());
        assert!(!wl.add("example.com").unwrap()); // duplicate
        assert_eq!(wl.domains.len(), 1);

        assert!(wl.add("test.org").unwrap());
        assert_eq!(wl.domains.len(), 2);
        // Should be sorted
        assert_eq!(wl.domains[0], "example.com");
        assert_eq!(wl.domains[1], "test.org");

        assert!(wl.remove("example.com"));
        assert!(!wl.remove("example.com")); // already removed
        assert_eq!(wl.domains.len(), 1);
    }

    #[test]
    fn test_watchlist_add_normalizes_case() {
        let mut wl = Watchlist::default();
        wl.add("EXAMPLE.COM").unwrap();
        assert_eq!(wl.domains[0], "example.com");
    }

    #[test]
    fn test_watchlist_serialization() {
        let mut wl = Watchlist::default();
        wl.add("a.com").unwrap();
        wl.add("b.org").unwrap();
        let toml_str = toml::to_string_pretty(&wl).unwrap();
        assert!(toml_str.contains("a.com"));
        assert!(toml_str.contains("b.org"));

        let parsed: Watchlist = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.domains.len(), 2);
    }

    #[test]
    fn test_watch_result_serialization() {
        let result = WatchResult {
            domain: "example.com".to_string(),
            ssl_days_remaining: Some(45),
            domain_days_remaining: Some(120),
            registrar: Some("Test Registrar".to_string()),
            http_status: Some(200),
            issues: vec![],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("example.com"));
        assert!(json.contains("45"));
    }
}
