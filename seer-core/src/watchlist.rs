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
        dirs::home_dir().map(|h| h.join(".seer").join("watchlist.toml"))
    }

    /// Loads the watchlist from disk, returning an empty list on any failure.
    ///
    /// When the file exists but fails to parse, it is renamed to
    /// `<path>.corrupt` (preserving the user's data for recovery/forensics)
    /// and a warning is logged — previously the file was silently
    /// overwritten on the next save, dropping the user's watchlist.
    pub fn load() -> Self {
        let Some(path) = Self::path() else {
            return Self::default();
        };
        Self::load_from_path(&path)
    }

    /// Like [`Self::load`] but reads from an explicit path. Split out so
    /// tests can exercise the corrupt-file handling without depending on
    /// the real `~/.seer/watchlist.toml` location.
    pub(crate) fn load_from_path(path: &std::path::Path) -> Self {
        if !path.exists() {
            return Self::default();
        }
        match std::fs::read_to_string(path) {
            Ok(content) => match toml::from_str::<Watchlist>(&content) {
                Ok(w) => w,
                Err(e) => {
                    let backup = path.with_extension("corrupt");
                    if let Err(rename_err) = std::fs::rename(path, &backup) {
                        tracing::error!(
                            path = %path.display(),
                            error = %rename_err,
                            "failed to back up corrupt watchlist",
                        );
                    } else {
                        tracing::warn!(
                            path = %path.display(),
                            backup = %backup.display(),
                            error = %e,
                            "watchlist file corrupt; moved to backup",
                        );
                    }
                    Watchlist::default()
                }
            },
            Err(_) => Self::default(),
        }
    }

    /// Persists the watchlist to disk via write-and-rename so a crash mid-write
    /// cannot leave the file truncated (the next `load()` would see corrupt
    /// TOML and silently fall back to the default empty watchlist, losing
    /// the user's domains). Mirrors `LookupHistory::save`.
    ///
    /// The temp filename is suffixed with the current PID so two concurrent
    /// `seer` processes don't write to the same intermediate path and race
    /// each other's `rename`s.
    pub fn save(&self) -> Result<()> {
        let path = Self::path()
            .ok_or_else(|| SeerError::ConfigError("Cannot determine home directory".to_string()))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| SeerError::ConfigError(e.to_string()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }
        let content =
            toml::to_string_pretty(self).map_err(|e| SeerError::ConfigError(e.to_string()))?;
        let tmp_path = path.with_extension(format!("toml.{}.tmp", std::process::id()));
        std::fs::write(&tmp_path, content).map_err(|e| SeerError::ConfigError(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp_path, &path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp_path);
            SeerError::ConfigError(e.to_string())
        })?;
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
    // A result counts as critical if ANY of: SSL expires within 30 days,
    // domain registration expires within 30 days, or an issue string mentions
    // "invalid" / "failed". Flat OR of three predicates, evaluated
    // independently — the previous version nested the numeric checks inside
    // an `any()` over issue strings, which made the critical count depend
    // on iteration order over `issues` and could short-circuit incorrectly.
    let critical = results
        .iter()
        .filter(|r| {
            let bad_ssl = r.ssl_days_remaining.is_some_and(|d| d < 30);
            let bad_domain = r.domain_days_remaining.is_some_and(|d| d < 30);
            let bad_issue = r
                .issues
                .iter()
                .any(|i| i.contains("invalid") || i.contains("failed"));
            bad_ssl || bad_domain || bad_issue
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

    /// Creates a unique temporary file path for a load-from-disk test.
    fn unique_temp_watchlist_path(tag: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "seer-watchlist-test-{}-{}",
            tag,
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        dir.push("watchlist.toml");
        dir
    }

    #[test]
    fn load_from_path_returns_default_and_backs_up_corrupt_file() {
        let path = unique_temp_watchlist_path("corrupt");
        let backup = path.with_extension("corrupt");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&backup);

        // TOML parsers reject stray garbage on the value side of `=`.
        std::fs::write(&path, b"domains = not-an-array-\n").expect("seed corrupt watchlist file");

        let loaded = Watchlist::load_from_path(&path);
        assert!(
            loaded.domains.is_empty(),
            "corrupt watchlist must load as empty default"
        );
        assert!(
            !path.exists(),
            "original corrupt file should have been renamed away"
        );
        assert!(
            backup.exists(),
            "backup .corrupt file should exist at {}",
            backup.display()
        );

        let _ = std::fs::remove_file(&backup);
        if let Some(parent) = path.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }

    #[test]
    fn load_from_path_returns_default_when_missing() {
        let path = unique_temp_watchlist_path("missing");
        let _ = std::fs::remove_file(&path);

        let loaded = Watchlist::load_from_path(&path);
        assert!(loaded.domains.is_empty());

        if let Some(parent) = path.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
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
