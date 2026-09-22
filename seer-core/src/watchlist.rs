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
        crate::fsutil::load_or_back_up(path, "watchlist", |content| {
            toml::from_str::<Watchlist>(content).map_err(|e| e.to_string())
        })
    }

    /// Persists the watchlist to disk via write-and-rename so a crash mid-write
    /// cannot leave the file truncated (the next `load()` would see corrupt
    /// TOML and silently fall back to the default empty watchlist, losing
    /// the user's domains). Mirrors `LookupHistory::save`.
    ///
    /// The temp filename is unique per call (PID + process-wide counter, see
    /// `crate::fsutil`) so concurrent saves — whether from two `seer`
    /// processes or two tasks in one process — never write to the same
    /// intermediate path and race each other's `rename`s.
    ///
    /// # Concurrency
    ///
    /// As with [`crate::history::LookupHistory::save`], the write is atomic but
    /// the load → add/remove → save cycle is not cross-process locked: two
    /// concurrent writers can lose one side's add/remove (last-writer-wins). No
    /// corruption occurs. A cross-process advisory lock would close the window;
    /// it is omitted to avoid a new dependency for a low-frequency edge case.
    pub fn save(&self) -> Result<()> {
        let path = Self::path()
            .ok_or_else(|| SeerError::ConfigError("Cannot determine home directory".to_string()))?;
        self.save_to_path(&path)
    }

    /// Like [`Self::save`] but writes to an explicit path. Split out so tests
    /// can exercise the atomic-save path without touching `~/.seer`.
    pub(crate) fn save_to_path(&self, path: &std::path::Path) -> Result<()> {
        let content =
            toml::to_string_pretty(self).map_err(|e| SeerError::ConfigError(e.to_string()))?;
        crate::fsutil::write_atomic_owner_only(path, &content, "toml")
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

/// SSL or domain-registration expiry within this many days is *critical*.
const EXPIRY_CRITICAL_DAYS: i64 = 30;
/// Domain-registration expiry within this many days surfaces an informational
/// (warning-band) issue even before it becomes critical. SSL uses only the
/// critical band. Defined as named constants so the issue-push thresholds and
/// the critical tally are a single source of truth (issue #57).
const DOMAIN_EXPIRY_WARN_DAYS: i64 = 90;
/// Exact issue strings this module emits, so the critical predicate can match
/// them structurally rather than scanning free text for "invalid"/"failed".
const SSL_INVALID_ISSUE: &str = "SSL certificate invalid";
const CHECK_FAILED_PREFIX: &str = "Check failed:";

/// Returns true if a checked result is *critical* (vs merely a warning): an SSL
/// or registration expiry within [`EXPIRY_CRITICAL_DAYS`], an invalid SSL
/// certificate, or a failed check. Uses the numeric day fields and the exact
/// issue markers this module emits — not a locale/text-fragile substring scan
/// for "invalid"/"failed" (issue #57).
fn result_is_critical(r: &WatchResult) -> bool {
    let bad_ssl = r
        .ssl_days_remaining
        .is_some_and(|d| d < EXPIRY_CRITICAL_DAYS);
    let bad_domain = r
        .domain_days_remaining
        .is_some_and(|d| d < EXPIRY_CRITICAL_DAYS);
    // Match the exact markers this module emits, not arbitrary free text, so a
    // benign issue line that happens to contain "failed"/"invalid" can't be
    // miscounted as critical.
    let bad_issue = r
        .issues
        .iter()
        .any(|i| i == SSL_INVALID_ISSUE || i.starts_with(CHECK_FAILED_PREFIX));
    bad_ssl || bad_domain || bad_issue
}

/// Default number of domains checked at once by [`check_watchlist`].
const DEFAULT_WATCH_CONCURRENCY: usize = 10;

/// Turns one domain's status check into a [`WatchResult`]. Pure, so every
/// issue rule is unit-testable without the network.
///
/// `StatusClient::check` only returns `Err` for an invalid domain: a site that
/// is down or no longer resolves comes back `Ok` with its failures recorded in
/// `StatusResponse::errors`. Those must surface here, or a dead domain reads
/// as healthy and `watch --fail-on` exits 0.
fn assess(domain: String, outcome: Result<crate::status::StatusResponse>) -> WatchResult {
    let mut watch_result = WatchResult {
        domain,
        ssl_days_remaining: None,
        domain_days_remaining: None,
        registrar: None,
        http_status: None,
        issues: vec![],
    };

    let status = match outcome {
        Ok(status) => status,
        Err(e) => {
            watch_result
                .issues
                .push(format!("{} {}", CHECK_FAILED_PREFIX, e));
            return watch_result;
        }
    };

    watch_result.http_status = status.http_status;

    // A domain that no longer resolves (lapsed delegation, hijack, deleted
    // records) is the most severe thing a watch can see.
    if status.dns_resolution.as_ref().is_some_and(|d| !d.resolves) {
        watch_result.issues.push(format!(
            "{} dns: domain does not resolve",
            CHECK_FAILED_PREFIX
        ));
    }
    for err in &status.errors {
        match err.check.as_str() {
            "dns" => watch_result
                .issues
                .push(format!("{} dns: {}", CHECK_FAILED_PREFIX, err.message)),
            // Unreachable web/TLS endpoints are reported, but as warnings:
            // a watched domain may legitimately serve no website (mail-only).
            "http" => watch_result
                .issues
                .push(format!("HTTP check failed: {}", err.message)),
            "ssl" => watch_result
                .issues
                .push(format!("SSL check failed: {}", err.message)),
            _ => {}
        }
    }

    if let Some(ref cert) = status.certificate {
        watch_result.ssl_days_remaining = Some(cert.days_until_expiry);
        if cert.days_until_expiry < EXPIRY_CRITICAL_DAYS {
            watch_result
                .issues
                .push(format!("SSL expires in {} days", cert.days_until_expiry));
        }
        if !cert.is_valid {
            watch_result.issues.push(SSL_INVALID_ISSUE.to_string());
        }
    }

    if let Some(ref exp) = status.domain_expiration {
        watch_result.domain_days_remaining = Some(exp.days_until_expiry);
        watch_result.registrar = exp.registrar.clone();
        if exp.days_until_expiry < DOMAIN_EXPIRY_WARN_DAYS {
            watch_result
                .issues
                .push(format!("Domain expires in {} days", exp.days_until_expiry));
        }
    }

    if let Some(status_code) = status.http_status {
        if !(200..300).contains(&status_code) {
            watch_result
                .issues
                .push(format!("HTTP status {}", status_code));
        }
    }

    watch_result
}

/// Checks all given domains concurrently and produces a [`WatchReport`],
/// using default timeouts and concurrency.
///
/// Prefer [`check_watchlist_with_config`] from a front-end, so the user's
/// `~/.seer/config.toml` timeouts and bulk concurrency apply.
pub async fn check_watchlist(domains: &[String]) -> WatchReport {
    check_watchlist_with(domains, StatusClient::new(), DEFAULT_WATCH_CONCURRENCY).await
}

/// Like [`check_watchlist`], honoring the config file's per-protocol
/// timeouts (via [`StatusClient::from_config`]) and `bulk.concurrency`.
pub async fn check_watchlist_with_config(
    domains: &[String],
    config: &crate::config::SeerConfig,
) -> WatchReport {
    check_watchlist_with(
        domains,
        StatusClient::from_config(config),
        config.bulk.concurrency,
    )
    .await
}

/// Checks all given domains with `client`, at most `concurrency` at a time.
pub async fn check_watchlist_with(
    domains: &[String],
    client: StatusClient,
    concurrency: usize,
) -> WatchReport {
    use futures::stream::{self, StreamExt};

    // Each per-domain future owns its `client` (via `Arc`) and `domain`
    // (owned `String`) so the `buffer_unordered` futures are `Send + 'static`
    // and the whole `check_watchlist` future can be used from `tokio::spawn`
    // (e.g. the TUI). Borrowing `&client`/`&String` here makes the closure fail
    // the higher-ranked `FnOnce` bound `tokio::spawn` requires.
    let client = std::sync::Arc::new(client);

    let results: Vec<WatchResult> = stream::iter(domains.iter().cloned())
        .map(|domain| {
            let client = client.clone();
            async move {
                let outcome = client.check(&domain).await;
                assess(domain, outcome)
            }
        })
        .buffer_unordered(concurrency.max(1))
        .collect()
        .await;

    let total = results.len();
    // Critical vs warning use explicit, shared bands (see `result_is_critical`
    // and the EXPIRY_* constants) so the tally lines up with the human-visible
    // issue lines: a registration expiry in the 30..90-day warning band shows
    // an issue and counts as a warning, while < 30 days counts as critical.
    let critical = results.iter().filter(|r| result_is_critical(r)).count();
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

    fn status_with(
        dns: Option<crate::status::DnsResolution>,
        errors: &[(&str, &str)],
    ) -> crate::status::StatusResponse {
        let mut status = crate::status::StatusResponse::new("example.com".to_string());
        status.dns_resolution = dns;
        status.errors = errors
            .iter()
            .map(|(check, message)| crate::status::StatusError {
                check: check.to_string(),
                message: message.to_string(),
            })
            .collect();
        status
    }

    fn resolution(resolves: bool) -> crate::status::DnsResolution {
        crate::status::DnsResolution {
            a_records: vec![],
            aaaa_records: vec![],
            cname_target: None,
            nameservers: vec![],
            resolves,
        }
    }

    #[test]
    fn a_domain_that_stopped_resolving_is_critical() {
        // Previously every sub-check failure was swallowed into
        // `StatusResponse::errors`, so this read as a healthy green domain.
        let r = assess(
            "example.com".to_string(),
            Ok(status_with(Some(resolution(false)), &[])),
        );
        assert!(result_is_critical(&r), "issues: {:?}", r.issues);
        let r = assess(
            "example.com".to_string(),
            Ok(status_with(None, &[("dns", "DNS lookup timed out")])),
        );
        assert!(result_is_critical(&r), "issues: {:?}", r.issues);
    }

    #[test]
    fn unreachable_web_endpoints_are_warnings() {
        let r = assess(
            "example.com".to_string(),
            Ok(status_with(
                Some(resolution(true)),
                &[("http", "connection refused"), ("ssl", "handshake failed")],
            )),
        );
        assert_eq!(r.issues.len(), 2, "issues: {:?}", r.issues);
        assert!(!r.issues.is_empty());
        // Mail-only domains legitimately serve no website: warn, not critical.
        assert!(!result_is_critical(&r));
    }

    #[test]
    fn a_healthy_domain_has_no_issues() {
        let r = assess(
            "example.com".to_string(),
            Ok(status_with(Some(resolution(true)), &[])),
        );
        assert!(r.issues.is_empty(), "issues: {:?}", r.issues);
    }

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
    fn concurrent_saves_do_not_corrupt_the_file() {
        // Two same-process writers saving to the same target concurrently:
        // with a shared (PID-only) temp path one writer truncates the other's
        // finished bytes and the loser's rename fails (or publishes a torn
        // file). With per-call temp paths every save succeeds and the last
        // rename wins with a complete file. Mirrors the history.rs test.
        let path = unique_temp_watchlist_path("concurrent");
        let _ = std::fs::remove_file(&path);

        let mut a = Watchlist::default();
        a.add("a.example").unwrap();
        let mut b = Watchlist::default();
        for i in 0..100 {
            b.add(&format!("b{i}.example")).unwrap();
        }

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let spawn_saver =
            |wl: Watchlist, path: PathBuf, barrier: std::sync::Arc<std::sync::Barrier>| {
                std::thread::spawn(move || {
                    for _ in 0..50 {
                        barrier.wait();
                        wl.save_to_path(&path).expect("concurrent save failed");
                    }
                })
            };
        let ta = spawn_saver(a, path.clone(), barrier.clone());
        let tb = spawn_saver(b, path.clone(), barrier);
        ta.join().expect("thread A panicked");
        tb.join().expect("thread B panicked");

        // Whichever writer won the last rename, the file must be complete.
        let content = std::fs::read_to_string(&path).expect("saved file exists");
        toml::from_str::<Watchlist>(&content)
            .expect("concurrently saved watchlist must parse (no torn rename)");

        if let Some(parent) = path.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }

    fn result_with(ssl: Option<i64>, domain: Option<i64>, issues: &[&str]) -> WatchResult {
        WatchResult {
            domain: "x.test".to_string(),
            ssl_days_remaining: ssl,
            domain_days_remaining: domain,
            registrar: None,
            http_status: Some(200),
            issues: issues.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn critical_uses_explicit_expiry_bands() {
        // Registration expiry in the 30..90-day warning band is NOT critical,
        // even though it surfaces an issue line; < 30 days IS critical (#57).
        assert!(!result_is_critical(&result_with(
            None,
            Some(60),
            &["Domain expires in 60 days"]
        )));
        assert!(result_is_critical(&result_with(
            None,
            Some(20),
            &["Domain expires in 20 days"]
        )));
        // SSL critical band and invalid cert.
        assert!(result_is_critical(&result_with(Some(10), None, &[])));
        assert!(result_is_critical(&result_with(
            Some(200),
            None,
            &["SSL certificate invalid"]
        )));
        // Failed check is critical.
        assert!(result_is_critical(&result_with(
            None,
            None,
            &["Check failed: connection refused"]
        )));
    }

    #[test]
    fn critical_predicate_is_structured_not_freetext() {
        // A healthy domain whose issue text merely contains the word "failed"
        // (or "invalid") must NOT be counted critical — the old predicate
        // scanned free text and was locale/wording-fragile (issue #57).
        let r = result_with(
            Some(200),
            Some(200),
            &["Note: a prior validation failed last week"],
        );
        assert!(
            !result_is_critical(&r),
            "free-text 'failed' must not trip the critical predicate"
        );
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
