//! Lookup history cache for storing past lookup results to disk.
//!
//! Results are persisted to `~/.seer/history.json` with a maximum of 50 entries
//! per domain to prevent unbounded growth.

use std::collections::BTreeMap;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Result, SeerError};
use crate::lookup::LookupResult;

/// A single cached lookup entry with timestamp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub domain: String,
    pub timestamp: DateTime<Utc>,
    pub result: LookupResult,
}

/// On-disk cache of past lookup results, keyed by domain.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LookupHistory {
    pub entries: BTreeMap<String, Vec<HistoryEntry>>,
}

/// Maximum number of history entries retained per domain.
const MAX_ENTRIES_PER_DOMAIN: usize = 50;

/// Maximum number of distinct domains retained. The per-domain cap above
/// bounds entries within a domain, but the number of distinct domain keys was
/// previously unbounded — long-lived/automated use could grow `history.json`
/// without limit. When exceeded, the domain whose most-recent entry is oldest
/// is evicted (LRU by most-recent activity). (issue #59)
const MAX_DOMAINS: usize = 1000;

/// Entries older than this are pruned. Bounds growth and the per-save rewrite
/// cost under long-lived use. (issue #59)
const MAX_ENTRY_AGE_DAYS: i64 = 365;

impl LookupHistory {
    /// Returns the path to the history file (`~/.seer/history.json`).
    pub fn path() -> Option<PathBuf> {
        dirs::home_dir().map(|h| h.join(".seer").join("history.json"))
    }

    /// Loads history from disk, returning an empty history on any failure.
    ///
    /// When the file exists but fails to parse, it is renamed to
    /// `<path>.corrupt` (preserving the user's data for recovery/forensics)
    /// and a warning is logged — previously the file was silently
    /// overwritten on the next save, dropping the user's history.
    pub fn load() -> Self {
        let Some(path) = Self::path() else {
            return Self::default();
        };
        Self::load_from_path(&path)
    }

    /// Like [`Self::load`] but reads from an explicit path. Split out so
    /// tests can exercise the corrupt-file handling without depending on
    /// the real `~/.seer/history.json` location.
    pub(crate) fn load_from_path(path: &std::path::Path) -> Self {
        if !path.exists() {
            return Self::default();
        }
        match std::fs::read_to_string(path) {
            Ok(content) => match serde_json::from_str::<LookupHistory>(&content) {
                Ok(h) => h,
                Err(e) => {
                    let backup = path.with_extension("corrupt");
                    if let Err(rename_err) = std::fs::rename(path, &backup) {
                        tracing::error!(
                            path = %path.display(),
                            error = %rename_err,
                            "failed to back up corrupt history",
                        );
                    } else {
                        tracing::warn!(
                            path = %path.display(),
                            backup = %backup.display(),
                            error = %e,
                            "history file corrupt; moved to backup",
                        );
                    }
                    LookupHistory::default()
                }
            },
            Err(_) => Self::default(),
        }
    }

    /// Persists history to disk via a write-and-rename so a kill mid-write
    /// can't leave the file truncated. `std::fs::write` is open(O_TRUNC)
    /// followed by write — if the process dies between the two, the next
    /// `load()` finds an empty/partial file, the corrupt-file branch fires,
    /// and the user's history is silently moved to `.corrupt`. Writing to
    /// a sibling temp file and `rename`-ing over the target is atomic on
    /// POSIX and survives that crash.
    ///
    /// # Concurrency
    ///
    /// The save itself is atomic (temp + rename) so a reader never sees a
    /// torn file. However the load → mutate → save cycle is **not** guarded by
    /// a cross-process lock: if two `seer` processes load, each appends, and
    /// each saves, the later `rename` wins and the earlier process's new entry
    /// is lost (last-writer-wins). This is data loss of at most a single
    /// concurrent entry — never corruption — and is bounded further by the
    /// growth caps above. A future cross-process advisory lock (or an
    /// append-only log) would close the remaining window; it is intentionally
    /// omitted here to avoid a new dependency for a low-frequency edge case.
    pub fn save(&self) -> Result<()> {
        let path = Self::path()
            .ok_or_else(|| SeerError::ConfigError("Cannot determine home directory".to_string()))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| SeerError::ConfigError(e.to_string()))?;
            // Lookup history is sensitive reconnaissance metadata; keep the
            // ~/.seer dir owner-only on Unix (best-effort defense in depth).
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| SeerError::ConfigError(e.to_string()))?;
        // Per-PID temp filename so two concurrent `seer` processes don't
        // race on the same intermediate path. Without this, process B's
        // `fs::write` could truncate A's `.tmp` after A finished writing
        // but before A's `rename` — A would then rename a truncated file
        // and silently lose history.
        let tmp_path = path.with_extension(format!("json.{}.tmp", std::process::id()));
        std::fs::write(&tmp_path, content).map_err(|e| SeerError::ConfigError(e.to_string()))?;
        // Owner-only before the rename so the published file is never briefly
        // world-readable.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp_path, &path).map_err(|e| {
            // Best-effort cleanup of the temp file so we don't litter on
            // failure. Swallow the cleanup error — the original rename
            // error is what we want to surface.
            let _ = std::fs::remove_file(&tmp_path);
            SeerError::ConfigError(e.to_string())
        })?;
        Ok(())
    }

    /// Records a lookup result for the given domain, trimming old entries if needed.
    pub fn record(&mut self, domain: &str, result: LookupResult) {
        let entry = HistoryEntry {
            domain: domain.to_lowercase(),
            timestamp: Utc::now(),
            result,
        };
        let entries = self.entries.entry(domain.to_lowercase()).or_default();
        entries.push(entry);
        // Keep at most MAX_ENTRIES_PER_DOMAIN entries
        if entries.len() > MAX_ENTRIES_PER_DOMAIN {
            let drain_count = entries.len() - MAX_ENTRIES_PER_DOMAIN;
            entries.drain(..drain_count);
        }
        self.prune();
    }

    /// Bounds total growth: drops entries older than [`MAX_ENTRY_AGE_DAYS`],
    /// removes any domain left with no entries, then evicts least-recently-active
    /// domains until at most [`MAX_DOMAINS`] remain (issue #59).
    fn prune(&mut self) {
        let cutoff = Utc::now() - chrono::Duration::days(MAX_ENTRY_AGE_DAYS);
        self.entries.retain(|_, v| {
            v.retain(|e| e.timestamp >= cutoff);
            !v.is_empty()
        });
        // Evict whole domains (least-recently-active first) until under the cap.
        // `record` adds one domain at a time, so this normally runs at most once.
        while self.entries.len() > MAX_DOMAINS {
            let Some(victim) = self
                .entries
                .iter()
                .min_by_key(|(_, v)| v.iter().map(|e| e.timestamp).max())
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            self.entries.remove(&victim);
        }
    }

    /// Returns all history entries for a domain, newest last.
    pub fn get(&self, domain: &str) -> Vec<&HistoryEntry> {
        self.entries
            .get(&domain.to_lowercase())
            .map(|entries| entries.iter().collect())
            .unwrap_or_default()
    }

    /// Clears all history entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::availability::AvailabilityResult;

    fn make_lookup_result(domain: &str) -> LookupResult {
        LookupResult::Available {
            data: Box::new(AvailabilityResult {
                domain: domain.to_string(),
                available: true,
                confidence: "high".to_string(),
                method: "test".to_string(),
                details: None,
            }),
            rdap_error: "test".to_string(),
            whois_error: "test".to_string(),
            whois_data: None,
        }
    }

    #[test]
    fn test_history_default() {
        let history = LookupHistory::default();
        assert!(history.entries.is_empty());
    }

    #[test]
    fn test_history_record_and_get() {
        let mut history = LookupHistory::default();
        history.record("example.com", make_lookup_result("example.com"));
        history.record("example.com", make_lookup_result("example.com"));
        history.record("test.org", make_lookup_result("test.org"));

        let entries = history.get("example.com");
        assert_eq!(entries.len(), 2);

        let entries = history.get("test.org");
        assert_eq!(entries.len(), 1);

        let entries = history.get("nonexistent.com");
        assert!(entries.is_empty());
    }

    #[test]
    fn test_history_case_insensitive() {
        let mut history = LookupHistory::default();
        history.record("EXAMPLE.COM", make_lookup_result("EXAMPLE.COM"));

        let entries = history.get("example.com");
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn test_history_max_entries() {
        let mut history = LookupHistory::default();
        for _ in 0..60 {
            history.record("example.com", make_lookup_result("example.com"));
        }
        let entries = history.get("example.com");
        assert_eq!(entries.len(), MAX_ENTRIES_PER_DOMAIN);
    }

    #[test]
    fn history_global_domain_cap_bounds_distinct_domains() {
        // History caps entries PER domain, but the number of distinct domains
        // was unbounded. A global cap must bound total domains (issue #59).
        let mut h = LookupHistory::default();
        for i in 0..(MAX_DOMAINS + 50) {
            h.record(&format!("d{i}.example"), make_lookup_result("x"));
        }
        assert!(
            h.entries.len() <= MAX_DOMAINS,
            "distinct domains must be capped at {MAX_DOMAINS}, got {}",
            h.entries.len()
        );
    }

    #[test]
    fn history_prunes_entries_older_than_max_age() {
        // Entries older than the max age are trimmed so the file can't grow
        // without bound under long-lived/automated use (issue #59).
        let mut h = LookupHistory::default();
        h.record("old.example", make_lookup_result("x"));
        // Backdate the entry beyond the retention window.
        h.entries.get_mut("old.example").unwrap()[0].timestamp =
            Utc::now() - chrono::Duration::days(MAX_ENTRY_AGE_DAYS + 10);
        // Any subsequent record triggers a prune.
        h.record("new.example", make_lookup_result("x"));
        assert!(
            h.get("old.example").is_empty(),
            "entry older than the retention window must be pruned"
        );
        assert!(!h.get("new.example").is_empty(), "fresh entry retained");
    }

    #[test]
    fn test_history_clear() {
        let mut history = LookupHistory::default();
        history.record("a.com", make_lookup_result("a.com"));
        history.record("b.com", make_lookup_result("b.com"));
        assert_eq!(history.entries.len(), 2);

        history.clear();
        assert!(history.entries.is_empty());
    }

    #[test]
    fn test_history_serialization_roundtrip() {
        let mut history = LookupHistory::default();
        history.record("example.com", make_lookup_result("example.com"));

        let json = serde_json::to_string(&history).unwrap();
        let parsed: LookupHistory = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.get("example.com").len(), 1);
    }

    /// Regression: history must round-trip a WHOIS-bearing result.
    ///
    /// `test_history_serialization_roundtrip` above only exercises the
    /// `Available` variant (`whois_data: None`), so it missed that
    /// `WhoisResponse.raw_response` (`skip_serializing`) failed to deserialize
    /// without `default`: every saved history containing a WHOIS lookup was
    /// rejected as "missing field `raw_response`" on the next load, moved to
    /// `.corrupt`, and silently dropped — so `seer history` and the TUI History
    /// lens were always empty after a real lookup.
    #[test]
    fn history_roundtrips_a_whois_bearing_result() {
        let whois = crate::whois::WhoisResponse::parse(
            "example.com",
            "whois.verisign-grs.com",
            "Domain Name: example.com\nRegistrar: Example Registrar\n",
        );
        let result = LookupResult::Whois {
            data: whois,
            rdap_error: None,
            rdap_fallback: None,
        };
        let mut history = LookupHistory::default();
        history.record("example.com", result);

        let json = serde_json::to_string(&history).expect("serialize");
        let parsed: LookupHistory = serde_json::from_str(&json)
            .expect("WHOIS-bearing history must deserialize (raw_response needs default)");
        assert_eq!(
            parsed.get("example.com").len(),
            1,
            "the WHOIS entry survives"
        );
    }

    /// Creates a unique temporary file path for a load-from-disk test.
    /// Returned path does not exist and the parent directory is created.
    /// The caller is responsible for cleaning up on drop (via the helper).
    fn unique_temp_history_path(tag: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("seer-history-test-{}-{}", tag, std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        dir.push("history.json");
        dir
    }

    #[test]
    fn load_from_path_returns_default_and_backs_up_corrupt_file() {
        let path = unique_temp_history_path("corrupt");
        let backup = path.with_extension("corrupt");

        // Clean any stragglers from a previous run.
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&backup);

        // Write an intentionally corrupt JSON file.
        std::fs::write(&path, b"{ this is not valid json ").expect("seed file");

        let loaded = LookupHistory::load_from_path(&path);
        assert!(
            loaded.entries.is_empty(),
            "corrupt file load must return default"
        );
        assert!(
            !path.exists(),
            "original file should have been renamed away"
        );
        assert!(
            backup.exists(),
            "backup .corrupt file should exist at {}",
            backup.display()
        );

        // Clean up.
        let _ = std::fs::remove_file(&backup);
        if let Some(parent) = path.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }

    #[test]
    fn load_from_path_returns_default_when_missing() {
        let path = unique_temp_history_path("missing");
        let _ = std::fs::remove_file(&path);

        let loaded = LookupHistory::load_from_path(&path);
        assert!(loaded.entries.is_empty());

        if let Some(parent) = path.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }
}
