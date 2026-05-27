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
    pub fn save(&self) -> Result<()> {
        let path = Self::path()
            .ok_or_else(|| SeerError::ConfigError("Cannot determine home directory".to_string()))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| SeerError::ConfigError(e.to_string()))?;
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
