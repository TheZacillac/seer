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
        dirs_next::home_dir().map(|h| h.join(".seer").join("history.json"))
    }

    /// Loads history from disk, returning an empty history on any failure.
    pub fn load() -> Self {
        let path = match Self::path() {
            Some(p) => p,
            None => return Self::default(),
        };
        if !path.exists() {
            return Self::default();
        }
        match std::fs::read_to_string(&path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Persists history to disk.
    pub fn save(&self) -> Result<()> {
        let path = Self::path()
            .ok_or_else(|| SeerError::ConfigError("Cannot determine home directory".to_string()))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| SeerError::ConfigError(e.to_string()))?;
        }
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| SeerError::ConfigError(e.to_string()))?;
        std::fs::write(&path, content).map_err(|e| SeerError::ConfigError(e.to_string()))?;
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
}
