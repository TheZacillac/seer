//! Subdomain baseline persistence and diffing.
//!
//! Stores per-domain snapshots of a CT-log subdomain enumeration under
//! `~/.seer/subdomain_baselines.json` and diffs a fresh enumeration against
//! the stored set, surfacing the change that matters for security monitoring:
//! **newly appeared names**. A certificate issued for a subdomain you didn't
//! create is a classic early indicator of phishing infrastructure or a
//! compromised DNS zone.
//!
//! # Why only additions are "material"
//!
//! CT logs are append-mostly: certificates keep showing up in aggregator
//! results long after they expire, so a name genuinely leaving the result set
//! is rare. In practice a "removed" name usually means the aggregator
//! truncated or flaked (crt.sh 429s, certspotter pagination limits), not that
//! anything changed on the domain. Removals are therefore reported for
//! visibility but do NOT count as a material change — only additions drive
//! [`SubdomainBaselineDiff::has_new_names`], which callers (CLI/cron) use for
//! a non-zero exit code, mirroring [`crate::drift::DriftReport::has_drift`].
//!
//! Persistence mirrors [`crate::history`]: owner-only permissions on Unix,
//! atomic write-and-rename saves, corrupt files backed up to `.corrupt`
//! instead of silently overwritten, and bounded growth (one baseline per
//! domain, oldest-evicted domain cap).

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Maximum number of distinct domains retained. When exceeded, the domain
/// with the oldest baseline is evicted (same bounded-growth rationale as
/// `history.rs` — issue #59).
const MAX_DOMAINS: usize = 1000;

/// A stored subdomain baseline for one domain: the name set from a single
/// enumeration run, plus when and from which CT source it was recorded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainBaseline {
    /// When this baseline was recorded.
    pub recorded_at: DateTime<Utc>,
    /// Which CT source produced the enumeration (e.g. "crt.sh").
    #[serde(default)]
    pub source: String,
    /// The recorded subdomain names (sorted, deduplicated).
    #[serde(default)]
    pub names: BTreeSet<String>,
}

/// On-disk store of subdomain baselines, keyed by (lowercased) domain.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SubdomainBaselines {
    /// One baseline per domain — recording merges into the previous one.
    #[serde(default)]
    pub domains: BTreeMap<String, SubdomainBaseline>,
}

/// A report of how a fresh enumeration differs from the stored baseline.
///
/// Produced by [`SubdomainBaselines::diff`]; rendered by the human/markdown
/// formatters and serialized directly for JSON/YAML output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainBaselineDiff {
    /// The domain compared.
    pub domain: String,
    /// When the baseline was recorded (`None` when no baseline exists).
    pub baseline_recorded_at: Option<DateTime<Utc>>,
    /// Names present now but absent from the baseline (the material change).
    pub added: Vec<String>,
    /// Names in the baseline but absent from the fresh enumeration.
    /// Informational only — see the module docs for why removals don't count
    /// as material.
    pub removed: Vec<String>,
    /// Number of names present in both the baseline and the fresh set.
    pub unchanged_count: usize,
    /// True when no baseline was stored for this domain (first run). The
    /// `added`/`removed` lists are empty in that case so callers keying the
    /// exit code off [`Self::has_new_names`] exit 0 on a first run.
    pub baseline_missing: bool,
}

impl SubdomainBaselineDiff {
    /// True when at least one new name appeared since the baseline. Callers
    /// (CLI/cron) use this to drive a non-zero exit code. Removals never make
    /// this true — see the module docs.
    pub fn has_new_names(&self) -> bool {
        !self.added.is_empty()
    }

    /// Diffs a fresh enumeration against an optional stored baseline.
    ///
    /// With no baseline, returns an empty diff flagged `baseline_missing` —
    /// a first run has nothing to compare against and must not alert.
    pub fn between(domain: &str, baseline: Option<&SubdomainBaseline>, fresh: &[String]) -> Self {
        let Some(baseline) = baseline else {
            return Self {
                domain: domain.to_string(),
                baseline_recorded_at: None,
                added: Vec::new(),
                removed: Vec::new(),
                unchanged_count: 0,
                baseline_missing: true,
            };
        };

        let fresh_set: BTreeSet<String> = fresh.iter().map(|n| normalize_name(n)).collect();

        let added: Vec<String> = fresh_set.difference(&baseline.names).cloned().collect();
        let removed: Vec<String> = baseline.names.difference(&fresh_set).cloned().collect();
        let unchanged_count = fresh_set.intersection(&baseline.names).count();

        Self {
            domain: domain.to_string(),
            baseline_recorded_at: Some(baseline.recorded_at),
            added,
            removed,
            unchanged_count,
            baseline_missing: false,
        }
    }
}

/// Normalizes a subdomain name for set comparison. Enumeration output is
/// already trimmed/lowercased; this keeps injected test data and any future
/// callers on the same footing so case churn is never reported as a change.
fn normalize_name(name: &str) -> String {
    name.trim().to_lowercase()
}

crate::fsutil::persisted_store!(
    SubdomainBaselines,
    "subdomain_baselines.json",
    json,
    "subdomain baselines"
);

impl SubdomainBaselines {
    /// Records `names` into the baseline for `domain`, merging them with any
    /// previously recorded names. Evicts the oldest-recorded domain when the
    /// store exceeds [`MAX_DOMAINS`].
    ///
    /// Merging rather than replacing follows from the module's premise: a
    /// name missing from a run is almost always aggregator truncation, not a
    /// real removal. Replacing would let one flaky run (crt.sh throttled, a
    /// capped certspotter fallback) shrink the baseline, and every
    /// long-standing name it dropped would then resurface as "new" — a false
    /// alert — on the next healthy run.
    pub fn record(&mut self, domain: &str, names: &[String], source: &str) {
        let key = domain.to_lowercase();
        let mut merged: BTreeSet<String> = self
            .domains
            .remove(&key)
            .map(|previous| previous.names)
            .unwrap_or_default();
        merged.extend(names.iter().map(|n| normalize_name(n)));
        self.domains.insert(
            key,
            SubdomainBaseline {
                recorded_at: Utc::now(),
                source: source.to_string(),
                names: merged,
            },
        );
        while self.domains.len() > MAX_DOMAINS {
            let Some(victim) = self
                .domains
                .iter()
                .min_by_key(|(_, b)| b.recorded_at)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            self.domains.remove(&victim);
        }
    }

    /// Returns the stored baseline for a domain, if any.
    pub fn get(&self, domain: &str) -> Option<&SubdomainBaseline> {
        self.domains.get(&domain.to_lowercase())
    }

    /// Diffs a fresh enumeration for `domain` against its stored baseline.
    /// See [`SubdomainBaselineDiff::between`] for the no-baseline semantics.
    pub fn diff(&self, domain: &str, fresh: &[String]) -> SubdomainBaselineDiff {
        SubdomainBaselineDiff::between(domain, self.get(domain), fresh)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn names(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn diff_reports_added_removed_and_unchanged() {
        let mut store = SubdomainBaselines::default();
        store.record(
            "example.com",
            &names(&["api.example.com", "mail.example.com", "old.example.com"]),
            "crt.sh",
        );
        let report = store.diff(
            "example.com",
            &names(&["api.example.com", "mail.example.com", "new.example.com"]),
        );

        assert!(!report.baseline_missing);
        assert!(report.baseline_recorded_at.is_some());
        assert_eq!(report.added, vec!["new.example.com"]);
        assert_eq!(report.removed, vec!["old.example.com"]);
        assert_eq!(report.unchanged_count, 2);
        assert!(report.has_new_names());
    }

    #[test]
    fn removals_alone_are_not_material() {
        // CT logs are append-mostly; a shrinking result set usually means
        // source flakiness, so removals must not drive the exit code.
        let mut store = SubdomainBaselines::default();
        store.record(
            "example.com",
            &names(&["a.example.com", "b.example.com"]),
            "crt.sh",
        );
        let report = store.diff("example.com", &names(&["a.example.com"]));
        assert_eq!(report.removed, vec!["b.example.com"]);
        assert!(!report.has_new_names(), "removals must be non-fatal");
    }

    #[test]
    fn identical_sets_show_no_changes() {
        let mut store = SubdomainBaselines::default();
        store.record("example.com", &names(&["a.example.com"]), "crt.sh");
        let report = store.diff("example.com", &names(&["a.example.com"]));
        assert!(report.added.is_empty());
        assert!(report.removed.is_empty());
        assert_eq!(report.unchanged_count, 1);
        assert!(!report.has_new_names());
    }

    #[test]
    fn missing_baseline_yields_empty_non_material_diff() {
        // First run: nothing to compare against — must not alert (exit 0).
        let store = SubdomainBaselines::default();
        let report = store.diff("example.com", &names(&["a.example.com"]));
        assert!(report.baseline_missing);
        assert!(report.baseline_recorded_at.is_none());
        assert!(report.added.is_empty());
        assert!(report.removed.is_empty());
        assert_eq!(report.unchanged_count, 0);
        assert!(!report.has_new_names());
    }

    #[test]
    fn empty_fresh_set_reports_all_baseline_names_removed() {
        let mut store = SubdomainBaselines::default();
        store.record(
            "example.com",
            &names(&["a.example.com", "b.example.com"]),
            "crt.sh",
        );
        let report = store.diff("example.com", &[]);
        assert!(report.added.is_empty());
        assert_eq!(report.removed, vec!["a.example.com", "b.example.com"]);
        assert_eq!(report.unchanged_count, 0);
        assert!(!report.has_new_names(), "a wiped result set must not alert");
    }

    #[test]
    fn case_and_whitespace_churn_is_not_a_change() {
        let mut store = SubdomainBaselines::default();
        store.record("Example.COM", &names(&["API.example.com "]), "crt.sh");
        let report = store.diff("example.com", &names(&["api.example.com"]));
        assert!(report.added.is_empty(), "case churn: {:?}", report.added);
        assert!(report.removed.is_empty());
        assert_eq!(report.unchanged_count, 1);
    }

    #[test]
    fn record_merges_into_previous_baseline() {
        let mut store = SubdomainBaselines::default();
        store.record(
            "example.com",
            &names(&["a.example.com", "b.example.com"]),
            "crt.sh",
        );
        // A truncated fallback run must not shrink the baseline...
        store.record("example.com", &names(&["b.example.com"]), "certspotter");
        let baseline = store.get("example.com").expect("baseline");
        assert_eq!(baseline.source, "certspotter");
        assert!(baseline.names.contains("a.example.com"));
        assert!(baseline.names.contains("b.example.com"));
        // ...or the next healthy run would re-report `a` as a new name.
        let diff = store.diff("example.com", &names(&["a.example.com", "b.example.com"]));
        assert!(!diff.has_new_names(), "{diff:?}");
    }

    #[test]
    fn domain_cap_evicts_oldest_baseline() {
        let mut store = SubdomainBaselines::default();
        for i in 0..(MAX_DOMAINS + 5) {
            store.record(&format!("d{i}.example"), &names(&["x.d.example"]), "t");
            // Backdate earlier entries so eviction order is deterministic.
            if let Some(b) = store.domains.get_mut(&format!("d{i}.example")) {
                b.recorded_at = Utc::now() + chrono::Duration::seconds(i as i64);
            }
        }
        assert!(
            store.domains.len() <= MAX_DOMAINS,
            "distinct domains must be capped at {MAX_DOMAINS}, got {}",
            store.domains.len()
        );
        assert!(
            store.get("d0.example").is_none(),
            "oldest baseline should be evicted first"
        );
    }

    /// Creates a unique temp path for load/save round-trip tests. The parent
    /// dir is created; the caller cleans up.
    fn unique_temp_path(tag: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "seer-subdomain-baseline-test-{}-{}",
            tag,
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        dir.push("subdomain_baselines.json");
        dir
    }

    #[test]
    fn record_save_load_round_trip() {
        let path = unique_temp_path("roundtrip");
        let _ = std::fs::remove_file(&path);

        let mut store = SubdomainBaselines::default();
        store.record(
            "example.com",
            &names(&["api.example.com", "mail.example.com"]),
            "crt.sh",
        );
        store.save_to_path(&path).expect("save");

        let loaded = SubdomainBaselines::load_from_path(&path);
        let baseline = loaded.get("example.com").expect("baseline survives");
        assert_eq!(baseline.source, "crt.sh");
        assert_eq!(baseline.names.len(), 2);
        assert!(baseline.names.contains("api.example.com"));

        if let Some(parent) = path.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }

    #[cfg(unix)]
    #[test]
    fn save_applies_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let path = unique_temp_path("perms");
        let _ = std::fs::remove_file(&path);

        let mut store = SubdomainBaselines::default();
        store.record("example.com", &names(&["a.example.com"]), "crt.sh");
        store.save_to_path(&path).expect("save");

        let mode = std::fs::metadata(&path).expect("metadata").permissions();
        assert_eq!(
            mode.mode() & 0o777,
            0o600,
            "baseline file must be owner-only"
        );

        if let Some(parent) = path.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }

    #[test]
    fn load_from_path_backs_up_corrupt_file_and_returns_default() {
        let path = unique_temp_path("corrupt");
        let backup = path.with_extension("corrupt");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&backup);

        std::fs::write(&path, b"{ not valid json ").expect("seed file");

        let loaded = SubdomainBaselines::load_from_path(&path);
        assert!(
            loaded.domains.is_empty(),
            "corrupt load must return default"
        );
        assert!(!path.exists(), "corrupt file should be renamed away");
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
        let path = unique_temp_path("missing");
        let _ = std::fs::remove_file(&path);
        let loaded = SubdomainBaselines::load_from_path(&path);
        assert!(loaded.domains.is_empty());
        if let Some(parent) = path.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }

    #[test]
    fn baseline_json_missing_optional_fields_still_parses() {
        // Forward-compat: `source`/`names` carry #[serde(default)] so an
        // older or hand-edited file missing them still loads instead of
        // being kicked to `.corrupt` (the history.rs raw_response lesson).
        let json = r#"{"domains":{"example.com":{"recorded_at":"2026-06-01T00:00:00Z"}}}"#;
        let store: SubdomainBaselines = serde_json::from_str(json).expect("parses");
        let baseline = store.get("example.com").expect("baseline");
        assert!(baseline.names.is_empty());
        assert!(baseline.source.is_empty());
    }
}
