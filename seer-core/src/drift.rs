//! Domain drift detection.
//!
//! Diffs a domain's current registration/DNS state against a prior snapshot to
//! surface the changes that matter for security monitoring: nameserver swaps,
//! registrar transfers, expiry shifts, DNSSEC toggles, and registrant changes.
//! Silent nameserver swaps and DNSSEC removal are classic hijack indicators.
//!
//! This is pure post-processing over data seer already merges into
//! [`DomainInfo`] and persists in [`crate::history`] — no new network protocol.

use serde::{Deserialize, Serialize};

use crate::domain_info::DomainInfo;
use crate::history::LookupHistory;
use crate::lookup::LookupResult;

/// A single field that differs between two snapshots of a domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldChange {
    /// The name of the field that changed (e.g. `"nameservers"`).
    pub field: String,
    /// The previous value (`None` when the field was previously unset/empty).
    pub old: Option<String>,
    /// The current value (`None` when the field is now unset/empty).
    pub new: Option<String>,
}

/// A report of what changed between two snapshots of a domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftReport {
    /// The domain compared.
    pub domain: String,
    /// The set of changed fields (empty when nothing material changed).
    pub changes: Vec<FieldChange>,
}

impl DriftReport {
    /// True when at least one material field changed. Callers (CLI/cron) use
    /// this to drive a non-zero exit code.
    pub fn has_drift(&self) -> bool {
        !self.changes.is_empty()
    }

    /// Diffs two already-merged [`DomainInfo`] snapshots, comparing only the
    /// fields that matter for change monitoring.
    pub fn between(domain: &str, old: &DomainInfo, new: &DomainInfo) -> Self {
        let mut changes = Vec::new();

        let mut push = |field: &str, old: Option<String>, new: Option<String>| {
            if old != new {
                changes.push(FieldChange {
                    field: field.to_string(),
                    old,
                    new,
                });
            }
        };

        push("registrar", old.registrar.clone(), new.registrar.clone());
        push(
            "organization",
            old.organization.clone(),
            new.organization.clone(),
        );
        push("registrant", old.registrant.clone(), new.registrant.clone());
        push(
            "nameservers",
            joined_set(&old.nameservers),
            joined_set(&new.nameservers),
        );
        push("status", joined_set(&old.status), joined_set(&new.status));
        push(
            "expiration_date",
            old.expiration_date.map(|d| d.to_rfc3339()),
            new.expiration_date.map(|d| d.to_rfc3339()),
        );
        push("dnssec", old.dnssec.clone(), new.dnssec.clone());

        DriftReport {
            domain: domain.to_string(),
            changes,
        }
    }

    /// Diffs two [`LookupResult`]s by merging each into a [`DomainInfo`] first.
    pub fn from_lookups(domain: &str, previous: &LookupResult, current: &LookupResult) -> Self {
        let old = DomainInfo::from_lookup_result(previous);
        let new = DomainInfo::from_lookup_result(current);
        Self::between(domain, &old, &new)
    }
}

/// Normalizes a list field (nameservers/status) to a case-insensitive, sorted,
/// deduplicated, comma-joined string so ordering churn isn't reported as drift.
/// Returns `None` for an empty list so an absent field compares equal across
/// snapshots.
fn joined_set(values: &[String]) -> Option<String> {
    let mut normalized: Vec<String> = values
        .iter()
        .map(|v| v.trim().to_lowercase())
        .filter(|v| !v.is_empty())
        .collect();
    normalized.sort();
    normalized.dedup();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized.join(", "))
    }
}

/// Computes drift between the two most recent history entries for a domain.
///
/// Returns `None` when the domain has fewer than two stored snapshots (nothing
/// to compare against yet).
pub fn drift_from_history(history: &LookupHistory, domain: &str) -> Option<DriftReport> {
    let entries = history.get(domain);
    if entries.len() < 2 {
        return None;
    }
    let previous = &entries[entries.len() - 2].result;
    let current = &entries[entries.len() - 1].result;
    Some(DriftReport::from_lookups(domain, previous, current))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    /// Builds a WHOIS-backed snapshot with the given nameservers/registrar so we
    /// can diff two merged `DomainInfo`s without fabricating full lookups.
    fn snapshot(registrar: &str, nameservers: &[&str], dnssec: &str) -> DomainInfo {
        let whois = crate::whois::WhoisResponse {
            domain: "example.com".to_string(),
            registrar: Some(registrar.to_string()),
            registrant: None,
            organization: None,
            registrant_email: None,
            registrant_phone: None,
            registrant_address: None,
            registrant_country: None,
            admin_name: None,
            admin_organization: None,
            admin_email: None,
            admin_phone: None,
            tech_name: None,
            tech_organization: None,
            tech_email: None,
            tech_phone: None,
            creation_date: Some(Utc.with_ymd_and_hms(2019, 6, 1, 0, 0, 0).unwrap()),
            expiration_date: Some(Utc.with_ymd_and_hms(2025, 6, 1, 0, 0, 0).unwrap()),
            updated_date: None,
            nameservers: nameservers.iter().map(|s| s.to_string()).collect(),
            status: vec![],
            dnssec: Some(dnssec.to_string()),
            whois_server: "whois.example.com".to_string(),
            raw_response: String::new(),
        };
        DomainInfo::from_sources("example.com", None, Some(&whois))
    }

    #[test]
    fn between_detects_nameserver_swap_and_registrar_transfer() {
        let old = snapshot("Old Registrar", &["ns1.old.net", "ns2.old.net"], "signed");
        let new = snapshot("New Registrar", &["ns1.new.net", "ns2.new.net"], "signed");
        let report = DriftReport::between("example.com", &old, &new);

        assert!(report.has_drift());
        let fields: Vec<&str> = report.changes.iter().map(|c| c.field.as_str()).collect();
        assert!(fields.contains(&"registrar"));
        assert!(fields.contains(&"nameservers"));
        assert!(!fields.contains(&"dnssec"), "dnssec unchanged");
    }

    #[test]
    fn between_detects_dnssec_removal() {
        let old = snapshot("R", &["ns1.example.com"], "signed");
        let new = snapshot("R", &["ns1.example.com"], "unsigned");
        let report = DriftReport::between("example.com", &old, &new);
        let dnssec = report.changes.iter().find(|c| c.field == "dnssec").unwrap();
        assert_eq!(dnssec.old.as_deref(), Some("signed"));
        assert_eq!(dnssec.new.as_deref(), Some("unsigned"));
    }

    #[test]
    fn nameserver_reordering_is_not_drift() {
        // Same set, different order/case → no change reported.
        let old = snapshot("R", &["NS1.example.com", "ns2.example.com"], "signed");
        let new = snapshot("R", &["ns2.example.com", "ns1.EXAMPLE.com"], "signed");
        let report = DriftReport::between("example.com", &old, &new);
        assert!(
            !report.has_drift(),
            "reordering/case must not count as drift: {:?}",
            report.changes
        );
    }

    #[test]
    fn identical_snapshots_have_no_drift() {
        let a = snapshot("R", &["ns1.example.com"], "signed");
        let b = snapshot("R", &["ns1.example.com"], "signed");
        assert!(!DriftReport::between("example.com", &a, &b).has_drift());
    }

    #[test]
    fn drift_from_history_needs_two_snapshots() {
        let mut history = LookupHistory::default();
        let result = LookupResult::Whois {
            data: crate::whois::WhoisResponse::parse(
                "example.com",
                "whois.example.com",
                "Domain Name: example.com\nName Server: ns1.example.com\n",
            ),
            rdap_error: None,
            rdap_fallback: None,
        };
        history.record("example.com", result.clone());
        // Only one snapshot → nothing to compare.
        assert!(drift_from_history(&history, "example.com").is_none());
        history.record("example.com", result);
        // Two identical snapshots → a report exists but shows no drift.
        let report = drift_from_history(&history, "example.com").expect("report");
        assert!(!report.has_drift());
    }
}
