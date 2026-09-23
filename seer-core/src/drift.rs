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

use crate::domain_info::{DomainInfo, DomainInfoSource};
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
    /// Why the snapshots could not be compared, when one of them carries no
    /// registration data (a throttled or inconclusive lookup). An absent
    /// answer is not a changed answer, so nothing is diffed and
    /// [`DriftReport::has_drift`] stays false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inconclusive: Option<String>,
}

impl DriftReport {
    /// True when at least one material field changed. Callers (CLI/cron) use
    /// this to drive a non-zero exit code.
    pub fn has_drift(&self) -> bool {
        !self.changes.is_empty()
    }

    /// A report with nothing compared yet (no previous snapshot).
    pub fn empty(domain: &str) -> Self {
        DriftReport {
            domain: domain.to_string(),
            changes: Vec::new(),
            inconclusive: None,
        }
    }

    /// Diffs two already-merged [`DomainInfo`] snapshots, comparing only the
    /// fields that matter for change monitoring.
    ///
    /// Values are compared in a source-independent form: RDAP and WHOIS spell
    /// the same EPP status (`client transfer prohibited` vs
    /// `clientTransferProhibited`) and DNSSEC state (`signed` vs
    /// `signedDelegation`) differently, and smart lookup legitimately flips
    /// between the two when RDAP is throttled — that must not read as a
    /// hijack indicator.
    pub fn between(domain: &str, old: &DomainInfo, new: &DomainInfo) -> Self {
        // A domain that is now genuinely available has lapsed or been
        // deleted: that is the one change worth reporting on its own.
        let lapsed = |info: &DomainInfo| {
            matches!(
                info.availability_verdict.as_deref(),
                Some("available" | "likely_available")
            )
        };
        if has_registration_data(old) && !has_registration_data(new) && lapsed(new) {
            return DriftReport {
                domain: domain.to_string(),
                changes: vec![FieldChange {
                    field: "registration".to_string(),
                    old: Some("registered".to_string()),
                    new: new.availability_verdict.clone(),
                }],
                inconclusive: None,
            };
        }
        for (label, info) in [("previous", old), ("current", new)] {
            if !has_registration_data(info) {
                return DriftReport {
                    domain: domain.to_string(),
                    changes: Vec::new(),
                    inconclusive: Some(format!(
                        "the {label} lookup returned no registration data ({}), so the \
                         snapshots were not compared",
                        info.availability_verdict
                            .as_deref()
                            .unwrap_or("no RDAP/WHOIS data")
                    )),
                };
            }
        }

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
        push(
            "status",
            joined_keys(&old.status, status_key),
            joined_keys(&new.status, status_key),
        );
        push(
            "expiration_date",
            old.expiration_date.map(|d| d.to_rfc3339()),
            new.expiration_date.map(|d| d.to_rfc3339()),
        );
        // Only a definite signed/unsigned on BOTH sides is comparable: one
        // side simply not reporting DNSSEC (thin WHOIS) is not a toggle.
        if let (Some(o), Some(n)) = (dnssec_state(old), dnssec_state(new)) {
            if o != n {
                push("dnssec", old.dnssec.clone(), new.dnssec.clone());
            }
        }

        DriftReport {
            domain: domain.to_string(),
            changes,
            inconclusive: None,
        }
    }

    /// Diffs two [`LookupResult`]s by merging each into a [`DomainInfo`] first.
    pub fn from_lookups(domain: &str, previous: &LookupResult, current: &LookupResult) -> Self {
        let old = DomainInfo::from_lookup_result(previous);
        let new = DomainInfo::from_lookup_result(current);
        Self::between(domain, &old, &new)
    }
}

/// True when a snapshot carries any registration data at all. A lookup that
/// was throttled or inconclusive produces a snapshot with none of these, and
/// diffing it would report every field as "removed".
fn has_registration_data(info: &DomainInfo) -> bool {
    info.source != DomainInfoSource::Available
        || info.registrar.is_some()
        || !info.nameservers.is_empty()
        || !info.status.is_empty()
        || info.expiration_date.is_some()
}

/// Canonical EPP status key, independent of RDAP (`client transfer
/// prohibited`) vs WHOIS (`clientTransferProhibited`) spelling. Mirrors
/// `domain_info`'s status normalization (a trailing ` (URL)` is dropped).
fn status_key(code: &str) -> String {
    code.chars()
        .take_while(|c| *c != '(')
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// DNSSEC state reduced to signed (`true`) / unsigned (`false`), or `None`
/// when the value is absent or unrecognized.
fn dnssec_state(info: &DomainInfo) -> Option<bool> {
    let v = info.dnssec.as_deref()?.trim().to_ascii_lowercase();
    if v.starts_with("unsigned") || v == "no" || v == "false" || v == "inactive" {
        Some(false)
    } else if v.starts_with("signed") || v == "yes" || v == "true" || v == "active" {
        Some(true)
    } else {
        None
    }
}

/// Normalizes a list field (nameservers/status) to a case-insensitive, sorted,
/// deduplicated, comma-joined string so ordering churn isn't reported as drift.
/// Returns `None` for an empty list so an absent field compares equal across
/// snapshots.
fn joined_set(values: &[String]) -> Option<String> {
    joined_keys(values, |v| v.trim().trim_end_matches('.').to_lowercase())
}

/// [`joined_set`] with a caller-supplied normalization.
fn joined_keys(values: &[String], key: impl Fn(&str) -> String) -> Option<String> {
    let mut normalized: Vec<String> = values
        .iter()
        .map(|v| key(v))
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

/// True when a stored lookup carries registration data, i.e. is usable as a
/// drift baseline. A throttled or inconclusive lookup recorded into history
/// must not become the snapshot the next run is compared against.
pub fn is_comparable(result: &LookupResult) -> bool {
    has_registration_data(&DomainInfo::from_lookup_result(result))
}

/// Picks the baseline for a drift check: the most recent comparable stored
/// snapshot, falling back to the most recent one of any kind.
pub fn baseline_snapshot<'a>(
    entries: impl DoubleEndedIterator<Item = &'a LookupResult> + Clone,
) -> Option<&'a LookupResult> {
    entries
        .clone()
        .rev()
        .find(|r| is_comparable(r))
        .or_else(|| entries.clone().next_back())
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
            creation_date: Some(Utc.with_ymd_and_hms(2019, 6, 1, 0, 0, 0).unwrap()),
            expiration_date: Some(Utc.with_ymd_and_hms(2025, 6, 1, 0, 0, 0).unwrap()),
            nameservers: nameservers.iter().map(|s| s.to_string()).collect(),
            dnssec: Some(dnssec.to_string()),
            whois_server: "whois.example.com".to_string(),
            ..Default::default()
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
    fn rdap_whois_source_flip_is_not_drift() {
        // RDAP throttled on the second run, so smart lookup fell back to
        // WHOIS: same facts, different spelling. Must not look like a hijack.
        let mut old = snapshot("R", &["ns1.example.com."], "signed");
        old.status = vec!["client transfer prohibited".to_string()];
        let mut new = snapshot("R", &["NS1.EXAMPLE.COM"], "signedDelegation");
        new.status = vec!["clientTransferProhibited".to_string()];
        let report = DriftReport::between("example.com", &old, &new);
        assert!(!report.has_drift(), "{:?}", report.changes);

        // A real DNSSEC removal in either spelling is still caught.
        let new = snapshot("R", &["ns1.example.com"], "Unsigned");
        let report = DriftReport::between("example.com", &old, &new);
        assert!(report.changes.iter().any(|c| c.field == "dnssec"));
    }

    #[test]
    fn a_snapshot_without_registration_data_is_inconclusive_not_drift() {
        let old = snapshot("R", &["ns1.example.com"], "signed");
        // What a throttled/inconclusive lookup produces.
        let mut empty = DomainInfo::from_sources("example.com", None, None);
        empty.source = DomainInfoSource::Available;
        empty.availability_verdict = Some("unknown".to_string());

        let report = DriftReport::between("example.com", &old, &empty);
        assert!(!report.has_drift(), "{:?}", report.changes);
        assert!(report
            .inconclusive
            .as_deref()
            .unwrap_or_default()
            .contains("current lookup"));
        let report = DriftReport::between("example.com", &empty, &old);
        assert!(!report.has_drift());
        assert!(report.inconclusive.is_some());
    }

    #[test]
    fn a_lapsed_registration_is_drift() {
        let old = snapshot("R", &["ns1.example.com"], "signed");
        let mut gone = DomainInfo::from_sources("example.com", None, None);
        gone.source = DomainInfoSource::Available;
        gone.availability_verdict = Some("available".to_string());
        let report = DriftReport::between("example.com", &old, &gone);
        assert!(report.has_drift());
        assert_eq!(report.changes[0].field, "registration");
        assert_eq!(report.changes[0].new.as_deref(), Some("available"));
    }

    #[test]
    fn identical_snapshots_have_no_drift() {
        let a = snapshot("R", &["ns1.example.com"], "signed");
        let b = snapshot("R", &["ns1.example.com"], "signed");
        assert!(!DriftReport::between("example.com", &a, &b).has_drift());
    }

    #[test]
    fn baseline_snapshot_needs_an_earlier_snapshot() {
        let result = LookupResult::Whois {
            data: crate::whois::WhoisResponse::parse(
                "example.com",
                "whois.example.com",
                "Domain Name: example.com\nName Server: ns1.example.com\n",
            ),
            rdap_error: None,
            rdap_fallback: None,
        };
        // No earlier snapshot → nothing to compare.
        assert!(baseline_snapshot(std::iter::empty()).is_none());
        // Two identical snapshots → a report exists but shows no drift.
        let previous = baseline_snapshot([&result].into_iter()).expect("baseline");
        let report = DriftReport::from_lookups("example.com", previous, &result);
        assert!(!report.has_drift());
    }
}
