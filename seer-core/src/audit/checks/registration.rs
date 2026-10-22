//! Registration hygiene from the smart lookup: expiry, registrar locks and
//! registration age, and whether the name is registered at all (only a
//! high-confidence "available" verdict is a finding; a less certain one is
//! incomplete). No new traffic. Lock findings are reported only for
//! registries that demonstrably speak EPP lock vocabulary (some status is a
//! `…Prohibited` code); for the rest (`ok`/`active` only, a ccTLD's own
//! words) a missing lock is no evidence.

use futures::future::BoxFuture;

use super::{AuditContext, CheckOutput, CheckSpec};
use crate::audit::finding::{Category, Finding, Severity};
use crate::availability::AvailabilityResult;
use crate::domain_info::{has_lock_vocabulary, has_status_key, DomainInfo, ExpiryStatus};
use crate::lookup::LookupResult;

const CHECK: &str = "registration";

pub(crate) const SPEC: CheckSpec = CheckSpec {
    checks: &[(CHECK, Category::Registration)],
    run,
};

#[cfg(test)]
pub(crate) const IDS: &[&str] = &[
    "registration.expiry.expired",
    "registration.expiry.redemption",
    "registration.expiry.soon",
    "registration.lock.transfer",
    "registration.lock.update",
    "registration.lock.delete",
    "registration.age.young",
    "registration.status.unregistered",
];

/// Registrations younger than this are noted: fresh domains are phishing's
/// raw material, so a young domain is worth knowing about.
const YOUNG_DAYS: i64 = 30;

/// The registration facts the mapping reads.
pub(crate) struct Registration<'a> {
    pub expiry: Option<ExpiryStatus>,
    pub days_until_expiration: Option<i64>,
    pub age_days: Option<i64>,
    pub statuses: &'a [String],
}

impl<'a> From<&'a DomainInfo> for Registration<'a> {
    fn from(info: &'a DomainInfo) -> Self {
        Self {
            expiry: info.expiry_status,
            days_until_expiration: info.days_until_expiration,
            age_days: info.domain_age_days,
            statuses: &info.status,
        }
    }
}

fn run<'a>(ctx: &'a AuditContext<'a>) -> BoxFuture<'a, CheckOutput> {
    Box::pin(async move {
        let mut out = CheckOutput::default();
        match ctx.auditor.lookup.lookup(ctx.domain).await {
            Ok(LookupResult::Available { data, .. }) => {
                match availability_outcome(ctx.domain, &data) {
                    Ok(findings) => out.ran(CHECK, Category::Registration, findings),
                    Err(reason) => out.incomplete(CHECK, Category::Registration, reason),
                }
            }
            Ok(result) => {
                let info = DomainInfo::from_lookup_result(&result);
                out.ran(
                    CHECK,
                    Category::Registration,
                    findings(ctx.domain, &(&info).into()),
                );
            }
            Err(e) => out.failed(CHECK, Category::Registration, &e),
        }
        out
    })
}

/// Maps a lookup that found no registration record to findings, or to the
/// reason the check is incomplete. Only a high-confidence "available"
/// verdict is a finding; anything less certain is unknown. Pure.
pub(crate) fn availability_outcome(
    domain: &str,
    data: &AvailabilityResult,
) -> Result<Vec<Finding>, &'static str> {
    if !data.available {
        return Err("registration data unavailable");
    }
    // `verdict()` is "available" only for (available, confidence "high").
    if data.verdict() != "available" {
        return Err("registration status uncertain");
    }
    Ok(vec![Finding::new(
        "registration.status.unregistered",
        Category::Registration,
        Severity::Critical,
        domain,
        "Domain is not registered",
    )
    .evidence(format!("checked via {}", data.method))
    .fix(
        "Anyone can register this name; register it or stop using it.",
    )])
}

/// Maps registration facts to findings. Pure.
pub(crate) fn findings(domain: &str, reg: &Registration<'_>) -> Vec<Finding> {
    let new = |id, severity, title: &str| {
        Finding::new(id, Category::Registration, severity, domain, title)
    };
    let mut out = Vec::new();
    match reg.expiry {
        Some(ExpiryStatus::Expired) => out.push(
            new(
                "registration.expiry.expired",
                Severity::Critical,
                "Domain registration has expired",
            )
            .fix("Renew the domain with the registrar now."),
        ),
        Some(ExpiryStatus::Redemption | ExpiryStatus::PendingDelete) => out.push(
            new(
                "registration.expiry.redemption",
                Severity::Critical,
                "Domain is in redemption or pending deletion",
            )
            .fix("Restore the domain through the registrar before the registry releases it."),
        ),
        Some(ExpiryStatus::ExpiringSoon) => {
            let mut f = new(
                "registration.expiry.soon",
                Severity::High,
                "Domain registration expires soon",
            )
            .fix("Renew now and turn on auto-renew.");
            if let Some(days) = reg.days_until_expiration {
                f = f.evidence(format!("expires in {days} day(s)"));
            }
            out.push(f);
        }
        _ => {}
    }

    // A registry that publishes no `*Prohibited` status says nothing about
    // locks: it may not use (or publish) EPP lock statuses at all.
    if has_lock_vocabulary(reg.statuses) {
        let locked = |client: &str, server: &str| {
            has_status_key(reg.statuses, client) || has_status_key(reg.statuses, server)
        };
        if !locked("clienttransferprohibited", "servertransferprohibited") {
            out.push(
                new(
                    "registration.lock.transfer",
                    Severity::Medium,
                    "No transfer lock",
                )
                .fix("Ask the registrar to set clientTransferProhibited (registrar lock)."),
            );
        }
        if !locked("clientupdateprohibited", "serverupdateprohibited") {
            out.push(
                new("registration.lock.update", Severity::Low, "No update lock").fix(
                    "Set clientUpdateProhibited to block unauthorised nameserver or contact changes.",
                ),
            );
        }
        if !locked("clientdeleteprohibited", "serverdeleteprohibited") {
            out.push(
                new("registration.lock.delete", Severity::Low, "No delete lock")
                    .fix("Set clientDeleteProhibited."),
            );
        }
    }

    // A negative age (creation date in the future) is bad data, not youth.
    if let Some(days) = reg.age_days.filter(|d| (0..YOUNG_DAYS).contains(d)) {
        out.push(
            new(
                "registration.age.young",
                Severity::Info,
                "Recently registered domain",
            )
            .evidence(format!("registered {days} day(s) ago")),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg<'a>(statuses: &'a [String]) -> Registration<'a> {
        Registration {
            expiry: Some(ExpiryStatus::Active),
            days_until_expiration: Some(300),
            age_days: Some(4000),
            statuses,
        }
    }
    fn ids(findings: &[Finding]) -> Vec<&'static str> {
        findings.iter().map(|f| f.id).collect()
    }
    fn locked() -> Vec<String> {
        [
            "clientTransferProhibited",
            "clientUpdateProhibited",
            "clientDeleteProhibited",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    #[test]
    fn a_healthy_locked_domain_has_no_findings() {
        let statuses = locked();
        assert!(findings("example.com", &reg(&statuses)).is_empty());
    }

    #[test]
    fn expiry_bands_map_to_severities() {
        let statuses = locked();
        for (expiry, id, severity) in [
            (
                ExpiryStatus::Expired,
                "registration.expiry.expired",
                Severity::Critical,
            ),
            (
                ExpiryStatus::Redemption,
                "registration.expiry.redemption",
                Severity::Critical,
            ),
            (
                ExpiryStatus::PendingDelete,
                "registration.expiry.redemption",
                Severity::Critical,
            ),
            (
                ExpiryStatus::ExpiringSoon,
                "registration.expiry.soon",
                Severity::High,
            ),
        ] {
            let f = findings(
                "example.com",
                &Registration {
                    expiry: Some(expiry),
                    days_until_expiration: Some(10),
                    ..reg(&statuses)
                },
            );
            assert_eq!(ids(&f), vec![id]);
            assert_eq!(f[0].severity, severity);
        }
    }

    #[test]
    fn missing_locks_are_flagged() {
        let statuses = vec!["ok".to_string(), "clientDeleteProhibited".to_string()];
        let f = findings("example.com", &reg(&statuses));
        assert_eq!(
            ids(&f),
            vec!["registration.lock.transfer", "registration.lock.update"]
        );
        assert_eq!(f[0].severity, Severity::Medium);
        assert_eq!(f[1].severity, Severity::Low);
    }

    #[test]
    fn no_lock_findings_without_epp_lock_vocabulary() {
        // Registries that never publish a `*Prohibited` status (plain "ok",
        // "active", a ccTLD's own words, FRED prose) say nothing about locks.
        for status in [
            "active",
            "connect",
            "ok",
            "Sponsoring registrar change forbidden",
        ] {
            let statuses = vec![status.to_string()];
            assert!(
                findings("example.com", &reg(&statuses)).is_empty(),
                "{status}"
            );
        }
    }

    #[test]
    fn a_server_lock_counts() {
        let statuses = vec![
            "server transfer prohibited".to_string(),
            "serverUpdateProhibited".to_string(),
            "serverDeleteProhibited".to_string(),
        ];
        assert!(findings("example.com", &reg(&statuses)).is_empty());
    }

    #[test]
    fn no_status_codes_means_no_lock_findings() {
        assert!(findings("example.com", &reg(&[])).is_empty());
    }

    #[test]
    fn a_negative_age_is_not_young() {
        // A creation date in the future (clock skew, bad registry data) is
        // not evidence of a fresh registration.
        let statuses = locked();
        let f = findings(
            "example.com",
            &Registration {
                age_days: Some(-2),
                ..reg(&statuses)
            },
        );
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn young_registration_is_info() {
        let statuses = locked();
        let f = findings(
            "example.com",
            &Registration {
                age_days: Some(3),
                ..reg(&statuses)
            },
        );
        assert_eq!(ids(&f), vec!["registration.age.young"]);
        assert_eq!(f[0].severity, Severity::Info);
    }

    fn availability(available: bool, confidence: &str) -> AvailabilityResult {
        AvailabilityResult::new("example.com", available, confidence, "rdap")
    }

    #[test]
    fn a_confidently_unregistered_domain_is_critical() {
        let f = availability_outcome("example.com", &availability(true, "high")).unwrap();
        assert_eq!(ids(&f), vec!["registration.status.unregistered"]);
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(f[0].evidence.as_deref(), Some("checked via rdap"));
        assert!(IDS.contains(&f[0].id));
    }

    #[test]
    fn an_uncertain_or_failed_availability_is_incomplete() {
        for confidence in ["medium", "low", "none"] {
            assert_eq!(
                availability_outcome("example.com", &availability(true, confidence)),
                Err("registration status uncertain"),
                "{confidence}"
            );
        }
        assert_eq!(
            availability_outcome("example.com", &availability(false, "none")),
            Err("registration data unavailable")
        );
    }

    #[test]
    fn every_emitted_id_is_declared() {
        let statuses = vec!["ok".to_string(), "clientRenewProhibited".to_string()];
        let f = findings(
            "example.com",
            &Registration {
                expiry: Some(ExpiryStatus::Expired),
                days_until_expiration: Some(-1),
                age_days: Some(1),
                statuses: &statuses,
            },
        );
        assert!(f.iter().all(|f| IDS.contains(&f.id)));
    }
}
