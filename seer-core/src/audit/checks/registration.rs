//! Registration hygiene from the smart lookup: expiry, registrar locks and
//! registration age. No new traffic. Registries that publish no EPP status
//! codes give no evidence about locks, so none are reported for them.

use futures::future::BoxFuture;

use super::{AuditContext, CheckOutput, CheckSpec};
use crate::audit::finding::{Category, Finding, Severity};
use crate::domain_info::{has_status_key, DomainInfo, ExpiryStatus};
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
            Ok(LookupResult::Available { data, .. }) if data.available => {
                out.not_applicable(CHECK, Category::Registration, "domain is not registered");
            }
            Ok(LookupResult::Available { .. }) => {
                out.incomplete(
                    CHECK,
                    Category::Registration,
                    "registration data unavailable",
                );
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

    // A registry that publishes no status codes says nothing about locks.
    if !reg.statuses.is_empty() {
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

    if let Some(days) = reg.age_days.filter(|d| *d < YOUNG_DAYS) {
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
        let statuses = vec!["ok".to_string()];
        let f = findings("example.com", &reg(&statuses));
        assert_eq!(
            ids(&f),
            vec![
                "registration.lock.transfer",
                "registration.lock.update",
                "registration.lock.delete"
            ]
        );
        assert_eq!(f[0].severity, Severity::Medium);
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

    #[test]
    fn every_emitted_id_is_declared() {
        let statuses = vec!["ok".to_string()];
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
