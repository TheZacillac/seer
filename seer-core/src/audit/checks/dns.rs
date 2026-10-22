//! DNSSEC and NS delegation health. DNSSEC is digest-only
//! (`AuthenticationTier::DigestOnly`): "broken" means a DS set validators
//! would use matches no DNSKEY — validating resolvers then fail the zone.
//!
//! Lame nameservers split on [`LameKind`]: one that answered wrongly
//! (REFUSED, non-authoritative, referral, …) is definitive and High; one
//! that gave no usable response may be dead or may be a lost probe, so it is
//! Medium and never caps the grade.

use futures::future::BoxFuture;

use super::{AuditContext, CheckOutput, CheckSpec};
use crate::audit::finding::{Category, Finding, Severity};
use crate::dns::{DelegationReport, DnssecReport, LameKind};

const D: Category = Category::Dns;
const DNSSEC_CHECK: &str = "dns.dnssec";
const DELEGATION_CHECK: &str = "dns.delegation";

pub(crate) const DNSSEC: CheckSpec = CheckSpec {
    checks: &[(DNSSEC_CHECK, D)],
    run: run_dnssec,
};
pub(crate) const DELEGATION: CheckSpec = CheckSpec {
    checks: &[(DELEGATION_CHECK, D)],
    run: run_delegation,
};

#[cfg(test)]
pub(crate) const IDS: &[&str] = &[
    "dns.dnssec.broken",
    "dns.dnssec.unsigned",
    "dns.dnssec.partial",
    "dns.delegation.lame",
    "dns.delegation.unresponsive",
    "dns.delegation.out-of-sync",
    "dns.ns.single",
];

fn run_dnssec<'a>(ctx: &'a AuditContext<'a>) -> BoxFuture<'a, CheckOutput> {
    Box::pin(async move {
        let mut out = CheckOutput::default();
        match ctx.auditor.dnssec.check(ctx.domain).await {
            Ok(r) => out.ran(DNSSEC_CHECK, D, assess_dnssec(ctx.domain, &r)),
            Err(e) => out.failed(DNSSEC_CHECK, D, &e),
        }
        out
    })
}

fn run_delegation<'a>(ctx: &'a AuditContext<'a>) -> BoxFuture<'a, CheckOutput> {
    Box::pin(async move {
        let mut out = CheckOutput::default();
        match ctx.auditor.delegation.check(ctx.domain).await {
            Ok(r) => out.ran(DELEGATION_CHECK, D, assess_delegation(ctx.domain, &r)),
            Err(e) => out.failed(DELEGATION_CHECK, D, &e),
        }
        out
    })
}

/// Maps a DNSSEC report (its fixed `status` code) to findings. Pure.
pub(crate) fn assess_dnssec(domain: &str, r: &DnssecReport) -> Vec<Finding> {
    let new = |id, severity, title: &str| Finding::new(id, D, severity, domain, title);
    match r.status.as_str() {
        "misconfigured" => vec![new(
            "dns.dnssec.broken",
            Severity::Critical,
            "DNSSEC is broken (DS matches no DNSKEY)",
        )
        .fix("Fix the DS at the registrar to match a published DNSKEY, or remove it.")],
        "unsigned" => vec![new(
            "dns.dnssec.unsigned",
            Severity::Low,
            "Zone is not DNSSEC-signed",
        )
        .fix("Sign the zone and publish its DS at the registrar.")],
        "partial" => vec![new(
            "dns.dnssec.partial",
            Severity::Low,
            "DNSSEC is incomplete (no usable DS)",
        )
        .fix("Publish a DS record with a supported algorithm at the registrar.")],
        _ => Vec::new(),
    }
}

/// Maps a delegation report to findings. Pure.
pub(crate) fn assess_delegation(domain: &str, r: &DelegationReport) -> Vec<Finding> {
    let new = |id, severity, title: &str| Finding::new(id, D, severity, domain, title);
    let hosts = |unresponsive: bool| {
        r.lame
            .iter()
            .filter(|l| (l.kind == LameKind::Unresponsive) == unresponsive)
            .map(|l| l.host.as_str())
            .collect::<Vec<_>>()
    };
    let mut out = Vec::new();
    let answered_wrongly = hosts(false);
    if !answered_wrongly.is_empty() {
        out.push(
            new("dns.delegation.lame", Severity::High, "Lame nameserver delegation")
                .evidence(answered_wrongly.join(", "))
                .fix("Make every delegated nameserver answer authoritatively, or remove it from the delegation."),
        );
    }
    let silent = hosts(true);
    if !silent.is_empty() {
        out.push(
            new(
                "dns.delegation.unresponsive",
                Severity::Medium,
                "Nameserver did not respond",
            )
            .evidence(silent.join(", "))
            .fix("Check the nameserver is up and reachable on UDP and TCP port 53, or remove it from the delegation."),
        );
    }
    if !r.missing_from_zone.is_empty() || !r.missing_from_parent.is_empty() {
        out.push(
            new(
                "dns.delegation.out-of-sync",
                Severity::Medium,
                "Parent and zone NS sets differ",
            )
            .fix("Make the registrar's NS list and the zone's own NS records identical."),
        );
    }
    if r.delegated_ns.len() == 1 {
        out.push(
            new("dns.ns.single", Severity::Medium, "Only one nameserver")
                .fix("Delegate to at least two nameservers on separate networks."),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{AuthenticationTier, LameKind, LameNs};

    fn dnssec(status: &str) -> DnssecReport {
        DnssecReport {
            domain: "example.com".into(),
            enabled: status != "unsigned",
            has_ds_records: false,
            has_dnskey_records: false,
            ds_records: vec![],
            dnskey_records: vec![],
            issues: vec![],
            status: status.into(),
            chain_valid: status == "signed",
            authentication_tier: AuthenticationTier::DigestOnly,
        }
    }
    fn delegation() -> DelegationReport {
        DelegationReport {
            domain: "example.com".into(),
            parent_zone: "com".into(),
            parent_server_queried: vec!["a.gtld-servers.net".into()],
            delegated_ns: vec!["ns1.example.com".into(), "ns2.example.com".into()],
            zone_ns: vec!["ns1.example.com".into(), "ns2.example.com".into()],
            in_sync: true,
            missing_from_zone: vec![],
            missing_from_parent: vec![],
            lame: vec![],
            warnings: vec![],
        }
    }
    fn ids(f: &[Finding]) -> Vec<&'static str> {
        f.iter().map(|f| f.id).collect()
    }

    #[test]
    fn dnssec_states() {
        assert!(assess_dnssec("example.com", &dnssec("signed")).is_empty());
        let f = assess_dnssec("example.com", &dnssec("misconfigured"));
        assert_eq!(ids(&f), vec!["dns.dnssec.broken"]);
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(
            ids(&assess_dnssec("example.com", &dnssec("unsigned"))),
            vec!["dns.dnssec.unsigned"]
        );
        assert_eq!(
            ids(&assess_dnssec("example.com", &dnssec("partial"))),
            vec!["dns.dnssec.partial"]
        );
    }

    #[test]
    fn delegation_problems() {
        assert!(assess_delegation("example.com", &delegation()).is_empty());

        let mut d = delegation();
        d.lame = vec![lame("ns2.example.com", LameKind::ErrorRcode)];
        d.missing_from_zone = vec!["ns3.example.com".into()];
        d.in_sync = false;
        assert_eq!(
            ids(&assess_delegation("example.com", &d)),
            vec!["dns.delegation.lame", "dns.delegation.out-of-sync"]
        );

        let mut d = delegation();
        d.delegated_ns.truncate(1);
        assert_eq!(
            ids(&assess_delegation("example.com", &d)),
            vec!["dns.ns.single"]
        );
    }

    fn lame(host: &str, kind: LameKind) -> LameNs {
        LameNs {
            host: host.into(),
            kind,
            reason: String::new(),
        }
    }

    /// A server that answered wrongly is definitive (High, caps at C); one
    /// that never answered may be dead or may be packet loss (Medium, no
    /// cap). Each finding names only its own servers.
    #[test]
    fn unresponsive_nameservers_are_medium_not_lame() {
        let mut d = delegation();
        d.in_sync = false;
        d.lame = vec![lame("ns2.example.com", LameKind::Unresponsive)];
        let f = assess_delegation("example.com", &d);
        assert_eq!(ids(&f), vec!["dns.delegation.unresponsive"]);
        assert_eq!(f[0].severity, Severity::Medium);
        assert_eq!(f[0].evidence.as_deref(), Some("ns2.example.com"));

        for definitive in [
            LameKind::Nxdomain,
            LameKind::NoNsRecords,
            LameKind::NotAuthoritative,
            LameKind::Referral,
            LameKind::EmptyAnswer,
            LameKind::ErrorRcode,
        ] {
            d.lame = vec![lame("ns1.example.com", definitive)];
            let f = assess_delegation("example.com", &d);
            assert_eq!(ids(&f), vec!["dns.delegation.lame"], "{definitive:?}");
            assert_eq!(f[0].severity, Severity::High);
        }

        d.lame = vec![
            lame("ns1.example.com", LameKind::ErrorRcode),
            lame("ns2.example.com", LameKind::Unresponsive),
        ];
        let f = assess_delegation("example.com", &d);
        assert_eq!(
            ids(&f),
            vec!["dns.delegation.lame", "dns.delegation.unresponsive"]
        );
        assert_eq!(f[0].evidence.as_deref(), Some("ns1.example.com"));
        assert_eq!(f[1].evidence.as_deref(), Some("ns2.example.com"));
        assert!(f.iter().all(|f| IDS.contains(&f.id)));
    }
}
