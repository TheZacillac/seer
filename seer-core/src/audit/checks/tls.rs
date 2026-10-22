//! Certificate and CAA, from one `SslChecker` inspection. Reads
//! `CertWarning.kind`, `days_until_expiry` and the embedded CAA policy —
//! never warning text. Chain trust is not verified by `ssl` (inspection
//! only), so there is no "untrusted chain" finding; self-signed is the
//! structured signal. A failed handshake is the Web check's finding.

use futures::future::BoxFuture;

use super::{AuditContext, CheckOutput, CheckSpec};
use crate::audit::finding::{Category, Finding, Severity};
use crate::caa::IssuerCaaMatch;
use crate::ssl::{CertWarningKind, SslReport};

const T: Category = Category::Tls;
const CERT: &str = "tls.certificate";
const CAA: &str = "tls.caa";

pub(crate) const SPEC: CheckSpec = CheckSpec {
    checks: &[(CERT, T), (CAA, T)],
    run,
};

#[cfg(test)]
pub(crate) const IDS: &[&str] = &[
    "tls.cert.expired",
    "tls.cert.not-yet-valid",
    "tls.cert.name-mismatch",
    "tls.cert.self-signed",
    "tls.cert.weak-key",
    "tls.cert.weak-signature",
    "tls.cert.ca-leaf",
    "tls.cert.expiring-14d",
    "tls.cert.expiring-30d",
    "tls.caa.missing",
    "tls.caa.issuer-not-listed",
];

fn run<'a>(ctx: &'a AuditContext<'a>) -> BoxFuture<'a, CheckOutput> {
    Box::pin(async move {
        match ctx.auditor.ssl.check(ctx.host).await {
            Ok(report) => assess(ctx.host, &report),
            Err(e) => {
                let mut out = CheckOutput::default();
                out.failed(CERT, T, &e);
                out.failed(CAA, T, &e);
                out
            }
        }
    })
}

/// SANs listed in name-mismatch evidence before the rest are counted.
const MAX_LISTED_SANS: usize = 5;

/// The first [`MAX_LISTED_SANS`] SANs, then `+N more`.
fn san_summary(sans: &[String]) -> String {
    let mut out = sans
        .iter()
        .take(MAX_LISTED_SANS)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    if sans.len() > MAX_LISTED_SANS {
        out.push_str(&format!(", +{} more", sans.len() - MAX_LISTED_SANS));
    }
    out
}

/// Maps an SSL report to the certificate and CAA runs. Pure.
pub(crate) fn assess(host: &str, r: &SslReport) -> CheckOutput {
    let mut out = CheckOutput::default();
    let new = |id, severity, title: &str| Finding::new(id, T, severity, host, title);

    let mut cert = Vec::new();
    for w in &r.warnings {
        let finding = match w.kind {
            CertWarningKind::Expired => new(
                "tls.cert.expired",
                Severity::Critical,
                "Certificate has expired",
            )
            .fix("Renew the certificate and automate renewal (ACME)."),
            CertWarningKind::NotYetValid => new(
                "tls.cert.not-yet-valid",
                Severity::Critical,
                "Certificate is not yet valid",
            )
            .fix("Check the server clock and the certificate's notBefore date."),
            CertWarningKind::HostnameMismatch => new(
                "tls.cert.name-mismatch",
                Severity::Critical,
                "Certificate does not match the host name",
            )
            .evidence(san_summary(&r.san_names))
            .fix("Issue a certificate whose SANs include this host."),
            CertWarningKind::SelfSigned => new(
                "tls.cert.self-signed",
                Severity::High,
                "Certificate is self-signed",
            )
            .fix("Use a certificate from a publicly trusted CA."),
            CertWarningKind::WeakKey => new(
                "tls.cert.weak-key",
                Severity::High,
                "Certificate key is too short",
            )
            .fix("Reissue with RSA 2048+ or ECDSA P-256+."),
            CertWarningKind::DeprecatedSignature => new(
                "tls.cert.weak-signature",
                Severity::High,
                "Certificate uses a deprecated signature (SHA-1/MD5)",
            )
            .fix("Reissue with a SHA-256 (or stronger) signature."),
            CertWarningKind::CaLeaf => new(
                "tls.cert.ca-leaf",
                Severity::Medium,
                "Leaf certificate is marked as a CA",
            )
            .fix("Reissue the leaf without the CA basic constraint."),
            // Graded below from the day count, which separates 14 from 30.
            CertWarningKind::ExpiringSoon => continue,
        };
        cert.push(finding);
    }
    if (0..14).contains(&r.days_until_expiry) {
        cert.push(
            new(
                "tls.cert.expiring-14d",
                Severity::High,
                "Certificate expires within 14 days",
            )
            .evidence(format!("{} day(s) left", r.days_until_expiry))
            .fix("Renew now and check that automated renewal works."),
        );
    } else if (14..30).contains(&r.days_until_expiry) {
        cert.push(
            new(
                "tls.cert.expiring-30d",
                Severity::Medium,
                "Certificate expires within 30 days",
            )
            .evidence(format!("{} day(s) left", r.days_until_expiry))
            .fix("Renew soon and check that automated renewal works."),
        );
    }
    out.ran(CERT, T, cert);

    match &r.caa {
        Some(p) if p.has_policy => {
            let mismatch = p.issuer_match == Some(IssuerCaaMatch::Mismatch);
            out.ran(
                CAA,
                T,
                if mismatch {
                    vec![new(
                        "tls.caa.issuer-not-listed",
                        Severity::Info,
                        "Certificate issuer is not in the CAA policy",
                    )
                    .fix(
                        "CAA applies at issuance only; add the issuing CA before the next renewal.",
                    )]
                } else {
                    Vec::new()
                },
            );
        }
        Some(p) if p.lookup_failed => out.incomplete(CAA, T, "CAA lookup failed"),
        Some(_) => out.ran(
            CAA,
            T,
            vec![new("tls.caa.missing", Severity::Low, "No CAA policy")
                .fix("Publish CAA records naming the CAs allowed to issue for this domain.")],
        ),
        None => out.incomplete(CAA, T, "CAA not evaluated"),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::finding::CheckStatus;
    use crate::caa::CaaPolicy;
    use crate::ssl::{CertWarning, CertWarningSeverity};

    fn report() -> SslReport {
        SslReport {
            domain: "example.com".into(),
            chain: vec![],
            protocol_version: Some("TLSv1.3".into()),
            san_names: vec!["example.com".into()],
            is_valid: true,
            hostname_verified: true,
            days_until_expiry: 80,
            caa: Some(CaaPolicy {
                has_policy: true,
                ..CaaPolicy::empty()
            }),
            warnings: vec![],
        }
    }
    fn warning(kind: CertWarningKind) -> CertWarning {
        CertWarning {
            severity: CertWarningSeverity::Critical,
            kind,
            message: String::new(),
        }
    }
    fn ids(out: &CheckOutput) -> Vec<&'static str> {
        out.findings.iter().map(|f| f.id).collect()
    }

    #[test]
    fn a_good_certificate_with_caa_is_clean() {
        let out = assess("example.com", &report());
        assert!(out.findings.is_empty());
        assert_eq!(out.runs.len(), 2);
    }

    #[test]
    fn warning_kinds_map_to_findings() {
        let mut r = report();
        r.warnings = vec![
            warning(CertWarningKind::Expired),
            warning(CertWarningKind::HostnameMismatch),
            warning(CertWarningKind::SelfSigned),
            warning(CertWarningKind::WeakKey),
            warning(CertWarningKind::DeprecatedSignature),
            warning(CertWarningKind::CaLeaf),
            warning(CertWarningKind::NotYetValid),
            warning(CertWarningKind::ExpiringSoon),
        ];
        let out = assess("example.com", &r);
        assert_eq!(
            ids(&out),
            vec![
                "tls.cert.expired",
                "tls.cert.name-mismatch",
                "tls.cert.self-signed",
                "tls.cert.weak-key",
                "tls.cert.weak-signature",
                "tls.cert.ca-leaf",
                "tls.cert.not-yet-valid",
            ],
            "ExpiringSoon is graded from days_until_expiry, not the warning"
        );
        let severities: Vec<Severity> = out.findings.iter().map(|f| f.severity).collect();
        assert_eq!(
            severities,
            vec![
                Severity::Critical,
                Severity::Critical,
                Severity::High,
                Severity::High,
                Severity::High,
                Severity::Medium,
                Severity::Critical,
            ]
        );
    }

    #[test]
    fn name_mismatch_evidence_caps_the_san_list() {
        let mut r = report();
        r.warnings = vec![warning(CertWarningKind::HostnameMismatch)];
        r.san_names = (1..=8).map(|i| format!("h{i}.example.net")).collect();
        let out = assess("example.com", &r);
        assert_eq!(
            out.findings[0].evidence.as_deref(),
            Some("h1.example.net, h2.example.net, h3.example.net, h4.example.net, h5.example.net, +3 more")
        );
        r.san_names.truncate(2);
        let out = assess("example.com", &r);
        assert_eq!(
            out.findings[0].evidence.as_deref(),
            Some("h1.example.net, h2.example.net")
        );
    }

    #[test]
    fn expiry_windows() {
        let mut r = report();
        r.days_until_expiry = 10;
        let out = assess("example.com", &r);
        assert_eq!(ids(&out), vec!["tls.cert.expiring-14d"]);
        assert_eq!(out.findings[0].severity, Severity::High);
        r.days_until_expiry = 20;
        let out = assess("example.com", &r);
        assert_eq!(ids(&out), vec!["tls.cert.expiring-30d"]);
        assert_eq!(out.findings[0].severity, Severity::Medium);
    }

    #[test]
    fn caa_missing_mismatch_and_unknown() {
        let mut r = report();
        r.caa = Some(CaaPolicy::empty());
        let out = assess("example.com", &r);
        assert_eq!(ids(&out), vec!["tls.caa.missing"]);
        assert_eq!(out.findings[0].severity, Severity::Low);

        r.caa = Some(CaaPolicy {
            has_policy: true,
            issuer_match: Some(IssuerCaaMatch::Mismatch),
            ..CaaPolicy::empty()
        });
        let out = assess("example.com", &r);
        assert_eq!(ids(&out), vec!["tls.caa.issuer-not-listed"]);
        assert_eq!(out.findings[0].severity, Severity::Info);

        r.caa = Some(CaaPolicy {
            lookup_failed: true,
            ..CaaPolicy::empty()
        });
        let out = assess("example.com", &r);
        assert!(out.findings.is_empty());
        assert!(out
            .runs
            .iter()
            .any(|run| run.check == "tls.caa"
                && matches!(run.status, CheckStatus::Incomplete { .. })));
    }
}
