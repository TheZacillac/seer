//! What the origin serves over HTTP(S): security headers and cookies, the
//! port-80 → HTTPS upgrade, and `security.txt`. Three independent fetches,
//! so three specs (one slow origin cannot take the others' results with it).
//!
//! A failed HTTPS connection (refused, unreachable, TLS handshake failure)
//! is a finding — the site is not reachable over HTTPS — reported by the
//! `web.headers` check; any other fetch failure is unknown (incomplete).

use futures::future::BoxFuture;

use super::{AuditContext, CheckOutput, CheckSpec};
use crate::audit::finding::{Category, Finding, Severity};
use crate::headers::{audit_headers_with, HeaderReport, HeaderVerdict};
use crate::http::SendError;
use crate::https_upgrade::{self, HttpsUpgradeReport};
use crate::security_txt::{self, SecurityTxtIssue, SecurityTxtReport};

const W: Category = Category::Web;
const HEADERS_CHECK: &str = "web.headers";
const UPGRADE_CHECK: &str = "web.upgrade";
const SECURITY_TXT_CHECK: &str = "web.security-txt";

pub(crate) const HEADERS: CheckSpec = CheckSpec {
    checks: &[(HEADERS_CHECK, W)],
    run: run_headers,
};
pub(crate) const UPGRADE: CheckSpec = CheckSpec {
    checks: &[(UPGRADE_CHECK, W)],
    run: run_upgrade,
};
pub(crate) const SECURITY_TXT: CheckSpec = CheckSpec {
    checks: &[(SECURITY_TXT_CHECK, W)],
    run: run_security_txt,
};

pub(crate) const IDS: &[&str] = &[
    "web.https.unreachable",
    "web.hsts.missing",
    "web.hsts.weak",
    "web.csp.missing",
    "web.csp.weak",
    "web.frame.missing",
    "web.nosniff.missing",
    "web.cookie.insecure",
    "web.cookie.flags",
    "web.disclosure.banner",
    "web.upgrade.missing",
    "web.security-txt.missing",
    "web.security-txt.expired",
];

fn run_headers<'a>(ctx: &'a AuditContext<'a>) -> BoxFuture<'a, CheckOutput> {
    Box::pin(async move {
        let mut out = CheckOutput::default();
        match audit_headers_with(&ctx.auditor.fetcher(), ctx.host).await {
            Ok(report) => out.ran(HEADERS_CHECK, W, assess_headers(ctx.host, &report)),
            Err(SendError::Connect(_)) => out.ran(HEADERS_CHECK, W, vec![unreachable(ctx.host)]),
            Err(SendError::Other(e)) => out.failed(HEADERS_CHECK, W, &e),
        }
        out
    })
}

fn run_upgrade<'a>(ctx: &'a AuditContext<'a>) -> BoxFuture<'a, CheckOutput> {
    Box::pin(async move {
        let mut out = CheckOutput::default();
        match https_upgrade::check_with(&ctx.auditor.fetcher(), ctx.host).await {
            Ok(r) if !r.listening => {
                out.not_applicable(UPGRADE_CHECK, W, "nothing listens on port 80");
            }
            Ok(r) => out.ran(UPGRADE_CHECK, W, assess_upgrade(ctx.host, &r)),
            Err(e) => out.failed(UPGRADE_CHECK, W, &e),
        }
        out
    })
}

fn run_security_txt<'a>(ctx: &'a AuditContext<'a>) -> BoxFuture<'a, CheckOutput> {
    Box::pin(async move {
        let mut out = CheckOutput::default();
        let url = format!("https://{}/.well-known/security.txt", ctx.host);
        match security_txt::fetch_url(&ctx.auditor.fetcher(), &url, chrono::Utc::now()).await {
            Ok(r) => out.ran(SECURITY_TXT_CHECK, W, assess_security_txt(ctx.host, &r)),
            Err(SendError::Connect(_)) => {
                out.not_applicable(SECURITY_TXT_CHECK, W, "no HTTPS listener");
            }
            Err(SendError::Other(e)) => out.failed(SECURITY_TXT_CHECK, W, &e),
        }
        out
    })
}

/// The finding for a failed HTTPS connection.
pub(crate) fn unreachable(host: &str) -> Finding {
    Finding::new(
        "web.https.unreachable",
        W,
        Severity::High,
        host,
        "HTTPS connection failed (refused, unreachable, or TLS handshake failure)",
    )
    .fix("Serve the site over HTTPS on port 443 with a valid certificate and TLS 1.2+.")
}

fn verdict_of(r: &HeaderReport, name: &str) -> Option<HeaderVerdict> {
    r.headers
        .iter()
        .find(|h| h.header == name)
        .map(|h| h.verdict)
}

/// Maps a header report to findings. Pure.
pub(crate) fn assess_headers(host: &str, r: &HeaderReport) -> Vec<Finding> {
    let mut out = Vec::new();
    let new = |id, severity, title: &str| Finding::new(id, W, severity, host, title);

    match verdict_of(r, "strict-transport-security") {
        Some(HeaderVerdict::Absent) => out.push(
            new("web.hsts.missing", Severity::Medium, "No HSTS header")
                .fix("Send Strict-Transport-Security: max-age=31536000; includeSubDomains."),
        ),
        Some(HeaderVerdict::Weak | HeaderVerdict::Moderate) => out.push(
            new("web.hsts.weak", Severity::Low, "HSTS is weak")
                .fix("Use max-age of at least one year and includeSubDomains."),
        ),
        _ => {}
    }
    match verdict_of(r, "content-security-policy") {
        Some(HeaderVerdict::Absent) => out.push(
            new(
                "web.csp.missing",
                Severity::Medium,
                "No Content-Security-Policy",
            )
            .fix("Add a Content-Security-Policy restricting script sources."),
        ),
        Some(HeaderVerdict::Weak | HeaderVerdict::Moderate) => out.push(
            new(
                "web.csp.weak",
                Severity::Low,
                "Content-Security-Policy is weak or report-only",
            )
            .fix("Remove unsafe-inline/unsafe-eval and enforce the policy."),
        ),
        _ => {}
    }
    if verdict_of(r, "x-frame-options") == Some(HeaderVerdict::Absent) {
        out.push(
            new("web.frame.missing", Severity::Low, "No framing protection")
                .fix("Send X-Frame-Options: DENY or CSP frame-ancestors 'none'."),
        );
    }
    if verdict_of(r, "x-content-type-options") == Some(HeaderVerdict::Absent) {
        out.push(
            new(
                "web.nosniff.missing",
                Severity::Low,
                "No X-Content-Type-Options: nosniff",
            )
            .fix("Send X-Content-Type-Options: nosniff."),
        );
    }

    let insecure: Vec<&str> = r
        .cookies
        .iter()
        .filter(|c| !c.secure)
        .map(|c| c.name.as_str())
        .collect();
    if !insecure.is_empty() {
        out.push(
            new(
                "web.cookie.insecure",
                Severity::Medium,
                "Cookie set without Secure",
            )
            .evidence(insecure.join(", "))
            .fix("Set the Secure flag on every cookie."),
        );
    }
    let loose: Vec<&str> = r
        .cookies
        .iter()
        .filter(|c| !c.http_only || c.same_site.is_none())
        .map(|c| c.name.as_str())
        .collect();
    if !loose.is_empty() {
        out.push(
            new(
                "web.cookie.flags",
                Severity::Low,
                "Cookie missing HttpOnly or SameSite",
            )
            .evidence(loose.join(", "))
            .fix("Set HttpOnly and SameSite=Lax (or Strict) on session cookies."),
        );
    }
    let banners: Vec<String> = r
        .disclosures
        .iter()
        .filter(|d| d.versioned)
        .map(|d| format!("{}: {}", d.header, d.value))
        .collect();
    if !banners.is_empty() {
        out.push(
            new(
                "web.disclosure.banner",
                Severity::Low,
                "Server discloses software versions",
            )
            .evidence(banners.join("; "))
            .fix("Remove version numbers from Server / X-Powered-By headers."),
        );
    }
    out
}

/// Maps an upgrade report (listening on port 80) to findings. Pure.
pub(crate) fn assess_upgrade(host: &str, r: &HttpsUpgradeReport) -> Vec<Finding> {
    if r.upgraded {
        return Vec::new();
    }
    let evidence = if r.cross_domain {
        format!(
            "redirects to another domain: {}",
            r.chain.last().map_or("", String::as_str)
        )
    } else {
        "served over plain HTTP".to_string()
    };
    vec![Finding::new(
        "web.upgrade.missing",
        W,
        Severity::Medium,
        host,
        "HTTP does not redirect to HTTPS",
    )
    .evidence(evidence)
    .fix("Redirect every http:// request to https:// on the same host (301).")]
}

/// Maps a security.txt report to findings. Pure.
pub(crate) fn assess_security_txt(host: &str, r: &SecurityTxtReport) -> Vec<Finding> {
    if !r.is_valid() {
        let evidence = r
            .issues
            .iter()
            .map(|i| match i {
                SecurityTxtIssue::NotFound => "not found",
                SecurityTxtIssue::NotPlainText => "served HTML, not text/plain",
                SecurityTxtIssue::MissingContact => "missing Contact",
                SecurityTxtIssue::MissingExpires => "missing Expires",
                SecurityTxtIssue::InvalidExpires => "invalid Expires",
                SecurityTxtIssue::MultipleExpires => "more than one Expires",
            })
            .collect::<Vec<_>>()
            .join(", ");
        return vec![Finding::new(
            "web.security-txt.missing",
            W,
            Severity::Low,
            host,
            "No valid security.txt",
        )
        .evidence(evidence)
        .fix("Publish /.well-known/security.txt with Contact and Expires (RFC 9116).")];
    }
    if r.expired {
        return vec![Finding::new(
            "web.security-txt.expired",
            W,
            Severity::Low,
            host,
            "security.txt has expired",
        )
        .fix("Update the Expires field (keep it under a year ahead).")];
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headers::{CookieFinding, Disclosure, HeaderFinding};

    fn header(name: &str, verdict: HeaderVerdict) -> HeaderFinding {
        HeaderFinding {
            header: name.into(),
            present: verdict != HeaderVerdict::Absent,
            value: None,
            verdict,
            note: None,
        }
    }
    fn report(headers: Vec<HeaderFinding>) -> HeaderReport {
        HeaderReport {
            domain: "example.com".into(),
            url: "https://example.com/".into(),
            status: 200,
            redirects: 0,
            grade: "A".into(),
            score: 90,
            headers,
            cookies: vec![],
            disclosures: vec![],
            notes: vec![],
        }
    }
    fn strict_all() -> Vec<HeaderFinding> {
        [
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
        ]
        .iter()
        .map(|h| header(h, HeaderVerdict::Strict))
        .collect()
    }
    fn ids(f: &[Finding]) -> Vec<&'static str> {
        f.iter().map(|f| f.id).collect()
    }

    #[test]
    fn hardened_headers_are_clean() {
        assert!(assess_headers("example.com", &report(strict_all())).is_empty());
    }

    #[test]
    fn missing_and_weak_headers() {
        let r = report(vec![
            header("strict-transport-security", HeaderVerdict::Absent),
            header("content-security-policy", HeaderVerdict::Weak),
            header("x-frame-options", HeaderVerdict::Absent),
            header("x-content-type-options", HeaderVerdict::Absent),
        ]);
        let f = assess_headers("example.com", &r);
        assert_eq!(
            ids(&f),
            vec![
                "web.hsts.missing",
                "web.csp.weak",
                "web.frame.missing",
                "web.nosniff.missing"
            ]
        );
        assert_eq!(f[0].severity, Severity::Medium);
        assert_eq!(f[1].severity, Severity::Low);
    }

    #[test]
    fn cookies_and_banners() {
        let mut r = report(strict_all());
        r.cookies = vec![
            CookieFinding {
                name: "sid".into(),
                secure: false,
                http_only: true,
                same_site: Some("Lax".into()),
                verdict: HeaderVerdict::Weak,
                issues: vec![],
            },
            CookieFinding {
                name: "pref".into(),
                secure: true,
                http_only: false,
                same_site: None,
                verdict: HeaderVerdict::Weak,
                issues: vec![],
            },
        ];
        r.disclosures = vec![Disclosure {
            header: "server".into(),
            value: "nginx/1.25.3".into(),
            versioned: true,
        }];
        let f = assess_headers("example.com", &r);
        assert_eq!(
            ids(&f),
            vec![
                "web.cookie.insecure",
                "web.cookie.flags",
                "web.disclosure.banner"
            ]
        );
        assert_eq!(f[0].evidence.as_deref(), Some("sid"));
    }

    #[test]
    fn connect_failure_reports_https_connection_failed() {
        let f = unreachable("example.com");
        assert_eq!(f.id, "web.https.unreachable");
        assert_eq!(f.severity, Severity::High);
        assert!(f.title.contains("HTTPS connection"), "{}", f.title);
    }

    #[test]
    fn upgrade_findings() {
        let ok = HttpsUpgradeReport {
            host: "example.com".into(),
            listening: true,
            chain: vec!["http://example.com/".into(), "https://example.com/".into()],
            upgraded: true,
            first_hop_https: true,
            cross_domain: false,
        };
        assert!(assess_upgrade("example.com", &ok).is_empty());
        let plain = HttpsUpgradeReport {
            upgraded: false,
            first_hop_https: false,
            chain: vec!["http://example.com/".into()],
            ..ok.clone()
        };
        assert_eq!(
            ids(&assess_upgrade("example.com", &plain)),
            vec!["web.upgrade.missing"]
        );
    }

    #[test]
    fn security_txt_findings() {
        let base = SecurityTxtReport {
            url: "https://example.com/.well-known/security.txt".into(),
            found: true,
            contact: vec!["mailto:a@example.com".into()],
            expires: None,
            expired: false,
            signed: false,
            issues: vec![],
        };
        assert!(assess_security_txt("example.com", &base).is_empty());
        let missing = SecurityTxtReport {
            found: false,
            issues: vec![SecurityTxtIssue::NotFound],
            ..base.clone()
        };
        assert_eq!(
            ids(&assess_security_txt("example.com", &missing)),
            vec!["web.security-txt.missing"]
        );
        let invalid = SecurityTxtReport {
            issues: vec![SecurityTxtIssue::MissingContact],
            ..base.clone()
        };
        assert_eq!(
            ids(&assess_security_txt("example.com", &invalid)),
            vec!["web.security-txt.missing"]
        );
        let expired = SecurityTxtReport {
            expired: true,
            ..base
        };
        assert_eq!(
            ids(&assess_security_txt("example.com", &expired)),
            vec!["web.security-txt.expired"]
        );
    }

    #[test]
    fn every_emitted_id_is_declared() {
        let r = report(vec![
            header("strict-transport-security", HeaderVerdict::Absent),
            header("content-security-policy", HeaderVerdict::Absent),
        ]);
        let mut all = assess_headers("example.com", &r);
        all.push(unreachable("example.com"));
        assert!(all.iter().all(|f| IDS.contains(&f.id)));
    }
}
