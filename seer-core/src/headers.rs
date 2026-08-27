//! HTTP security-header and cookie audit.
//!
//! Seer already inspects a domain's transport layer ([`crate::ssl`],
//! [`crate::caa`]), its DNS/email layer ([`crate::posture`], [`crate::dns`]),
//! and its registration layer ([`crate::whois`], [`crate::rdap`]). This module
//! covers the remaining one: what the origin actually sends back over HTTP.
//!
//! A single SSRF-guarded GET (see [`crate::http`]) is issued against
//! `https://<domain>`, and the response is graded on three axes:
//!
//! - **Security headers** — HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
//!   Referrer-Policy, Permissions-Policy, and the cross-origin isolation trio
//!   (COOP/COEP/CORP). Each gets a [`HeaderVerdict`] plus an advisory note
//!   explaining *why* it scored what it did.
//! - **Cookies** — every `Set-Cookie` is checked for `Secure`, `HttpOnly`, and
//!   `SameSite`, the flags whose absence turns a session cookie into an XSS or
//!   CSRF primitive.
//! - **Disclosure** — `Server`/`X-Powered-By`-style banners that hand an
//!   attacker a version number to match against a CVE list.
//!
//! The verdict scale mirrors [`crate::posture::PostureVerdict`] so the two
//! security reports read the same way. Scoring is a weighted sum over the
//! headers plus bounded penalties for cookie and disclosure findings, mapped to
//! a letter grade.
//!
//! Deliberately **one request, no probing**: this reports what the origin
//! volunteers to any ordinary visitor. It sends no crafted payloads, tries no
//! paths, and never authenticates — the same non-intrusive stance as
//! [`crate::status`]. All grading is pure and unit-tested; only the fetch is
//! async.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::http::{FetchedResponse, GuardedFetcher};
use crate::validation::normalize_domain;

/// A coarse enforcement verdict for one header or cookie.
///
/// Mirrors [`crate::posture::PostureVerdict`] so `seer headers` and
/// `seer posture` grade on the same scale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HeaderVerdict {
    /// Not sent at all.
    Absent,
    /// Sent, but configured so permissively it offers little protection.
    Weak,
    /// Sent with partial protection.
    Moderate,
    /// Sent with full protection.
    Strict,
    /// Sent; the mechanism has no weak/strict axis (presence is the signal).
    Present,
}

impl HeaderVerdict {
    /// Fraction of a header's weight this verdict earns, in percent. Integer
    /// math keeps scoring exactly reproducible across platforms.
    fn score_pct(self) -> u32 {
        match self {
            HeaderVerdict::Strict | HeaderVerdict::Present => 100,
            HeaderVerdict::Moderate => 60,
            HeaderVerdict::Weak => 30,
            HeaderVerdict::Absent => 0,
        }
    }
}

/// The audit result for one security header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderFinding {
    /// Lowercase header name, e.g. `strict-transport-security`.
    pub header: String,
    pub present: bool,
    /// The raw value as sent (untrusted — sanitize before display).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    pub verdict: HeaderVerdict,
    /// Why this verdict, and what would improve it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// The audit result for one `Set-Cookie`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieFinding {
    pub name: String,
    pub secure: bool,
    pub http_only: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub same_site: Option<String>,
    pub verdict: HeaderVerdict,
    /// The specific flags that are missing or unsafe.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub issues: Vec<String>,
}

/// A header that discloses software or version information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Disclosure {
    pub header: String,
    pub value: String,
    /// True when the value carries something that looks like a version number,
    /// which is what makes a banner CVE-matchable rather than merely noisy.
    pub versioned: bool,
}

/// The full HTTP security-header audit for a domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderReport {
    pub domain: String,
    /// The URL that finally answered, after redirects.
    pub url: String,
    pub status: u16,
    /// Number of redirect hops followed to reach `url`.
    pub redirects: usize,
    /// Letter grade derived from `score` (A+ through F).
    pub grade: String,
    /// 0–100 weighted score.
    pub score: u32,
    pub headers: Vec<HeaderFinding>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cookies: Vec<CookieFinding>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub disclosures: Vec<Disclosure>,
    /// Ranked advisory findings, worst first.
    pub notes: Vec<String>,
}

/// Default per-audit HTTP timeout, for callers with no configured value of
/// their own (the Python bindings). The CLI passes `config.http_timeout()`.
pub const DEFAULT_HEADER_TIMEOUT: Duration = Duration::from_secs(10);

/// Per-header weights, summing to 100. Ordering here is also the display order.
///
/// The weighting reflects blast radius: HSTS and CSP each defend against a
/// whole class of attack (transport downgrade, injected script), framing and
/// MIME-sniffing controls defend against one well-understood attack each, and
/// the cross-origin isolation trio is a smaller, more situational hardening
/// step that most sites legitimately do not need.
const HEADER_WEIGHTS: &[(&str, u32)] = &[
    ("strict-transport-security", 20),
    ("content-security-policy", 20),
    ("x-frame-options", 15),
    ("x-content-type-options", 10),
    ("referrer-policy", 10),
    ("permissions-policy", 10),
    ("cross-origin-opener-policy", 5),
    ("cross-origin-embedder-policy", 5),
    ("cross-origin-resource-policy", 5),
];

/// HSTS `max-age` at or above which the policy is considered fully enforcing
/// (1 year — the floor the browser preload lists require).
const HSTS_STRONG_MAX_AGE: u64 = 31_536_000;
/// HSTS `max-age` below which the window is too short to be meaningful
/// (6 months).
const HSTS_MODERATE_MAX_AGE: u64 = 15_552_000;

/// Penalty per cookie missing a protective flag, and the cap on that penalty.
const COOKIE_PENALTY: u32 = 4;
const COOKIE_PENALTY_CAP: u32 = 12;
/// Penalty per version-disclosing banner, and the cap on that penalty.
const DISCLOSURE_PENALTY: u32 = 3;
const DISCLOSURE_PENALTY_CAP: u32 = 6;

// --- Pure grading ------------------------------------------------------

/// Splits a `k=v; k; k=v` header (HSTS, Set-Cookie, CSP directive) into
/// lowercased-key / raw-value pairs. Valueless attributes map to an empty
/// string, so `HttpOnly` and `Secure` are found by key alone.
fn parse_attributes(value: &str) -> Vec<(String, String)> {
    value
        .split(';')
        .filter_map(|part| {
            let part = part.trim();
            if part.is_empty() {
                return None;
            }
            Some(match part.split_once('=') {
                Some((k, v)) => (k.trim().to_ascii_lowercase(), v.trim().to_string()),
                None => (part.to_ascii_lowercase(), String::new()),
            })
        })
        .collect()
}

/// Looks up an attribute by lowercase key.
fn attr<'a>(attrs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn grade_hsts(value: Option<&str>) -> (HeaderVerdict, Option<String>) {
    let Some(value) = value else {
        return (
            HeaderVerdict::Absent,
            Some("Add Strict-Transport-Security to stop protocol-downgrade and cookie-stripping attacks.".into()),
        );
    };
    let attrs = parse_attributes(value);
    let max_age: Option<u64> = attr(&attrs, "max-age").and_then(|v| v.trim().parse().ok());
    let include_subdomains = attr(&attrs, "includesubdomains").is_some();

    match max_age {
        None | Some(0) => (
            HeaderVerdict::Weak,
            Some("max-age is missing or zero, which disables HSTS entirely.".into()),
        ),
        Some(age) if age >= HSTS_STRONG_MAX_AGE && include_subdomains => {
            (HeaderVerdict::Strict, None)
        }
        Some(age) if age >= HSTS_STRONG_MAX_AGE => (
            HeaderVerdict::Moderate,
            Some("max-age is strong but includeSubDomains is missing — subdomains stay downgradable.".into()),
        ),
        Some(age) if age >= HSTS_MODERATE_MAX_AGE => (
            HeaderVerdict::Moderate,
            Some(format!(
                "max-age={age} is below the 31536000 (1 year) that preload requires."
            )),
        ),
        Some(age) => (
            HeaderVerdict::Weak,
            Some(format!(
                "max-age={age} is a short window; use at least 15552000 (6 months)."
            )),
        ),
    }
}

fn grade_csp(value: Option<&str>, report_only: bool) -> (HeaderVerdict, Option<String>) {
    let Some(value) = value else {
        if report_only {
            return (
                HeaderVerdict::Weak,
                Some("Only Content-Security-Policy-Report-Only is set — it reports violations but blocks nothing.".into()),
            );
        }
        return (
            HeaderVerdict::Absent,
            Some(
                "Add Content-Security-Policy — it is the primary defense against injected script."
                    .into(),
            ),
        );
    };

    let lower = value.to_ascii_lowercase();
    let unsafe_inline = lower.contains("'unsafe-inline'");
    let unsafe_eval = lower.contains("'unsafe-eval'");
    let has_baseline = lower.contains("default-src") || lower.contains("script-src");

    if unsafe_inline || unsafe_eval {
        let mut which = Vec::new();
        if unsafe_inline {
            which.push("'unsafe-inline'");
        }
        if unsafe_eval {
            which.push("'unsafe-eval'");
        }
        return (
            HeaderVerdict::Weak,
            Some(format!(
                "Policy allows {} — this reopens the injection hole CSP exists to close.",
                which.join(" and ")
            )),
        );
    }

    if !has_baseline {
        return (
            HeaderVerdict::Moderate,
            Some("Policy sets neither default-src nor script-src, so script loading is unrestricted.".into()),
        );
    }

    (HeaderVerdict::Strict, None)
}

fn grade_frame_options(value: Option<&str>, csp: Option<&str>) -> (HeaderVerdict, Option<String>) {
    // CSP frame-ancestors supersedes X-Frame-Options in every current browser;
    // a site that sets it is protected even with no XFO header at all.
    let csp_frame_ancestors = csp
        .map(|c| c.to_ascii_lowercase().contains("frame-ancestors"))
        .unwrap_or(false);

    let Some(value) = value else {
        if csp_frame_ancestors {
            return (
                HeaderVerdict::Present,
                Some(
                    "No X-Frame-Options, but CSP frame-ancestors is set, which supersedes it."
                        .into(),
                ),
            );
        }
        return (
            HeaderVerdict::Absent,
            Some(
                "Add X-Frame-Options (or CSP frame-ancestors) to prevent clickjacking via framing."
                    .into(),
            ),
        );
    };

    match value.trim().to_ascii_uppercase().as_str() {
        "DENY" | "SAMEORIGIN" => (HeaderVerdict::Strict, None),
        v if v.starts_with("ALLOW-FROM") => (
            HeaderVerdict::Weak,
            Some(
                "ALLOW-FROM is obsolete and ignored by modern browsers; use CSP frame-ancestors."
                    .into(),
            ),
        ),
        other => (
            HeaderVerdict::Weak,
            Some(format!(
                "Unrecognized value '{other}' — use DENY or SAMEORIGIN."
            )),
        ),
    }
}

fn grade_content_type_options(value: Option<&str>) -> (HeaderVerdict, Option<String>) {
    match value.map(|v| v.trim().to_ascii_lowercase()) {
        None => (
            HeaderVerdict::Absent,
            Some(
                "Add X-Content-Type-Options: nosniff to stop MIME-sniffing of user-supplied files."
                    .into(),
            ),
        ),
        Some(ref v) if v == "nosniff" => (HeaderVerdict::Strict, None),
        Some(other) => (
            HeaderVerdict::Weak,
            Some(format!(
                "Value '{other}' is not recognized; the only valid value is nosniff."
            )),
        ),
    }
}

fn grade_referrer_policy(value: Option<&str>) -> (HeaderVerdict, Option<String>) {
    let Some(value) = value else {
        return (
            HeaderVerdict::Absent,
            Some(
                "Add Referrer-Policy so URLs (and any secrets in them) do not leak cross-origin."
                    .into(),
            ),
        );
    };
    // A list picks the last token the browser understands; grading the
    // strongest present token is a close, simpler approximation.
    let tokens: Vec<String> = value
        .split(',')
        .map(|t| t.trim().to_ascii_lowercase())
        .collect();

    let strict = [
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    ];
    let moderate = [
        "origin",
        "origin-when-cross-origin",
        "no-referrer-when-downgrade",
    ];

    if tokens.iter().any(|t| strict.contains(&t.as_str())) {
        (HeaderVerdict::Strict, None)
    } else if tokens.iter().any(|t| moderate.contains(&t.as_str())) {
        (
            HeaderVerdict::Moderate,
            Some("Policy still sends the origin cross-site; strict-origin-when-cross-origin is tighter.".into()),
        )
    } else if tokens.iter().any(|t| t == "unsafe-url") {
        (
            HeaderVerdict::Weak,
            Some(
                "unsafe-url sends the full URL to every destination, including over plain HTTP."
                    .into(),
            ),
        )
    } else {
        (
            HeaderVerdict::Weak,
            Some(format!("Unrecognized policy '{}'.", value.trim())),
        )
    }
}

/// Grades a header whose presence is the whole signal (Permissions-Policy).
fn grade_presence(value: Option<&str>, advice: &str) -> (HeaderVerdict, Option<String>) {
    match value {
        Some(v) if !v.trim().is_empty() => (HeaderVerdict::Present, None),
        _ => (HeaderVerdict::Absent, Some(advice.to_string())),
    }
}

/// Grades a header against an ordered `(value, verdict)` table.
fn grade_enum(
    value: Option<&str>,
    table: &[(&str, HeaderVerdict)],
    absent_advice: &str,
) -> (HeaderVerdict, Option<String>) {
    let Some(value) = value else {
        return (HeaderVerdict::Absent, Some(absent_advice.to_string()));
    };
    let v = value.trim().to_ascii_lowercase();
    match table.iter().find(|(k, _)| *k == v) {
        Some((_, verdict)) => (*verdict, None),
        None => (
            HeaderVerdict::Weak,
            Some(format!("Unrecognized value '{}'.", value.trim())),
        ),
    }
}

/// Grades every `Set-Cookie` on the response.
fn grade_cookies(cookies: &[String]) -> Vec<CookieFinding> {
    cookies
        .iter()
        .map(|raw| {
            let attrs = parse_attributes(raw);
            // The first pair is `name=value`; everything after is attributes.
            // Take the name from the raw header rather than the parsed attrs:
            // cookie names are case-sensitive, and `parse_attributes`
            // lowercases keys so attribute lookups can be case-insensitive.
            let name = raw
                .split(';')
                .next()
                .map(|first| first.split_once('=').map_or(first, |(k, _)| k).trim())
                .filter(|n| !n.is_empty())
                .unwrap_or("(unnamed)")
                .to_string();

            let secure = attr(&attrs, "secure").is_some();
            let http_only = attr(&attrs, "httponly").is_some();
            let same_site = attr(&attrs, "samesite").map(|v| v.to_string());

            let mut issues = Vec::new();
            if !secure {
                issues.push("missing Secure (may be sent over plain HTTP)".to_string());
            }
            if !http_only {
                issues.push("missing HttpOnly (readable by JavaScript/XSS)".to_string());
            }
            match same_site.as_deref().map(|s| s.to_ascii_lowercase()) {
                None => issues.push("missing SameSite (CSRF exposure)".to_string()),
                Some(ref s) if s == "none" && !secure => {
                    issues.push("SameSite=None without Secure is rejected by browsers".to_string());
                }
                _ => {}
            }

            let verdict = match issues.len() {
                0 => HeaderVerdict::Strict,
                1 => HeaderVerdict::Moderate,
                _ => HeaderVerdict::Weak,
            };

            CookieFinding {
                name,
                secure,
                http_only,
                same_site,
                verdict,
                issues,
            }
        })
        .collect()
}

/// True when a banner carries something version-shaped (`nginx/1.25.3`,
/// `PHP/8.2`), which is what makes it CVE-matchable.
fn looks_versioned(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.windows(2).any(|w| {
        // A digit adjacent to '/' or '.' is the shape of a version token.
        (w[0] == b'/' && w[1].is_ascii_digit())
            || (w[0].is_ascii_digit() && w[1] == b'.')
            || (w[0] == b'.' && w[1].is_ascii_digit())
    })
}

/// Headers that routinely leak software identity.
const DISCLOSURE_HEADERS: &[&str] = &[
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
];

fn collect_disclosures(response: &FetchedResponse) -> Vec<Disclosure> {
    DISCLOSURE_HEADERS
        .iter()
        .filter_map(|name| {
            let value = response.header(name)?;
            if value.trim().is_empty() {
                return None;
            }
            Some(Disclosure {
                header: (*name).to_string(),
                value: value.to_string(),
                versioned: looks_versioned(value),
            })
        })
        .collect()
}

/// Computes the 0–100 score from the graded headers plus bounded penalties.
fn compute_score(
    headers: &[HeaderFinding],
    cookies: &[CookieFinding],
    disclosures: &[Disclosure],
) -> u32 {
    let earned: u32 = headers
        .iter()
        .map(|f| {
            let weight = HEADER_WEIGHTS
                .iter()
                .find(|(name, _)| *name == f.header)
                .map(|(_, w)| *w)
                .unwrap_or(0);
            weight * f.verdict.score_pct() / 100
        })
        .sum();

    let cookie_penalty = (cookies.iter().filter(|c| !c.issues.is_empty()).count() as u32
        * COOKIE_PENALTY)
        .min(COOKIE_PENALTY_CAP);

    let disclosure_penalty = (disclosures.iter().filter(|d| d.versioned).count() as u32
        * DISCLOSURE_PENALTY)
        .min(DISCLOSURE_PENALTY_CAP);

    earned.saturating_sub(cookie_penalty + disclosure_penalty)
}

/// Maps a score to a letter grade.
fn grade_letter(score: u32) -> &'static str {
    match score {
        95..=u32::MAX => "A+",
        85..=94 => "A",
        75..=84 => "B",
        65..=74 => "C",
        50..=64 => "D",
        30..=49 => "E",
        _ => "F",
    }
}

/// Builds the ranked advisory list from the graded findings.
fn build_notes(
    headers: &[HeaderFinding],
    cookies: &[CookieFinding],
    disclosures: &[Disclosure],
) -> Vec<String> {
    let mut notes = Vec::new();

    // Missing headers first, in weight order (HEADER_WEIGHTS order), so the
    // highest-impact gap is the first thing an operator reads.
    for finding in headers {
        if let Some(note) = &finding.note {
            notes.push(format!("{}: {}", finding.header, note));
        }
    }

    for cookie in cookies {
        if !cookie.issues.is_empty() {
            notes.push(format!(
                "cookie '{}': {}",
                cookie.name,
                cookie.issues.join("; ")
            ));
        }
    }

    for d in disclosures.iter().filter(|d| d.versioned) {
        notes.push(format!(
            "{} discloses a version ('{}') — an attacker can match it against known CVEs.",
            d.header, d.value
        ));
    }

    notes
}

/// Grades an already-fetched response. Pure, so the whole ruleset is
/// unit-testable without any network.
fn build_report(domain: String, response: &FetchedResponse) -> HeaderReport {
    let csp = response.header("content-security-policy");
    let csp_report_only = response
        .header("content-security-policy-report-only")
        .is_some();

    let graded: Vec<(&str, (HeaderVerdict, Option<String>))> = vec![
        (
            "strict-transport-security",
            grade_hsts(response.header("strict-transport-security")),
        ),
        ("content-security-policy", grade_csp(csp, csp_report_only)),
        (
            "x-frame-options",
            grade_frame_options(response.header("x-frame-options"), csp),
        ),
        (
            "x-content-type-options",
            grade_content_type_options(response.header("x-content-type-options")),
        ),
        (
            "referrer-policy",
            grade_referrer_policy(response.header("referrer-policy")),
        ),
        (
            "permissions-policy",
            grade_presence(
                response.header("permissions-policy"),
                "Add Permissions-Policy to disable powerful browser features the site does not use.",
            ),
        ),
        (
            "cross-origin-opener-policy",
            grade_enum(
                response.header("cross-origin-opener-policy"),
                &[
                    ("same-origin", HeaderVerdict::Strict),
                    ("same-origin-allow-popups", HeaderVerdict::Moderate),
                    ("unsafe-none", HeaderVerdict::Weak),
                ],
                "Add Cross-Origin-Opener-Policy: same-origin to isolate the browsing context.",
            ),
        ),
        (
            "cross-origin-embedder-policy",
            grade_enum(
                response.header("cross-origin-embedder-policy"),
                &[
                    ("require-corp", HeaderVerdict::Strict),
                    ("credentialless", HeaderVerdict::Strict),
                    ("unsafe-none", HeaderVerdict::Weak),
                ],
                "Add Cross-Origin-Embedder-Policy: require-corp to block un-opted-in cross-origin loads.",
            ),
        ),
        (
            "cross-origin-resource-policy",
            grade_enum(
                response.header("cross-origin-resource-policy"),
                &[
                    ("same-origin", HeaderVerdict::Strict),
                    ("same-site", HeaderVerdict::Moderate),
                    ("cross-origin", HeaderVerdict::Weak),
                ],
                "Add Cross-Origin-Resource-Policy to control who may embed this origin's resources.",
            ),
        ),
    ];

    // Emit in HEADER_WEIGHTS order so display, notes, and scoring agree.
    let headers: Vec<HeaderFinding> = HEADER_WEIGHTS
        .iter()
        .filter_map(|(name, _)| {
            let (_, (verdict, note)) = graded.iter().find(|(n, _)| n == name)?;
            let value = response.header(name).map(|v| v.to_string());
            Some(HeaderFinding {
                header: (*name).to_string(),
                present: value.is_some(),
                value,
                verdict: *verdict,
                note: note.clone(),
            })
        })
        .collect();

    let set_cookies: Vec<String> = response
        .header_all("set-cookie")
        .map(|v| v.to_string())
        .collect();
    let cookies = grade_cookies(&set_cookies);
    let disclosures = collect_disclosures(response);

    let score = compute_score(&headers, &cookies, &disclosures);
    let notes = build_notes(&headers, &cookies, &disclosures);

    HeaderReport {
        domain,
        url: response.final_url.clone(),
        status: response.status,
        redirects: response.redirects,
        grade: grade_letter(score).to_string(),
        score,
        headers,
        cookies,
        disclosures,
        notes,
    }
}

/// Audits the HTTP security headers served by `domain`.
///
/// Issues a single SSRF-guarded `GET https://<domain>/`, following redirects
/// (each one re-validated) and grading the response that finally answers.
///
/// # Arguments
/// * `domain` - Domain to audit (normalized internally)
/// * `timeout` - Per-hop HTTP timeout
///
/// # Returns
/// * `Ok(HeaderReport)` - the graded audit
/// * `Err(SeerError::InvalidDomain)` - the domain is not valid
/// * `Err(SeerError::HttpError)` - the host is SSRF-blocked or unreachable
///
/// # Example
/// ```no_run
/// # async fn demo() -> seer_core::Result<()> {
/// use std::time::Duration;
/// let report = seer_core::headers::audit_headers("example.com", Duration::from_secs(10)).await?;
/// println!("{} scored {}", report.domain, report.grade);
/// # Ok(())
/// # }
/// ```
pub async fn audit_headers(domain: &str, timeout: Duration) -> Result<HeaderReport> {
    let domain = normalize_domain(domain)?;
    let fetcher = GuardedFetcher::new().with_timeout(timeout);
    let response = fetcher.get(&format!("https://{domain}/")).await?;
    Ok(build_report(domain, &response))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a synthetic response so the grading rules can be tested without
    /// any network.
    fn response_with(headers: &[(&str, &str)]) -> FetchedResponse {
        FetchedResponse {
            final_url: "https://example.com/".to_string(),
            status: 200,
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_ascii_lowercase(), v.to_string()))
                .collect(),
            body: String::new(),
            redirects: 0,
        }
    }

    #[test]
    fn hsts_grading_bands() {
        assert_eq!(grade_hsts(None).0, HeaderVerdict::Absent);
        assert_eq!(
            grade_hsts(Some("max-age=31536000; includeSubDomains")).0,
            HeaderVerdict::Strict
        );
        // Strong max-age but no includeSubDomains leaves subdomains exposed.
        assert_eq!(
            grade_hsts(Some("max-age=31536000")).0,
            HeaderVerdict::Moderate
        );
        assert_eq!(
            grade_hsts(Some("max-age=15552000; includeSubDomains")).0,
            HeaderVerdict::Moderate
        );
        assert_eq!(grade_hsts(Some("max-age=300")).0, HeaderVerdict::Weak);
        // max-age=0 actively disables HSTS.
        assert_eq!(grade_hsts(Some("max-age=0")).0, HeaderVerdict::Weak);
        assert_eq!(grade_hsts(Some("includeSubDomains")).0, HeaderVerdict::Weak);
    }

    #[test]
    fn csp_unsafe_directives_are_weak() {
        assert_eq!(
            grade_csp(Some("default-src 'self' 'unsafe-inline'"), false).0,
            HeaderVerdict::Weak
        );
        assert_eq!(
            grade_csp(Some("script-src 'unsafe-eval'"), false).0,
            HeaderVerdict::Weak
        );
        assert_eq!(
            grade_csp(Some("default-src 'self'"), false).0,
            HeaderVerdict::Strict
        );
        // A policy with no script-governing directive restricts nothing.
        assert_eq!(
            grade_csp(Some("img-src 'self'"), false).0,
            HeaderVerdict::Moderate
        );
        assert_eq!(grade_csp(None, false).0, HeaderVerdict::Absent);
        // Report-Only alone blocks nothing, but is better than silence.
        assert_eq!(grade_csp(None, true).0, HeaderVerdict::Weak);
    }

    #[test]
    fn csp_frame_ancestors_substitutes_for_x_frame_options() {
        // Modern browsers honor frame-ancestors over XFO, so a site using it
        // must not be marked as missing clickjacking protection.
        let (verdict, note) =
            grade_frame_options(None, Some("default-src 'self'; frame-ancestors 'none'"));
        assert_eq!(verdict, HeaderVerdict::Present);
        assert!(note.unwrap_or_default().contains("frame-ancestors"));

        // Without either, it is a real gap.
        assert_eq!(
            grade_frame_options(None, Some("default-src 'self'")).0,
            HeaderVerdict::Absent
        );
        assert_eq!(
            grade_frame_options(Some("DENY"), None).0,
            HeaderVerdict::Strict
        );
        assert_eq!(
            grade_frame_options(Some("SAMEORIGIN"), None).0,
            HeaderVerdict::Strict
        );
        // ALLOW-FROM is obsolete and silently ignored.
        assert_eq!(
            grade_frame_options(Some("ALLOW-FROM https://x.com"), None).0,
            HeaderVerdict::Weak
        );
    }

    #[test]
    fn referrer_policy_bands() {
        assert_eq!(
            grade_referrer_policy(Some("strict-origin-when-cross-origin")).0,
            HeaderVerdict::Strict
        );
        assert_eq!(
            grade_referrer_policy(Some("no-referrer")).0,
            HeaderVerdict::Strict
        );
        assert_eq!(
            grade_referrer_policy(Some("origin")).0,
            HeaderVerdict::Moderate
        );
        assert_eq!(
            grade_referrer_policy(Some("unsafe-url")).0,
            HeaderVerdict::Weak
        );
        // A fallback list is graded on its strongest understood token.
        assert_eq!(
            grade_referrer_policy(Some("no-referrer, strict-origin-when-cross-origin")).0,
            HeaderVerdict::Strict
        );
        assert_eq!(grade_referrer_policy(None).0, HeaderVerdict::Absent);
    }

    #[test]
    fn content_type_options_only_accepts_nosniff() {
        assert_eq!(
            grade_content_type_options(Some("nosniff")).0,
            HeaderVerdict::Strict
        );
        assert_eq!(
            grade_content_type_options(Some("NOSNIFF")).0,
            HeaderVerdict::Strict
        );
        assert_eq!(
            grade_content_type_options(Some("sniff")).0,
            HeaderVerdict::Weak
        );
        assert_eq!(grade_content_type_options(None).0, HeaderVerdict::Absent);
    }

    #[test]
    fn cookie_names_preserve_case() {
        // Cookie names are case-sensitive; reporting JSESSIONID as
        // "jsessionid" would misname the cookie an operator has to go fix.
        let findings = grade_cookies(&[
            "JSESSIONID=abc; Secure".to_string(),
            "WMF-Last-Access=1; Secure; HttpOnly".to_string(),
        ]);
        assert_eq!(findings[0].name, "JSESSIONID");
        assert_eq!(findings[1].name, "WMF-Last-Access");
        // Attribute matching stays case-insensitive.
        assert!(findings[1].secure);
        assert!(findings[1].http_only);
    }

    #[test]
    fn cookie_flags_are_graded_and_named() {
        let findings = grade_cookies(&[
            "session=abc; Secure; HttpOnly; SameSite=Strict".to_string(),
            "tracker=xyz".to_string(),
            "mixed=1; Secure".to_string(),
        ]);
        assert_eq!(findings[0].name, "session");
        assert_eq!(findings[0].verdict, HeaderVerdict::Strict);
        assert!(findings[0].issues.is_empty());

        // Missing all three protective flags.
        assert_eq!(findings[1].name, "tracker");
        assert_eq!(findings[1].verdict, HeaderVerdict::Weak);
        assert_eq!(findings[1].issues.len(), 3);

        // Secure only → missing HttpOnly and SameSite.
        assert_eq!(findings[2].verdict, HeaderVerdict::Weak);
        assert!(findings[2].secure);
        assert!(!findings[2].http_only);
    }

    #[test]
    fn same_site_none_without_secure_is_flagged() {
        let findings = grade_cookies(&["c=1; HttpOnly; SameSite=None".to_string()]);
        assert!(
            findings[0]
                .issues
                .iter()
                .any(|i| i.contains("SameSite=None without Secure")),
            "got {:?}",
            findings[0].issues
        );
    }

    #[test]
    fn version_disclosure_detection() {
        assert!(looks_versioned("nginx/1.25.3"));
        assert!(looks_versioned("PHP/8.2.1"));
        assert!(looks_versioned("Apache/2.4"));
        // A bare product name is noise, not a CVE-matchable banner.
        assert!(!looks_versioned("cloudflare"));
        assert!(!looks_versioned("nginx"));
    }

    #[test]
    fn perfect_headers_score_a_plus() {
        let response = response_with(&[
            (
                "strict-transport-security",
                "max-age=63072000; includeSubDomains; preload",
            ),
            ("content-security-policy", "default-src 'self'"),
            ("x-frame-options", "DENY"),
            ("x-content-type-options", "nosniff"),
            ("referrer-policy", "no-referrer"),
            ("permissions-policy", "geolocation=()"),
            ("cross-origin-opener-policy", "same-origin"),
            ("cross-origin-embedder-policy", "require-corp"),
            ("cross-origin-resource-policy", "same-origin"),
        ]);
        let report = build_report("example.com".to_string(), &response);
        assert_eq!(report.score, 100, "notes: {:?}", report.notes);
        assert_eq!(report.grade, "A+");
        assert!(report.notes.is_empty(), "got {:?}", report.notes);
    }

    #[test]
    fn bare_response_scores_f_and_lists_every_gap() {
        let report = build_report("example.com".to_string(), &response_with(&[]));
        assert_eq!(report.score, 0);
        assert_eq!(report.grade, "F");
        // Every weighted header should produce an advisory.
        assert_eq!(report.headers.len(), HEADER_WEIGHTS.len());
        assert_eq!(report.notes.len(), HEADER_WEIGHTS.len());
        assert!(report.headers.iter().all(|h| !h.present));
    }

    #[test]
    fn penalties_apply_but_stay_bounded() {
        // Ten flawed cookies and several versioned banners must not drive the
        // score below zero or exceed the documented caps.
        let cookies = grade_cookies(&(0..10).map(|i| format!("c{i}=1")).collect::<Vec<_>>());
        let disclosures = vec![
            Disclosure {
                header: "server".into(),
                value: "nginx/1.0".into(),
                versioned: true,
            },
            Disclosure {
                header: "x-powered-by".into(),
                value: "PHP/8.0".into(),
                versioned: true,
            },
            Disclosure {
                header: "x-generator".into(),
                value: "Drupal/9.1".into(),
                versioned: true,
            },
        ];
        // A perfect header set (100) minus the capped penalties.
        let headers: Vec<HeaderFinding> = HEADER_WEIGHTS
            .iter()
            .map(|(name, _)| HeaderFinding {
                header: (*name).to_string(),
                present: true,
                value: None,
                verdict: HeaderVerdict::Strict,
                note: None,
            })
            .collect();
        let score = compute_score(&headers, &cookies, &disclosures);
        assert_eq!(score, 100 - COOKIE_PENALTY_CAP - DISCLOSURE_PENALTY_CAP);

        // And penalties can never underflow past zero.
        let empty: Vec<HeaderFinding> = Vec::new();
        assert_eq!(compute_score(&empty, &cookies, &disclosures), 0);
    }

    #[test]
    fn weights_sum_to_one_hundred() {
        // The score is presented as a percentage, so the weights must total 100
        // or a flawless site could never reach A+.
        let total: u32 = HEADER_WEIGHTS.iter().map(|(_, w)| *w).sum();
        assert_eq!(total, 100);
    }

    #[test]
    fn grade_bands_are_ordered_and_total() {
        assert_eq!(grade_letter(100), "A+");
        assert_eq!(grade_letter(95), "A+");
        assert_eq!(grade_letter(94), "A");
        assert_eq!(grade_letter(85), "A");
        assert_eq!(grade_letter(75), "B");
        assert_eq!(grade_letter(65), "C");
        assert_eq!(grade_letter(50), "D");
        assert_eq!(grade_letter(30), "E");
        assert_eq!(grade_letter(29), "F");
        assert_eq!(grade_letter(0), "F");
    }

    #[test]
    fn report_captures_cookies_and_disclosures_from_response() {
        let mut response = response_with(&[
            ("server", "nginx/1.25.3"),
            ("x-powered-by", "PHP/8.2"),
            ("x-content-type-options", "nosniff"),
        ]);
        // Two Set-Cookie headers, as a real origin would send them.
        response.headers.push((
            "set-cookie".into(),
            "a=1; Secure; HttpOnly; SameSite=Lax".into(),
        ));
        response.headers.push(("set-cookie".into(), "b=2".into()));

        let report = build_report("example.com".to_string(), &response);
        assert_eq!(report.cookies.len(), 2);
        assert_eq!(report.disclosures.len(), 2);
        assert!(report.disclosures.iter().all(|d| d.versioned));
        assert!(report.notes.iter().any(|n| n.contains("cookie 'b'")));
        assert!(report.notes.iter().any(|n| n.contains("CVE")));
    }

    #[test]
    fn header_values_are_preserved_for_display() {
        let response = response_with(&[("x-frame-options", "SAMEORIGIN")]);
        let report = build_report("example.com".to_string(), &response);
        let xfo = report
            .headers
            .iter()
            .find(|h| h.header == "x-frame-options")
            .expect("x-frame-options finding");
        assert!(xfo.present);
        assert_eq!(xfo.value.as_deref(), Some("SAMEORIGIN"));
    }
}
