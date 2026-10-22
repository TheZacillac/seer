//! `security.txt` (RFC 9116): does the site publish a vulnerability-disclosure
//! contact?
//!
//! One SSRF-guarded GET to `https://<host>/.well-known/security.txt` (body
//! capped at 32 KiB, redirects re-validated). Only a 200 `text/plain` body
//! that is not an HTML page counts as found — many sites answer every path
//! with a 200 HTML soft-404. Only a 404 or 410 means the file is missing;
//! any other status (a WAF's 403, a 429, a 5xx, a 3xx with no `Location`)
//! is an error, since it says nothing about the file. The parser checks the two required fields
//! (`Contact`, exactly one `Expires` in RFC 3339 form) and notes a PGP
//! cleartext-signature wrapper (presence only; the signature is not
//! verified). Field values are remote text: sanitize before display.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Result, SeerError};
use crate::http::{GuardedFetcher, SendError};
use crate::validation::normalize_host;

/// Body cap: real files are a few hundred bytes.
const MAX_BODY: usize = 32 * 1024;

/// A problem with the published file (or its absence).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityTxtIssue {
    /// The well-known path answered 404 or 410.
    NotFound,
    /// A 200 that is HTML or not `text/plain` (a soft-404).
    NotPlainText,
    /// No `Contact` field (required).
    MissingContact,
    /// No `Expires` field (required).
    MissingExpires,
    /// `Expires` is not an RFC 3339 date-time.
    InvalidExpires,
    /// More than one `Expires` field.
    MultipleExpires,
}

/// The fetched and parsed `security.txt`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityTxtReport {
    /// URL that was fetched.
    pub url: String,
    /// A plain-text file was served.
    pub found: bool,
    /// `Contact` values (remote text).
    pub contact: Vec<String>,
    /// Parsed `Expires` value, when present and well-formed.
    pub expires: Option<DateTime<Utc>>,
    /// `Expires` is in the past.
    pub expired: bool,
    /// Wrapped in a PGP cleartext signature (not verified).
    pub signed: bool,
    /// Problems found, in detection order.
    pub issues: Vec<SecurityTxtIssue>,
}

impl SecurityTxtReport {
    /// Found, with both required fields well-formed (expiry is separate).
    pub fn is_valid(&self) -> bool {
        self.found && self.issues.is_empty()
    }

    fn missing(url: &str, issue: SecurityTxtIssue) -> Self {
        Self {
            url: url.to_string(),
            found: false,
            contact: Vec::new(),
            expires: None,
            expired: false,
            signed: false,
            issues: vec![issue],
        }
    }
}

/// Fetches and parses `https://<host>/.well-known/security.txt`.
///
/// # Errors
/// `InvalidDomain` for bad input; an HTTP error when the fetch failed or the
/// server answered anything but 200, 404 or 410 (the result is unknown).
pub async fn fetch_security_txt(host: &str, timeout: Duration) -> Result<SecurityTxtReport> {
    let host = normalize_host(host)?;
    let fetcher = GuardedFetcher::new().with_timeout(timeout);
    let url = format!("https://{host}/.well-known/security.txt");
    Ok(fetch_url(&fetcher, &url, Utc::now()).await?)
}

/// Fetches `url` and parses it, keeping the connect/other failure split.
pub(crate) async fn fetch_url(
    fetcher: &GuardedFetcher,
    url: &str,
    now: DateTime<Utc>,
) -> std::result::Result<SecurityTxtReport, SendError> {
    let fetcher = fetcher.clone().with_max_body(MAX_BODY);
    let response = fetcher.get_traced(url).await.result?;
    match response.head.status {
        200 => {}
        404 | 410 => return Ok(SecurityTxtReport::missing(url, SecurityTxtIssue::NotFound)),
        // A WAF block, rate limit, server error or a 3xx with no `Location`
        // says nothing about whether the file exists.
        status => {
            return Err(SendError::Other(SeerError::HttpError(format!(
                "security.txt fetch answered HTTP {status}"
            ))))
        }
    }
    let plain = response.head.header("content-type").is_some_and(|ct| {
        ct.trim_start()
            .to_ascii_lowercase()
            .starts_with("text/plain")
    });
    let head = response.body.trim_start().to_ascii_lowercase();
    if !plain || head.starts_with("<!doctype") || head.starts_with("<html") {
        return Ok(SecurityTxtReport::missing(
            url,
            SecurityTxtIssue::NotPlainText,
        ));
    }
    Ok(parse(url, &response.body, now))
}

/// Parses a served file. Pure.
pub(crate) fn parse(url: &str, body: &str, now: DateTime<Utc>) -> SecurityTxtReport {
    let signed = body
        .trim_start()
        .starts_with("-----BEGIN PGP SIGNED MESSAGE-----");
    let mut contact = Vec::new();
    let mut expires_raw: Vec<&str> = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("-----") {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        match name.trim().to_ascii_lowercase().as_str() {
            // An empty `Contact:` names no one.
            "contact" if !value.trim().is_empty() => contact.push(value.trim().to_string()),
            "expires" => expires_raw.push(value.trim()),
            _ => {}
        }
    }

    let mut issues = Vec::new();
    if contact.is_empty() {
        issues.push(SecurityTxtIssue::MissingContact);
    }
    let expires = match expires_raw.as_slice() {
        [] => {
            issues.push(SecurityTxtIssue::MissingExpires);
            None
        }
        [one, rest @ ..] => {
            if !rest.is_empty() {
                issues.push(SecurityTxtIssue::MultipleExpires);
            }
            match DateTime::parse_from_rfc3339(one) {
                Ok(t) => Some(t.with_timezone(&Utc)),
                Err(_) => {
                    issues.push(SecurityTxtIssue::InvalidExpires);
                    None
                }
            }
        }
    };

    SecurityTxtReport {
        url: url.to_string(),
        found: true,
        contact,
        expired: expires.is_some_and(|t| t < now),
        expires,
        signed,
        issues,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 22, 0, 0, 0).unwrap()
    }

    const URL: &str = "https://example.com/.well-known/security.txt";

    #[test]
    fn parses_required_fields() {
        let r = parse(
            URL,
            "# comment\nContact: mailto:security@example.com\nContact: https://example.com/vdp\nExpires: 2027-01-01T00:00:00Z\n",
            now(),
        );
        assert!(r.found && r.is_valid() && !r.expired && !r.signed);
        assert_eq!(r.contact.len(), 2);
    }

    #[test]
    fn field_names_are_case_insensitive() {
        let r = parse(
            URL,
            "contact: mailto:a@b.test\nEXPIRES: 2027-01-01T00:00:00Z\n",
            now(),
        );
        assert!(r.is_valid(), "{:?}", r.issues);
    }

    #[test]
    fn missing_fields_and_expiry_are_issues() {
        let r = parse(URL, "Expires: 2020-01-01T00:00:00Z\n", now());
        assert!(r.expired);
        assert!(r.issues.contains(&SecurityTxtIssue::MissingContact));
        let r = parse(URL, "Contact: mailto:a@b.test\nExpires: soon\n", now());
        assert!(r.issues.contains(&SecurityTxtIssue::InvalidExpires));
        let r = parse(URL, "Contact: mailto:a@b.test\n", now());
        assert!(r.issues.contains(&SecurityTxtIssue::MissingExpires));
        let r = parse(
            URL,
            "Contact: mailto:a@b.test\nExpires: 2027-01-01T00:00:00Z\nExpires: 2028-01-01T00:00:00Z\n",
            now(),
        );
        assert!(r.issues.contains(&SecurityTxtIssue::MultipleExpires));
    }

    #[test]
    fn an_empty_contact_is_not_a_contact() {
        let r = parse(
            URL,
            "Contact:\nContact:   \nExpires: 2027-01-01T00:00:00Z\n",
            now(),
        );
        assert!(r.contact.is_empty());
        assert_eq!(r.issues, vec![SecurityTxtIssue::MissingContact]);
    }

    #[test]
    fn detects_a_pgp_signature_wrapper() {
        let body = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nContact: mailto:a@b.test\nExpires: 2027-01-01T00:00:00Z\n-----BEGIN PGP SIGNATURE-----\nxyz\n-----END PGP SIGNATURE-----\n";
        let r = parse(URL, body, now());
        assert!(r.signed && r.is_valid(), "{:?}", r.issues);
    }

    #[tokio::test]
    async fn html_soft_404_is_not_a_security_txt() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/security.txt"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string("<!DOCTYPE html><html>Not found</html>"),
            )
            .mount(&server)
            .await;
        let fetcher = GuardedFetcher::new().allowing_private_hosts();
        let url = format!("{}/.well-known/security.txt", server.uri());
        let r = fetch_url(&fetcher, &url, now()).await.unwrap();
        assert!(!r.found);
        assert_eq!(r.issues, vec![SecurityTxtIssue::NotPlainText]);
    }

    #[tokio::test]
    async fn a_404_is_not_found() {
        let server = MockServer::start().await;
        let fetcher = GuardedFetcher::new().allowing_private_hosts();
        let url = format!("{}/.well-known/security.txt", server.uri());
        let r = fetch_url(&fetcher, &url, now()).await.unwrap();
        assert!(!r.found);
        assert_eq!(r.issues, vec![SecurityTxtIssue::NotFound]);
    }

    /// Serves `status` (no `Location`) at the well-known path.
    async fn fetch_status(status: u16) -> std::result::Result<SecurityTxtReport, SendError> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/security.txt"))
            .respond_with(ResponseTemplate::new(status))
            .mount(&server)
            .await;
        let fetcher = GuardedFetcher::new().allowing_private_hosts();
        let url = format!("{}/.well-known/security.txt", server.uri());
        fetch_url(&fetcher, &url, now()).await
    }

    #[tokio::test]
    async fn only_404_and_410_mean_not_found() {
        for status in [404, 410] {
            let r = fetch_status(status).await.unwrap();
            assert_eq!(r.issues, vec![SecurityTxtIssue::NotFound], "{status}");
        }
    }

    #[tokio::test]
    async fn blocked_throttled_or_failing_answers_are_unknown() {
        // A WAF block, rate limit, server error or a 3xx going nowhere says
        // nothing about whether the file exists.
        for status in [401, 403, 429, 500, 503, 302] {
            let r = fetch_status(status).await;
            assert!(matches!(r, Err(SendError::Other(_))), "{status}: {r:?}");
        }
    }

    #[tokio::test]
    async fn a_plain_text_file_is_parsed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/security.txt"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/plain; charset=utf-8")
                    .set_body_string("Contact: mailto:a@b.test\nExpires: 2027-01-01T00:00:00Z\n"),
            )
            .mount(&server)
            .await;
        let fetcher = GuardedFetcher::new().allowing_private_hosts();
        let url = format!("{}/.well-known/security.txt", server.uri());
        let r = fetch_url(&fetcher, &url, now()).await.unwrap();
        assert!(r.is_valid(), "{r:?}");
    }
}
