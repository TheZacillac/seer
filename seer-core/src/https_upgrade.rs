//! Does plain HTTP upgrade to HTTPS?
//!
//! One SSRF-guarded GET to `http://<host>/`, following redirects manually
//! (every hop re-validated, at most 5) without reading a body, then a pure
//! assessment of the redirect chain: an upgrade is a chain that ends on
//! `https://` at the same registrable domain. A connection failure on the
//! first hop means nothing listens on port 80 (`listening: false`) — which is
//! fine, not a finding. A failure on a later hop does not erase what the
//! chain already shows once it has reached `https://` or left the site; a
//! failed plain-http hop on the same site leaves the answer unknown (an
//! error). IP literals compare exactly, never through the PSL.
//! Single-attempt, like every probe.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::http::{GuardedFetcher, SendError};
use crate::validation::normalize_host;

/// The outcome of an HTTP→HTTPS upgrade check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpsUpgradeReport {
    /// The host that was probed.
    pub host: String,
    /// Whether anything answered on port 80.
    pub listening: bool,
    /// URLs attempted, in order (remote-influenced — sanitize before display).
    pub chain: Vec<String>,
    /// The chain ends on HTTPS at the same registrable domain.
    pub upgraded: bool,
    /// The first redirect points at an `https://` URL.
    pub first_hop_https: bool,
    /// The chain ends at a different registrable domain.
    pub cross_domain: bool,
}

/// Probes `http://<host>/` and reports whether it upgrades to HTTPS.
///
/// # Errors
/// `InvalidDomain` for bad input; an HTTP error when the first hop failed for
/// a reason other than a refused/failed connection, or a later hop failed
/// before the chain reached `https://` or another site (the result is
/// unknown).
pub async fn check_https_upgrade(host: &str, timeout: Duration) -> Result<HttpsUpgradeReport> {
    let host = normalize_host(host)?;
    check_with(&GuardedFetcher::new().with_timeout(timeout), &host).await
}

/// [`check_https_upgrade`] for a normalized host and a caller-built fetcher.
pub(crate) async fn check_with(fetcher: &GuardedFetcher, host: &str) -> Result<HttpsUpgradeReport> {
    let traced = fetcher.get_head_traced(&format!("http://{host}/")).await;
    // An empty chain (the URL never parsed) is a first-hop failure too.
    let first_hop = traced.chain.len() <= 1;
    match traced.result {
        Ok(_) => Ok(assess(host, &traced.chain)),
        Err(SendError::Connect(_)) if first_hop => Ok(HttpsUpgradeReport {
            host: host.to_string(),
            listening: false,
            chain: traced.chain,
            upgraded: false,
            first_hop_https: false,
            cross_domain: false,
        }),
        Err(e) if first_hop => Err(e.into()),
        // A later hop failed. The chain so far is evidence only once it has
        // reached `https://` or left the site; a failed plain-http hop on the
        // same site leaves the answer unknown.
        Err(e) => {
            let report = assess(host, &traced.chain);
            let reached_https = traced
                .chain
                .last()
                .and_then(|u| url::Url::parse(u).ok())
                .is_some_and(|u| u.scheme() == "https");
            if reached_https || report.cross_domain {
                Ok(report)
            } else {
                Err(e.into())
            }
        }
    }
}

/// Assesses a redirect chain that started at `http://<host>/`. Pure.
pub(crate) fn assess(host: &str, chain: &[String]) -> HttpsUpgradeReport {
    let parsed: Vec<Option<url::Url>> = chain.iter().map(|u| url::Url::parse(u).ok()).collect();
    let is_https = |u: &Option<url::Url>| u.as_ref().is_some_and(|u| u.scheme() == "https");
    let last = parsed.last().cloned().flatten();
    let same_site = last
        .as_ref()
        .and_then(|u| u.host_str())
        .is_some_and(|final_host| same_registrable(host, final_host));
    let final_https = parsed.last().is_some_and(is_https);
    HttpsUpgradeReport {
        host: host.to_string(),
        listening: true,
        chain: chain.to_vec(),
        upgraded: final_https && same_site,
        first_hop_https: parsed.get(1).is_some_and(is_https),
        cross_domain: last.is_some() && !same_site,
    }
}

/// Whether two hosts share a registrable domain; IP literals and hosts with
/// none (bare labels) must match exactly — an IP never goes through the PSL,
/// which would read `10.1.2.3` as the registrable `2.3`. A `:port` on `a` is
/// ignored.
fn same_registrable(a: &str, b: &str) -> bool {
    let a = a.rsplit_once(':').map_or(a, |(h, port)| {
        if port.chars().all(|c| c.is_ascii_digit()) {
            h
        } else {
            a
        }
    });
    let is_ip = |h: &str| h.parse::<std::net::IpAddr>().is_ok();
    if is_ip(a) || is_ip(b) {
        return a.eq_ignore_ascii_case(b);
    }
    match (
        crate::psl::registrable_domain(a),
        crate::psl::registrable_domain(b),
    ) {
        (Some(x), Some(y)) => x.eq_ignore_ascii_case(y),
        _ => a.eq_ignore_ascii_case(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn chain(urls: &[&str]) -> Vec<String> {
        urls.iter().map(|u| u.to_string()).collect()
    }

    #[test]
    fn same_domain_https_redirect_is_an_upgrade() {
        let r = assess(
            "example.com",
            &chain(&["http://example.com/", "https://www.example.com/"]),
        );
        assert!(r.listening && r.upgraded && r.first_hop_https && !r.cross_domain);
    }

    #[test]
    fn plain_http_answer_is_not_an_upgrade() {
        let r = assess("example.com", &chain(&["http://example.com/"]));
        assert!(r.listening && !r.upgraded && !r.first_hop_https);
    }

    #[test]
    fn redirect_to_another_domain_is_not_an_upgrade() {
        let r = assess(
            "example.com",
            &chain(&["http://example.com/", "https://parking.test/"]),
        );
        assert!(!r.upgraded && r.cross_domain);
    }

    #[test]
    fn http_hop_after_https_ends_on_http() {
        let r = assess(
            "example.com",
            &chain(&[
                "http://example.com/",
                "https://example.com/",
                "http://example.com/login",
            ]),
        );
        assert!(r.first_hop_https && !r.upgraded);
    }

    #[test]
    fn ip_literals_compare_exactly() {
        // Never through the PSL, which would read `2.3` as a registrable domain.
        assert!(!same_registrable("10.1.2.3", "10.9.2.3"));
        assert!(!same_registrable("10.1.2.3:8080", "10.9.2.3"));
        assert!(same_registrable("10.1.2.3:8080", "10.1.2.3"));
        assert!(!same_registrable("example.com", "10.1.2.3"));
        assert!(same_registrable("example.com", "www.example.com"));
    }

    #[tokio::test]
    async fn closed_port_80_is_not_listening() {
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let fetcher = GuardedFetcher::new()
            .with_timeout(Duration::from_secs(2))
            .allowing_private_hosts();
        let r = check_with(&fetcher, &format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        assert!(!r.listening && !r.upgraded);
    }

    #[tokio::test]
    async fn plain_http_site_is_listening_without_upgrade() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let host = server.uri().trim_start_matches("http://").to_string();
        let fetcher = GuardedFetcher::new().allowing_private_hosts();
        let r = check_with(&fetcher, &host).await.unwrap();
        assert!(r.listening && !r.upgraded);
        assert_eq!(r.chain.len(), 1);
    }

    #[tokio::test]
    async fn later_hop_failure_still_reports_the_upgrade() {
        // Redirects to an https URL on a closed port: the hop fails, but the
        // first hop already proved the upgrade.
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(301)
                    .insert_header("location", format!("https://127.0.0.1:{closed}/").as_str()),
            )
            .mount(&server)
            .await;
        let host = server.uri().trim_start_matches("http://").to_string();
        let fetcher = GuardedFetcher::new()
            .with_timeout(Duration::from_secs(2))
            .allowing_private_hosts();
        let r = check_with(&fetcher, &host).await.unwrap();
        assert!(r.listening && r.first_hop_https, "{r:?}");
        // IP literals compare exactly, ignoring the probed host's port: the
        // ports differ, the IP is equal.
        assert!(r.upgraded, "{r:?}");
    }

    #[tokio::test]
    async fn later_plain_http_hop_failure_is_unknown() {
        // Redirects to another plain-http URL that fails: nothing shows the
        // site upgrades or not, so the result is unknown.
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(301)
                    .insert_header("location", format!("http://127.0.0.1:{closed}/").as_str()),
            )
            .mount(&server)
            .await;
        let host = server.uri().trim_start_matches("http://").to_string();
        let fetcher = GuardedFetcher::new()
            .with_timeout(Duration::from_secs(2))
            .allowing_private_hosts();
        let r = check_with(&fetcher, &host).await;
        assert!(r.is_err(), "{r:?}");
    }

    #[tokio::test]
    async fn first_hop_non_connect_failure_is_unknown() {
        // A production fetcher refuses loopback before connecting (SSRF): an
        // unknown, not "nothing listens".
        let r = check_with(&GuardedFetcher::new(), "127.0.0.1").await;
        assert!(r.is_err(), "{r:?}");
    }

    #[tokio::test]
    async fn a_failure_before_any_hop_is_unknown() {
        // The URL never parses, so the chain is empty: unknown, never an
        // assessment of an empty chain.
        let r = check_with(&GuardedFetcher::new().allowing_private_hosts(), "exa mple").await;
        assert!(r.is_err(), "{r:?}");
    }
}
