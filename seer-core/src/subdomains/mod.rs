//! Subdomain enumeration via Certificate Transparency logs.
//!
//! CT aggregators are operationally flaky, so enumeration is resilient on two
//! axes: per-source retries that understand crt.sh's transient 404/429/HTML
//! responses, and an ordered chain of independent sources (crt.sh, then
//! certspotter) so a downed primary falls through to a fallback provider.
//!
//! Every request is bounded by the per-request timeout (`timeouts.ct_secs`,
//! 30s by default), and each source — its attempts, backoff, `Retry-After`
//! waits and pages together — by `SOURCE_BUDGET_TIMEOUTS` of them, so the
//! whole chain ends within that many timeouts per source. A paginated source
//! cut short (page cap, a failed later page, the budget) is returned with
//! [`SubdomainResult::truncated`] set.

#[cfg(feature = "cli")]
mod baseline;
mod classify;
mod http;
mod sources;

use std::collections::BTreeSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::time::Instant;
use tracing::{debug, instrument, warn};

#[cfg(feature = "cli")]
pub use baseline::{SubdomainBaseline, SubdomainBaselineDiff, SubdomainBaselines};
pub use classify::{
    classify_subdomains, ClassifiedSubdomain, SubdomainClassification, SubdomainStatus,
};

use crate::error::{Result, SeerError};
use sources::{PaginationSpec, Source};

/// Result of subdomain enumeration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainResult {
    pub domain: String,
    pub subdomains: Vec<String>,
    /// Which CT source actually answered (crt.sh or the fallback).
    pub source: String,
    pub count: usize,
    /// True when the source stopped before its last page (page cap, a failed
    /// later page, or the time budget): names may be missing, so a baseline
    /// recorded from it is incomplete.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

/// The default per-request CT-log timeout (the `timeouts.ct_secs` default).
const DEFAULT_CT_TIMEOUT: Duration = Duration::from_secs(30);

/// Each source may spend at most this many per-request timeouts in total
/// (attempts, backoff, `Retry-After` and pages), so enumeration is bounded by
/// `SOURCE_BUDGET_TIMEOUTS × timeout × sources` — 3 minutes by default. It
/// used to have no overall bound: 4 attempts × 30s plus 30s `Retry-After`
/// waits, over crt.sh and each of up to 10 certspotter pages.
const SOURCE_BUDGET_TIMEOUTS: u32 = 3;

/// Enumerates subdomains using Certificate Transparency logs.
#[derive(Debug, Clone)]
pub struct SubdomainEnumerator {
    /// Per-request timeout; a source's budget is a multiple of it.
    timeout: Duration,
}

impl Default for SubdomainEnumerator {
    fn default() -> Self {
        Self::new()
    }
}

impl SubdomainEnumerator {
    /// An enumerator with the default 30s per-request timeout.
    pub fn new() -> Self {
        Self {
            timeout: DEFAULT_CT_TIMEOUT,
        }
    }

    /// Builds an enumerator honoring `~/.seer/config.toml`: the per-request
    /// timeout is `timeouts.ct_secs` (clamped to 1–120s).
    pub fn from_config(config: &crate::config::SeerConfig) -> Self {
        Self::new().with_timeout(config.ct_timeout())
    }

    /// Sets the per-request timeout (each source's budget scales with it).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Discover subdomains for a domain using Certificate Transparency logs.
    ///
    /// Queries CT-log aggregators (crt.sh first, certspotter as a fallback) to
    /// find certificates issued for subdomains of the given domain. Returns a
    /// deduplicated, sorted list of discovered subdomains.
    ///
    /// # Arguments
    /// * `domain` - The domain name to enumerate subdomains for (e.g., "example.com")
    ///
    /// # Returns
    /// * `Ok(SubdomainResult)` - List of discovered subdomains
    /// * `Err(SeerError)` - If every CT source failed
    #[instrument(skip(self), fields(domain = %domain))]
    pub async fn enumerate(&self, domain: &str) -> Result<SubdomainResult> {
        let domain = crate::validation::normalize_domain(domain)?;
        debug!(domain = %domain, "Enumerating subdomains via CT logs");
        enumerate_with_sources(&domain, &sources::default_sources(), self.timeout).await
    }
}

/// Try each source in order, returning the first that yields a parseable
/// response. Records the last error so a total failure surfaces a real cause.
/// Each source runs under its own `SOURCE_BUDGET_TIMEOUTS` budget, so a
/// primary that eats its whole budget still leaves the fallback its share.
async fn enumerate_with_sources(
    domain: &str,
    srcs: &[Source],
    timeout: Duration,
) -> Result<SubdomainResult> {
    let mut last_err: Option<SeerError> = None;

    for src in srcs {
        let budget = http::Budget {
            timeout,
            deadline: Instant::now() + timeout * SOURCE_BUDGET_TIMEOUTS,
        };
        let fetched = match &src.paginate {
            Some(spec) => fetch_paginated(domain, &src.base, spec, budget).await,
            None => {
                let url = (src.build_url)(&src.base, domain);
                match http::fetch_with_retry(&url, budget).await {
                    Ok(body) => (src.parse)(&body).map(|names| (names, false)),
                    Err(e) => Err(e),
                }
            }
        };
        match fetched {
            Ok((names, truncated)) => {
                let mut result = build_result(domain, names, src.name);
                result.truncated = truncated;
                return Ok(result);
            }
            Err(e) => {
                warn!(source = src.name, error = %e, "CT source unavailable or unparseable, trying next");
                last_err = Some(e);
            }
        }
    }

    Err(last_err.unwrap_or_else(|| {
        SeerError::HttpError(
            "All Certificate Transparency sources are currently unavailable; try again shortly"
                .into(),
        )
    }))
}

/// Fetches a cursor-paginated source page by page, accumulating DNS names until
/// the cursor is exhausted or `max_pages` is reached, every page within the
/// source's `budget`. A failure on the FIRST page propagates (the source is
/// down — let the chain fall through); a failure on a LATER page returns what
/// was gathered so far rather than discarding the earlier pages. Returns the
/// names and whether pagination stopped before the last page.
async fn fetch_paginated(
    domain: &str,
    base: &str,
    spec: &PaginationSpec,
    budget: http::Budget,
) -> Result<(Vec<String>, bool)> {
    let mut names = Vec::new();
    let mut cursor: Option<String> = None;

    for page_num in 0..spec.max_pages {
        let url = (spec.url_after)(base, domain, cursor.as_deref());
        let page = match http::fetch_with_retry(&url, budget)
            .await
            .and_then(|body| (spec.parse_page)(&body))
        {
            Ok(page) => page,
            Err(e) if page_num == 0 => return Err(e),
            Err(e) => {
                warn!(error = %e, page = page_num, "pagination stopped early; returning partial results");
                return Ok((names, true));
            }
        };

        if page.names.is_empty() {
            return Ok((names, false));
        }
        names.extend(page.names);

        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => return Ok((names, false)),
        }
    }

    // The page cap was reached with a cursor still pointing at more.
    Ok((names, true))
}

/// Filter and normalize raw certificate names into the final subdomain list:
/// keep only names under `domain`, strip a wildcard's `*.` (a certificate for
/// `*.dev.example.com` reveals `dev.example.com`), drop the apex itself, and
/// reject anything that isn't a syntactically valid hostname.
fn build_result(domain: &str, raw_names: Vec<String>, source: &str) -> SubdomainResult {
    let suffix = format!(".{}", domain);
    let mut subdomains = BTreeSet::new();

    for name in raw_names {
        let name = name.trim().to_lowercase();
        let name = name.strip_prefix("*.").unwrap_or(&name);
        if (name.ends_with(&suffix) || name == domain) && !name.contains('*') {
            subdomains.insert(name.to_string());
        }
    }

    // The apex itself is not a subdomain.
    subdomains.remove(domain);

    let subdomains: Vec<String> = subdomains
        .into_iter()
        .filter(|s| {
            !s.is_empty()
                && s.len() <= 253
                // Underscores are valid in DNS names (RFC 8552 service labels,
                // e.g. `_acme-challenge`, `_dmarc`) and appear in CT-log SANs;
                // matches the charset normalize_domain accepts on input, so they
                // are not silently dropped here.
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
                && !s.contains("..")
                && !s.starts_with('.')
                && !s.starts_with('-')
        })
        .collect();

    let count = subdomains.len();
    SubdomainResult {
        domain: domain.to_string(),
        subdomains,
        source: source.to_string(),
        count,
        truncated: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Per-request timeout for the mock-server tests: long enough for the
    /// retry backoff (0.5 + 1 + 2 s) to fit in a source's budget.
    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    #[test]
    fn test_subdomain_result_serialization() {
        let result = SubdomainResult {
            domain: "example.com".to_string(),
            subdomains: vec![
                "api.example.com".to_string(),
                "mail.example.com".to_string(),
            ],
            source: "crt.sh (Certificate Transparency)".to_string(),
            count: 2,
            truncated: false,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("api.example.com"));
        assert!(json.contains("mail.example.com"));
        assert!(json.contains("crt.sh"));
    }

    #[test]
    fn test_subdomain_enumerator_default() {
        let _ = SubdomainEnumerator::default();
    }

    #[test]
    fn build_result_filters_and_dedups() {
        let raw = vec![
            "example.com".to_string(),       // apex — dropped
            "API.example.com".to_string(),   // lowercased
            "api.example.com".to_string(),   // dup
            "*.example.com".to_string(),     // wildcard of the apex — dropped
            "*.dev.example.com".to_string(), // wildcard — reveals dev
            "*.evilexample.com".to_string(), // off-domain wildcard — dropped
            "a.*.example.com".to_string(),   // interior wildcard — dropped
            "evil.com".to_string(),          // off-domain — dropped
            "ok.example.com".to_string(),
        ];
        let r = build_result("example.com", raw, "test");
        assert_eq!(
            r.subdomains,
            vec!["api.example.com", "dev.example.com", "ok.example.com"]
        );
        assert_eq!(r.count, 3);
        assert_eq!(r.source, "test");
    }

    #[test]
    fn build_result_keeps_underscore_service_labels() {
        // RFC 8552 service labels (routinely present in CT-log SANs) must not be
        // silently dropped by the hostname-charset filter.
        let raw = vec![
            "_acme-challenge.example.com".to_string(),
            "_dmarc.example.com".to_string(),
            "www.example.com".to_string(),
        ];
        let r = build_result("example.com", raw, "test");
        assert!(r
            .subdomains
            .contains(&"_acme-challenge.example.com".to_string()));
        assert!(r.subdomains.contains(&"_dmarc.example.com".to_string()));
        assert!(r.subdomains.contains(&"www.example.com".to_string()));
        assert_eq!(r.count, 3);
    }

    /// The headline regression: when the primary source rate-limits (429, the
    /// crt.sh failure mode behind the reported `zac.app` 404), enumeration must
    /// fall through to the fallback source instead of erroring out.
    #[tokio::test]
    async fn falls_back_to_second_source_when_primary_rate_limits() {
        let primary = MockServer::start().await;
        Mock::given(method("GET"))
            // Retry-After: 0 keeps the retry budget from sleeping in the test.
            .respond_with(
                ResponseTemplate::new(429).insert_header("retry-after", "0"),
            )
            .mount(&primary)
            .await;

        let fallback = MockServer::start().await;
        let body = r#"[{"dns_names":["api.example.com","example.com"]}]"#;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&fallback)
            .await;

        let srcs = vec![
            Source {
                name: "primary",
                base: primary.uri(),
                build_url: |b, d| format!("{}/?q={}", b, d),
                parse: sources::parse_crtsh,
                paginate: None,
            },
            Source {
                name: "fallback",
                base: fallback.uri(),
                build_url: |b, d| format!("{}/?domain={}", b, d),
                parse: sources::parse_certspotter,
                paginate: None,
            },
        ];

        let result = enumerate_with_sources("example.com", &srcs, TEST_TIMEOUT)
            .await
            .unwrap();
        assert_eq!(result.source, "fallback");
        assert_eq!(result.subdomains, vec!["api.example.com"]);
    }

    /// When every source is down, the error should be the friendly exhaustion
    /// message, not a silent empty success.
    #[tokio::test]
    async fn errors_when_all_sources_unavailable() {
        let down = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&down)
            .await;

        let srcs = vec![Source {
            name: "only",
            base: down.uri(),
            build_url: |b, d| format!("{}/?q={}", b, d),
            parse: sources::parse_crtsh,
            paginate: None,
        }];

        let err = enumerate_with_sources("example.com", &srcs, TEST_TIMEOUT).await;
        assert!(err.is_err());
    }

    /// A paginated source must follow the `after=` cursor and accumulate names
    /// across pages instead of silently truncating to the first page.
    #[tokio::test]
    async fn paginated_source_follows_cursor_across_pages() {
        use wiremock::matchers::{query_param, query_param_is_missing};

        let server = MockServer::start().await;

        // Page 1 (no cursor): id 100 -> next cursor "100".
        Mock::given(method("GET"))
            .and(query_param_is_missing("after"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"[{"id":"100","dns_names":["a.example.com"]}]"#),
            )
            .mount(&server)
            .await;

        // Page 2 (after=100): id 200 -> next cursor "200".
        Mock::given(method("GET"))
            .and(query_param("after", "100"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"[{"id":"200","dns_names":["b.example.com"]}]"#),
            )
            .mount(&server)
            .await;

        // Page 3 (after=200): empty -> pagination ends.
        Mock::given(method("GET"))
            .and(query_param("after", "200"))
            .respond_with(ResponseTemplate::new(200).set_body_string("[]"))
            .mount(&server)
            .await;

        let srcs = vec![Source {
            name: "paged",
            base: server.uri(),
            build_url: |b, d| format!("{}/?domain={}", b, d),
            parse: sources::parse_certspotter,
            paginate: Some(PaginationSpec {
                url_after: |base, domain, after| {
                    let mut url = format!("{}/v1/issuances?domain={}", base, domain);
                    if let Some(c) = after {
                        url.push_str("&after=");
                        url.push_str(c);
                    }
                    url
                },
                parse_page: sources::parse_certspotter_page,
                max_pages: 10,
            }),
        }];

        let result = enumerate_with_sources("example.com", &srcs, TEST_TIMEOUT)
            .await
            .unwrap();
        assert_eq!(
            result.subdomains,
            vec!["a.example.com", "b.example.com"],
            "names from both pages must be accumulated"
        );
        assert!(!result.truncated, "pagination ran to the end");
    }

    fn paged_source(base: String, max_pages: usize) -> Source {
        Source {
            name: "paged",
            base,
            build_url: |b, d| format!("{}/?domain={}", b, d),
            parse: sources::parse_certspotter,
            paginate: Some(PaginationSpec {
                url_after: |base, domain, after| match after {
                    Some(c) => format!("{base}/v1/issuances?domain={domain}&after={c}"),
                    None => format!("{base}/v1/issuances?domain={domain}"),
                },
                parse_page: sources::parse_certspotter_page,
                max_pages,
            }),
        }
    }

    /// A source cut short by its page cap (cursor still pointing at more) or
    /// by a failed later page is marked truncated, so a baseline recorded
    /// from it is known to be incomplete.
    #[tokio::test]
    async fn paginated_source_cut_short_is_truncated() {
        use wiremock::matchers::{query_param, query_param_is_missing};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(query_param_is_missing("after"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"[{"id":"100","dns_names":["a.example.com"]}]"#),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(query_param("after", "100"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&server)
            .await;

        // Page cap of 1 with a next cursor.
        let srcs = vec![paged_source(server.uri(), 1)];
        let result = enumerate_with_sources("example.com", &srcs, TEST_TIMEOUT)
            .await
            .unwrap();
        assert_eq!(result.subdomains, vec!["a.example.com"]);
        assert!(result.truncated);

        // Page 2 fails (terminal 400): partial names, truncated.
        let srcs = vec![paged_source(server.uri(), 10)];
        let result = enumerate_with_sources("example.com", &srcs, TEST_TIMEOUT)
            .await
            .unwrap();
        assert_eq!(result.subdomains, vec!["a.example.com"]);
        assert!(result.truncated);
    }

    /// Regression: enumeration had no overall bound (4 attempts × 30s plus
    /// 30s Retry-After waits per request). A source that never answers now
    /// gives up after its budget and the chain moves on.
    #[tokio::test]
    async fn a_hanging_source_is_bounded_by_its_budget() {
        let hanging = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("[]")
                    .set_delay(Duration::from_secs(30)),
            )
            .mount(&hanging)
            .await;
        let fallback = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r#"[{"dns_names":["b.example.com"]}]"#),
            )
            .mount(&fallback)
            .await;

        let srcs = vec![
            Source {
                name: "hanging",
                base: hanging.uri(),
                build_url: |b, d| format!("{}/?q={}", b, d),
                parse: sources::parse_crtsh,
                paginate: None,
            },
            Source {
                name: "fallback",
                base: fallback.uri(),
                build_url: |b, d| format!("{}/?domain={}", b, d),
                parse: sources::parse_certspotter,
                paginate: None,
            },
        ];
        let timeout = Duration::from_millis(200);
        let started = std::time::Instant::now();
        let result = enumerate_with_sources("example.com", &srcs, timeout)
            .await
            .unwrap();
        let elapsed = started.elapsed();
        assert_eq!(result.source, "fallback");
        // The hanging source's budget is 3 timeouts (600ms) plus backoff that
        // fits in it; far below a single 30s response.
        assert!(
            elapsed < Duration::from_secs(5),
            "enumeration took {elapsed:?}"
        );
    }

    #[test]
    fn from_config_takes_the_ct_timeout() {
        let mut config = crate::config::SeerConfig::default();
        config.timeouts.ct_secs = 45;
        assert_eq!(
            SubdomainEnumerator::from_config(&config).timeout,
            Duration::from_secs(45)
        );
        assert_eq!(SubdomainEnumerator::new().timeout, DEFAULT_CT_TIMEOUT);
    }
}
