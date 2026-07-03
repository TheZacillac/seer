//! Subdomain enumeration via Certificate Transparency logs.
//!
//! CT aggregators are operationally flaky, so enumeration is resilient on two
//! axes: per-source retries that understand crt.sh's transient 404/429/HTML
//! responses (see [`http`]), and an ordered chain of independent sources (see
//! [`sources`]) so a downed primary falls through to a fallback provider.

mod baseline;
mod classify;
mod http;
mod sources;

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use tracing::{debug, instrument, warn};

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
}

/// Enumerates subdomains using Certificate Transparency logs.
pub struct SubdomainEnumerator;

impl Default for SubdomainEnumerator {
    fn default() -> Self {
        Self::new()
    }
}

impl SubdomainEnumerator {
    pub fn new() -> Self {
        Self
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
        enumerate_with_sources(&domain, &sources::default_sources()).await
    }
}

/// Try each source in order, returning the first that yields a parseable
/// response. Records the last error so a total failure surfaces a real cause.
async fn enumerate_with_sources(domain: &str, srcs: &[Source]) -> Result<SubdomainResult> {
    let mut last_err: Option<SeerError> = None;

    for src in srcs {
        let fetched = match &src.paginate {
            Some(spec) => fetch_paginated(domain, &src.base, spec).await,
            None => {
                let url = (src.build_url)(&src.base, domain);
                match http::fetch_with_retry(&url).await {
                    Ok(body) => (src.parse)(&body),
                    Err(e) => Err(e),
                }
            }
        };
        match fetched {
            Ok(names) => return Ok(build_result(domain, names, src.name)),
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
/// the cursor is exhausted or `max_pages` is reached. A failure on the FIRST
/// page propagates (the source is down — let the chain fall through); a failure
/// on a LATER page returns what was gathered so far rather than discarding the
/// earlier pages.
async fn fetch_paginated(domain: &str, base: &str, spec: &PaginationSpec) -> Result<Vec<String>> {
    let mut names = Vec::new();
    let mut cursor: Option<String> = None;

    for page_num in 0..spec.max_pages {
        let url = (spec.url_after)(base, domain, cursor.as_deref());
        let page = match http::fetch_with_retry(&url)
            .await
            .and_then(|body| (spec.parse_page)(&body))
        {
            Ok(page) => page,
            Err(e) if page_num == 0 => return Err(e),
            Err(e) => {
                warn!(error = %e, page = page_num, "pagination stopped early; returning partial results");
                break;
            }
        };

        if page.names.is_empty() {
            break;
        }
        names.extend(page.names);

        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }

    Ok(names)
}

/// Filter and normalize raw certificate names into the final subdomain list:
/// keep only names under `domain`, drop wildcards and the apex itself, and
/// reject anything that isn't a syntactically valid hostname.
fn build_result(domain: &str, raw_names: Vec<String>, source: &str) -> SubdomainResult {
    let suffix = format!(".{}", domain);
    let mut subdomains = BTreeSet::new();

    for name in raw_names {
        let name = name.trim().to_lowercase();
        if (name.ends_with(&suffix) || name == domain) && !name.starts_with('*') {
            subdomains.insert(name);
        }
    }

    // The apex itself is not a subdomain.
    subdomains.remove(domain);

    let subdomains: Vec<String> = subdomains
        .into_iter()
        .filter(|s| {
            let s = s.strip_prefix("*.").unwrap_or(s);
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

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
            "example.com".to_string(),     // apex — dropped
            "API.example.com".to_string(), // lowercased
            "api.example.com".to_string(), // dup
            "*.example.com".to_string(),   // wildcard — dropped
            "evil.com".to_string(),        // off-domain — dropped
            "ok.example.com".to_string(),
        ];
        let r = build_result("example.com", raw, "test");
        assert_eq!(r.subdomains, vec!["api.example.com", "ok.example.com"]);
        assert_eq!(r.count, 2);
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

        let result = enumerate_with_sources("example.com", &srcs).await.unwrap();
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

        let err = enumerate_with_sources("example.com", &srcs).await;
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

        let result = enumerate_with_sources("example.com", &srcs).await.unwrap();
        assert_eq!(
            result.subdomains,
            vec!["a.example.com", "b.example.com"],
            "names from both pages must be accumulated"
        );
    }
}
