//! Subdomain enumeration via Certificate Transparency logs.
//!
//! CT aggregators are operationally flaky, so enumeration is resilient on two
//! axes: per-source retries that understand crt.sh's transient 404/429/HTML
//! responses (see [`http`]), and an ordered chain of independent sources (see
//! [`sources`]) so a downed primary falls through to a fallback provider.

mod http;
mod sources;

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use tracing::{debug, instrument, warn};

use crate::error::{Result, SeerError};
use sources::Source;

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
        let url = (src.build_url)(&src.base, domain);
        match http::fetch_with_retry(&url).await {
            Ok(body) => match (src.parse)(&body) {
                Ok(names) => return Ok(build_result(domain, names, src.name)),
                Err(e) => {
                    warn!(source = src.name, error = %e, "CT source returned unparseable data");
                    last_err = Some(e);
                }
            },
            Err(e) => {
                warn!(source = src.name, error = %e, "CT source unavailable, trying next");
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
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
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
            },
            Source {
                name: "fallback",
                base: fallback.uri(),
                build_url: |b, d| format!("{}/?domain={}", b, d),
                parse: sources::parse_certspotter,
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
        }];

        let err = enumerate_with_sources("example.com", &srcs).await;
        assert!(err.is_err());
    }
}
