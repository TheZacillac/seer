//! Pluggable Certificate Transparency sources.
//!
//! Each [`Source`] knows how to build a query URL for a domain and how to parse
//! the raw certificate DNS names out of that source's response shape. The
//! orchestrator in the parent module tries them in order, so a flaky primary
//! (crt.sh) can fall through to a second provider (certspotter) rather than
//! failing the whole command.

use serde::Deserialize;

use crate::error::{Result, SeerError};

/// A Certificate Transparency source.
///
/// `base` is split out from `build_url` so tests can point a source at a local
/// mock server without rewriting its URL logic.
pub(crate) struct Source {
    /// Human-facing provenance label, stored in `SubdomainResult.source`.
    pub name: &'static str,
    /// Base origin, e.g. `https://crt.sh`.
    pub base: String,
    /// Builds the full query URL from `(base, domain)`.
    pub build_url: fn(&str, &str) -> String,
    /// Extracts raw certificate DNS names from the response body.
    pub parse: fn(&[u8]) -> Result<Vec<String>>,
    /// Optional cursor-based pagination. When `Some`, the orchestrator fetches
    /// successive pages (following the per-page cursor, bounded by `max_pages`)
    /// instead of a single `build_url`/`parse` request — so a provider that
    /// returns issuances in fixed-size pages isn't silently truncated.
    pub paginate: Option<PaginationSpec>,
}

/// Cursor-based pagination strategy for a [`Source`].
pub(crate) struct PaginationSpec {
    /// Builds a page URL resuming after an optional cursor (`None` = first page).
    pub url_after: fn(&str, &str, Option<&str>) -> String,
    /// Parses one page into its DNS names plus the cursor for the next page
    /// (`None` ends pagination).
    pub parse_page: fn(&[u8]) -> Result<CertSpotterPage>,
    /// Hard cap on pages fetched per enumeration (fan-out / loop guard).
    pub max_pages: usize,
}

/// The default source chain: crt.sh first (richest data), certspotter as a
/// fallback for when crt.sh is throttling or down.
pub(crate) fn default_sources() -> Vec<Source> {
    vec![
        Source {
            name: "crt.sh (Certificate Transparency)",
            base: "https://crt.sh".to_string(),
            build_url: crtsh_url,
            parse: parse_crtsh,
            paginate: None,
        },
        Source {
            name: "certspotter (Certificate Transparency)",
            base: "https://api.certspotter.com".to_string(),
            build_url: certspotter_url,
            parse: parse_certspotter,
            paginate: Some(PaginationSpec {
                url_after: certspotter_url_after,
                parse_page: parse_certspotter_page,
                max_pages: CERTSPOTTER_MAX_PAGES,
            }),
        },
    ]
}

fn crtsh_url(base: &str, domain: &str) -> String {
    // `%25` is an encoded `%` wildcard: match all labels under `domain`.
    format!("{}/?q=%25.{}&output=json", base, domain)
}

fn certspotter_url(base: &str, domain: &str) -> String {
    certspotter_url_after(base, domain, None)
}

/// Maximum number of certspotter pages to fetch in one enumeration. certspotter
/// returns issuances in fixed-size pages and expects the client to follow an
/// `after=<id>` cursor; without paging, a domain with many CT issuances is
/// silently truncated to the first page. This cap bounds the fan-out so a
/// pathological domain can't trigger unbounded fetching — at certspotter's
/// default page size (~100) this covers ~1000 issuances, well past the point of
/// diminishing returns for subdomain discovery.
pub(crate) const CERTSPOTTER_MAX_PAGES: usize = 10;

/// Builds a certspotter issuances URL, optionally resuming after a cursor.
///
/// `after = None` yields the first-page URL (identical to the un-paginated
/// form). `after = Some(id)` appends `&after=<id>` so the request returns the
/// issuances that follow `id`, which is how certspotter paginates.
fn certspotter_url_after(base: &str, domain: &str, after: Option<&str>) -> String {
    let mut url = format!(
        "{}/v1/issuances?domain={}&include_subdomains=true&expand=dns_names",
        base, domain
    );
    if let Some(cursor) = after {
        url.push_str("&after=");
        url.push_str(cursor);
    }
    url
}

#[derive(Debug, Deserialize)]
struct CrtShEntry {
    #[serde(default)]
    common_name: String,
    #[serde(default)]
    name_value: Option<String>,
}

/// Parse crt.sh's `output=json` response: an array of entries whose
/// `common_name` / `name_value` fields may each hold newline-separated names.
pub(crate) fn parse_crtsh(body: &[u8]) -> Result<Vec<String>> {
    let entries: Vec<CrtShEntry> = serde_json::from_slice(body)
        .map_err(|e| SeerError::HttpError(format!("Failed to parse crt.sh response: {}", e)))?;

    let mut names = Vec::new();
    for entry in &entries {
        names.extend(entry.common_name.split('\n').map(str::to_string));
        if let Some(ref name_value) = entry.name_value {
            names.extend(name_value.split('\n').map(str::to_string));
        }
    }
    Ok(names)
}

#[derive(Debug, Deserialize)]
struct CertSpotterIssuance {
    /// Monotonic issuance id. certspotter pages are advanced by passing the
    /// largest id seen back as `after=<id>`. Serialized as a string.
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    dns_names: Vec<String>,
}

/// One parsed page of certspotter issuances: the DNS names it carried plus the
/// cursor to request the next page with (the largest issuance id on this page),
/// or `None` when the page was empty (pagination is complete).
pub(crate) struct CertSpotterPage {
    pub names: Vec<String>,
    /// Cursor for the next page (largest issuance id on this page), or `None`
    /// when the page was empty / pagination is complete.
    pub next_cursor: Option<String>,
}

/// Parse certspotter's `expand=dns_names` response into a flat name list,
/// discarding the cursor. Retained for the non-paginated [`Source::parse`] slot
/// and direct single-page tests; the live certspotter source paginates via
/// [`PaginationSpec`] (`certspotter_url_after` + [`parse_certspotter_page`]).
pub(crate) fn parse_certspotter(body: &[u8]) -> Result<Vec<String>> {
    Ok(parse_certspotter_page(body)?.names)
}

/// Parse a single certspotter page into its DNS names and the next-page cursor.
///
/// The cursor is the numerically-largest issuance `id` on the page (certspotter
/// ids are numeric strings, so a lexicographic max would mis-order "9" vs
/// "100"); it is `None` for an empty page, signalling the end of pagination.
pub(crate) fn parse_certspotter_page(body: &[u8]) -> Result<CertSpotterPage> {
    let issuances: Vec<CertSpotterIssuance> = serde_json::from_slice(body).map_err(|e| {
        SeerError::HttpError(format!("Failed to parse certspotter response: {}", e))
    })?;

    let next_cursor = issuances
        .iter()
        .filter_map(|i| i.id.as_deref())
        // Advance by numeric magnitude; fall back to keeping the id with the
        // largest parsed value. Ids that don't parse are ignored for cursoring.
        .filter_map(|id| id.parse::<u64>().ok().map(|n| (n, id)))
        .max_by_key(|(n, _)| *n)
        .map(|(_, id)| id.to_string());

    let names = issuances.into_iter().flat_map(|i| i.dns_names).collect();

    Ok(CertSpotterPage { names, next_cursor })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crtsh_url_encodes_wildcard() {
        assert_eq!(
            crtsh_url("https://crt.sh", "example.com"),
            "https://crt.sh/?q=%25.example.com&output=json"
        );
    }

    #[test]
    fn certspotter_url_includes_subdomains() {
        assert_eq!(
            certspotter_url("https://api.certspotter.com", "example.com"),
            "https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names"
        );
    }

    #[test]
    fn parse_crtsh_extracts_newline_separated_names() {
        let body =
            br#"[{"common_name":"example.com","name_value":"api.example.com\nmail.example.com"}]"#;
        let names = parse_crtsh(body).unwrap();
        assert!(names.contains(&"example.com".to_string()));
        assert!(names.contains(&"api.example.com".to_string()));
        assert!(names.contains(&"mail.example.com".to_string()));
    }

    #[test]
    fn parse_certspotter_extracts_dns_names() {
        let body = br#"[{"dns_names":["zac.app","www.zac.app"]},{"dns_names":["api.zac.app"]}]"#;
        let names = parse_certspotter(body).unwrap();
        assert!(names.contains(&"zac.app".to_string()));
        assert!(names.contains(&"www.zac.app".to_string()));
        assert!(names.contains(&"api.zac.app".to_string()));
    }

    #[test]
    fn certspotter_url_after_appends_cursor() {
        // The cursor-aware builder appends `&after=<id>` so a follow-up request
        // fetches the next page of issuances. The base (no-cursor) URL is the
        // `after=None` case and must be byte-identical to `certspotter_url`.
        assert_eq!(
            certspotter_url_after("https://api.certspotter.com", "example.com", None),
            certspotter_url("https://api.certspotter.com", "example.com"),
        );
        assert_eq!(
            certspotter_url_after("https://api.certspotter.com", "example.com", Some("12345")),
            "https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names&after=12345"
        );
    }

    #[test]
    fn parse_certspotter_page_extracts_names_and_next_cursor() {
        // A page parse yields both the dns_names and the highest issuance id on
        // the page, which becomes the `after=` cursor for the next request.
        let body =
            br#"[{"id":"100","dns_names":["a.zac.app"]},{"id":"205","dns_names":["b.zac.app"]}]"#;
        let page = parse_certspotter_page(body).unwrap();
        assert!(page.names.contains(&"a.zac.app".to_string()));
        assert!(page.names.contains(&"b.zac.app".to_string()));
        assert_eq!(
            page.next_cursor.as_deref(),
            Some("205"),
            "next cursor is the max issuance id on the page"
        );
    }

    #[test]
    fn parse_certspotter_page_empty_has_no_cursor() {
        // An empty page terminates pagination: no names, no cursor.
        let page = parse_certspotter_page(b"[]").unwrap();
        assert!(page.names.is_empty());
        assert!(page.next_cursor.is_none());
    }

    #[test]
    fn parse_certspotter_page_uses_numeric_max_not_lexicographic() {
        // certspotter ids are numeric strings; the cursor must advance by
        // numeric magnitude, not lexicographic order ("9" > "100" lexically).
        let body =
            br#"[{"id":"9","dns_names":["a.zac.app"]},{"id":"100","dns_names":["b.zac.app"]}]"#;
        let page = parse_certspotter_page(body).unwrap();
        assert_eq!(page.next_cursor.as_deref(), Some("100"));
    }

    #[test]
    fn parsers_error_on_html_body() {
        let html = b"<html>502 Bad Gateway</html>";
        assert!(parse_crtsh(html).is_err());
        assert!(parse_certspotter(html).is_err());
    }
}
