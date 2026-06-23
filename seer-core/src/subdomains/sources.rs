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
        },
        Source {
            name: "certspotter (Certificate Transparency)",
            base: "https://api.certspotter.com".to_string(),
            build_url: certspotter_url,
            parse: parse_certspotter,
        },
    ]
}

fn crtsh_url(base: &str, domain: &str) -> String {
    // `%25` is an encoded `%` wildcard: match all labels under `domain`.
    format!("{}/?q=%25.{}&output=json", base, domain)
}

fn certspotter_url(base: &str, domain: &str) -> String {
    format!(
        "{}/v1/issuances?domain={}&include_subdomains=true&expand=dns_names",
        base, domain
    )
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
    #[serde(default)]
    dns_names: Vec<String>,
}

/// Parse certspotter's `expand=dns_names` response: an array of issuances each
/// carrying a `dns_names` array.
pub(crate) fn parse_certspotter(body: &[u8]) -> Result<Vec<String>> {
    let issuances: Vec<CertSpotterIssuance> = serde_json::from_slice(body).map_err(|e| {
        SeerError::HttpError(format!("Failed to parse certspotter response: {}", e))
    })?;

    Ok(issuances.into_iter().flat_map(|i| i.dns_names).collect())
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
    fn parsers_error_on_html_body() {
        let html = b"<html>502 Bad Gateway</html>";
        assert!(parse_crtsh(html).is_err());
        assert!(parse_certspotter(html).is_err());
    }
}
