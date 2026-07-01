//! Case-insensitive in-lens row filtering for the table lenses (subdomains,
//! history, propagation).
//!
//! [`apply`] returns a filtered clone of the lens data; it is used by BOTH the
//! renderer and `App::row_count`, so the displayed rows, the selection index
//! space, and scrolling always agree on the same visible subset.

use crate::tui::action::LensData;

/// Whether `text` contains `filter`, case-insensitively. An empty filter
/// matches everything.
pub fn matches(text: &str, filter: &str) -> bool {
    filter.is_empty() || text.to_lowercase().contains(&filter.to_lowercase())
}

/// Whether a lens key supports in-lens `/`-filtering.
pub fn is_filterable(lens_key: &str) -> bool {
    matches!(lens_key, "subdomains" | "history" | "propagation")
}

/// The filterable text for a history row (mirrors the columns the lens shows).
fn history_label(e: &seer_core::HistoryEntry) -> String {
    let source = if e.result.is_rdap() {
        "RDAP"
    } else if e.result.is_whois() {
        "WHOIS"
    } else {
        "-"
    };
    format!(
        "{} {} {} {}",
        e.timestamp.format("%Y-%m-%d %H:%M"),
        e.domain,
        source,
        e.result.registrar().unwrap_or_default(),
    )
}

/// Returns a filtered clone of `data` for a filterable lens with a non-empty
/// filter, or `None` (the caller renders/counts the original unchanged).
pub fn apply(data: &LensData, filter: &str) -> Option<LensData> {
    if filter.is_empty() {
        return None;
    }
    match data {
        LensData::Subdomains(s) => {
            let mut r = (**s).clone();
            r.subdomains.retain(|host| matches(host, filter));
            r.count = r.subdomains.len();
            Some(LensData::Subdomains(Box::new(r)))
        }
        LensData::History(entries) => {
            let filtered: Vec<_> = entries
                .iter()
                .filter(|e| matches(&history_label(e), filter))
                .cloned()
                .collect();
            Some(LensData::History(filtered))
        }
        LensData::Prop(p) => {
            let mut r = (**p).clone();
            // Inline label (avoids naming the per-server element type).
            r.results.retain(|sr| {
                let answer = sr
                    .records
                    .first()
                    .map(|rec| rec.format_short())
                    .unwrap_or_default();
                let label = format!(
                    "{} {} {} {}",
                    sr.server.ip, sr.server.provider, sr.server.location, answer
                );
                matches(&label, filter)
            });
            Some(LensData::Prop(Box::new(r)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_is_case_insensitive_and_empty_matches_all() {
        assert!(matches("API.example.com", "api"));
        assert!(matches("anything", ""));
        assert!(!matches("host.example.com", "zzz"));
    }

    #[test]
    fn is_filterable_covers_the_table_lenses() {
        assert!(is_filterable("subdomains"));
        assert!(is_filterable("history"));
        assert!(is_filterable("propagation"));
        assert!(!is_filterable("whois"));
    }

    #[test]
    fn apply_filters_subdomains_and_updates_count() {
        let result = seer_core::SubdomainResult {
            domain: "example.com".into(),
            subdomains: vec![
                "api.example.com".into(),
                "mail.example.com".into(),
                "api-staging.example.com".into(),
            ],
            source: "crt.sh".into(),
            count: 3,
        };
        let data = LensData::Subdomains(Box::new(result));
        let filtered = apply(&data, "api").expect("filter applies");
        let LensData::Subdomains(s) = filtered else {
            panic!("wrong variant");
        };
        assert_eq!(s.subdomains.len(), 2);
        assert_eq!(s.count, 2);
        assert!(s.subdomains.iter().all(|h| h.contains("api")));
    }

    #[test]
    fn apply_returns_none_for_empty_filter_or_unfilterable_lens() {
        let result = seer_core::SubdomainResult {
            domain: "example.com".into(),
            subdomains: vec!["a.example.com".into()],
            source: "crt.sh".into(),
            count: 1,
        };
        let data = LensData::Subdomains(Box::new(result));
        assert!(apply(&data, "").is_none());
    }
}
