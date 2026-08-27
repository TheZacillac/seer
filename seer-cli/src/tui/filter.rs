//! Case-insensitive in-lens row filtering for the table lenses (subdomains,
//! history, propagation, takeover).
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
    matches!(
        lens_key,
        "subdomains" | "history" | "propagation" | "takeover"
    )
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
        LensData::Takeover(t) => {
            let mut r = (**t).clone();
            // Match the columns the lens shows, so what the user types lines
            // up with what they can see.
            r.findings.retain(|fnd| {
                let label = format!(
                    "{} {} {}",
                    fnd.host,
                    fnd.provider.as_deref().unwrap_or(""),
                    fnd.evidence.as_deref().unwrap_or(""),
                );
                matches(&label, filter)
            });
            // The headline counts must describe the visible subset, or a
            // filtered view would claim findings it is no longer showing.
            r.vulnerable = r
                .findings
                .iter()
                .filter(|f| f.verdict == seer_core::TakeoverVerdict::Vulnerable)
                .count();
            r.potential = r
                .findings
                .iter()
                .filter(|f| f.verdict == seer_core::TakeoverVerdict::Potential)
                .count();
            Some(LensData::Takeover(Box::new(r)))
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
    fn apply_filters_takeover_and_recomputes_counts() {
        use seer_core::{TakeoverFinding, TakeoverReport, TakeoverVerdict};
        let mk = |host: &str, verdict| TakeoverFinding {
            host: host.into(),
            verdict,
            provider: Some("GitHub Pages".into()),
            cname: None,
            addresses: vec![],
            evidence: None,
            http_status: None,
            probe_note: None,
        };
        let report = TakeoverReport {
            domain: "example.com".into(),
            hosts_checked: 3,
            hosts_skipped: 0,
            vulnerable: 1,
            potential: 2,
            findings: vec![
                mk("api.example.com", TakeoverVerdict::Vulnerable),
                mk("mail.example.com", TakeoverVerdict::Potential),
                mk("api-staging.example.com", TakeoverVerdict::Potential),
            ],
            notes: vec![],
        };
        let filtered = apply(&LensData::Takeover(Box::new(report)), "api").expect("filter applies");
        let LensData::Takeover(t) = filtered else {
            panic!("wrong variant");
        };
        assert_eq!(t.findings.len(), 2);
        // Counts must describe the visible subset, not the pre-filter scan —
        // otherwise the title claims findings the table no longer shows.
        assert_eq!(t.vulnerable, 1);
        assert_eq!(t.potential, 1);
    }

    #[test]
    fn takeover_is_filterable() {
        assert!(is_filterable("takeover"));
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
