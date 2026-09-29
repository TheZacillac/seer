//! Case-insensitive in-lens row filtering for the table lenses (subdomains,
//! history, propagation, takeover, and the DNS lens's Records tab).
//!
//! [`apply`] returns a filtered clone of the lens data; it is used by BOTH the
//! renderer and `App::row_count`, so the displayed rows, the selection index
//! space, and scrolling always agree on the same visible subset.
//!
//! History and dig results are the exceptions, filtered by reference instead
//! ([`history_rows`], [`dig_rows`]), which the renderer and `row_count` (and
//! History's selection lookup) share. History entries carry full lookup
//! results (raw WHOIS included) and can number in the tens of thousands, so
//! deep-cloning the matches every 100ms frame is prohibitive. A dig result
//! is small, but it describes the whole response: dropping answers from a
//! clone would turn its NOERROR verdict into a false "no records" (NODATA).

use seer_core::output::sanitize_line;
use seer_core::DnsRecord;

use crate::tui::action::LensData;

/// Whether `text` contains `filter`, case-insensitively. An empty filter
/// matches everything.
pub fn matches(text: &str, filter: &str) -> bool {
    filter.is_empty() || text.to_lowercase().contains(&filter.to_lowercase())
}

/// Whether a lens's sub-`tab` supports in-lens `/`-filtering. Of the DNS
/// lens's tabs only Records lists rows.
pub fn is_filterable(lens_key: &str, tab: usize) -> bool {
    match lens_key {
        "subdomains" | "history" | "propagation" | "takeover" => true,
        "dns" => tab == 0,
        _ => false,
    }
}

/// The filterable text for a history row (mirrors the columns the lens shows).
fn history_label(e: &seer_core::HistoryEntry) -> String {
    format!(
        "{} {} {} {}",
        e.timestamp.format("%Y-%m-%d %H:%M"),
        e.domain,
        crate::ops::lookup_source(&e.result).unwrap_or("-"),
        e.result.registrar().unwrap_or_default(),
    )
}

/// The history entries visible under `filter` (all of them when it is empty),
/// borrowed in display order — no entry is cloned.
pub fn history_rows<'a>(
    entries: &'a [seer_core::HistoryEntry],
    filter: &str,
) -> impl Iterator<Item = &'a seer_core::HistoryEntry> + 'a {
    let needle = filter.to_lowercase();
    entries
        .iter()
        .filter(move |e| needle.is_empty() || history_label(e).to_lowercase().contains(&needle))
}

/// A dig answer row's filterable text: the owner, TTL, type and data columns
/// the DNS lens shows, sanitized as it shows them.
fn dig_label(r: &DnsRecord) -> String {
    format!(
        "{} {} {} {}",
        sanitize_line(&r.name),
        r.ttl,
        r.record_type,
        sanitize_line(&r.data.to_string()),
    )
}

/// The ANSWER rows of a dig result visible under `filter` (all of them when
/// it is empty), borrowed in display order — the CNAME chain, then the
/// records. Each comes with whether it is an answer proper rather than a
/// hop of the chain.
pub fn dig_rows<'a>(
    result: &'a seer_core::DnsQueryResult,
    filter: &str,
) -> impl Iterator<Item = (&'a DnsRecord, bool)> + 'a {
    let needle = filter.to_lowercase();
    let chain = result.cname_chain().map(|r| (r, false));
    chain
        .chain(result.records().map(|r| (r, true)))
        .filter(move |(r, _)| needle.is_empty() || dig_label(r).to_lowercase().contains(&needle))
}

/// Returns a filtered clone of `data` for a filterable lens with a non-empty
/// filter, or `None` (the caller renders/counts the original unchanged).
/// History and dig results always return `None`; they are filtered via
/// [`history_rows`] and [`dig_rows`].
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
            r.results.retain(|sr| {
                let label = format!(
                    "{} {} {} {} {}",
                    sr.server.name,
                    sr.server.ip,
                    sr.server.provider,
                    sr.server.location,
                    crate::tui::lenses::propagation::answer_text(p, sr)
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
        assert!(is_filterable("subdomains", 0));
        assert!(is_filterable("history", 0));
        assert!(is_filterable("propagation", 0));
        assert!(!is_filterable("whois", 0));
        // DNS: Records only — DNSSEC, Compare and Trace list no rows.
        assert!(is_filterable("dns", 0));
        for tab in 1..=3 {
            assert!(!is_filterable("dns", tab), "tab {tab}");
        }
    }

    fn chained() -> seer_core::DnsQueryResult {
        use crate::payload::fixtures;
        fixtures::dig(
            seer_core::RecordType::A,
            vec![
                fixtures::cname("www.seer.test", "edge.cdn.test."),
                fixtures::a("edge.cdn.test", "192.0.2.7"),
                fixtures::a("edge.cdn.test", "192.0.2.8"),
            ],
        )
    }

    #[test]
    fn dig_rows_match_the_shown_columns_and_mark_the_chain() {
        let result = chained();
        let all: Vec<(String, bool)> = dig_rows(&result, "")
            .map(|(r, answer)| (r.name.clone(), answer))
            .collect();
        assert_eq!(
            all,
            [
                ("www.seer.test".to_string(), false),
                ("edge.cdn.test".to_string(), true),
                ("edge.cdn.test".to_string(), true),
            ]
        );
        // Data, type and owner all match, case-insensitively.
        assert_eq!(dig_rows(&result, "192.0.2.8").count(), 1);
        assert_eq!(dig_rows(&result, "cname").count(), 1);
        assert_eq!(dig_rows(&result, "EDGE").count(), 3, "owner or target");
        assert_eq!(dig_rows(&result, "zzz").count(), 0);
        // By reference: the result keeps every answer, so its verdict holds.
        assert!(apply(&LensData::Dig(Box::new(result.clone())), "zzz").is_none());
        assert!(!result.is_nodata());
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
        assert!(is_filterable("takeover", 0));
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
