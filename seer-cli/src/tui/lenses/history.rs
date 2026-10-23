//! History lens — selectable table of past lookups; while focused, the
//! selected entry's full timestamp, registrar and expiry show beneath it.
use ratatui::layout::Constraint;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Row;
use seer_core::output::sanitize_line;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::inspector::Field;
use crate::tui::widgets::or_dash;
use crate::tui::widgets::page::{Block, Detail, Page, TableBlock};

/// `filter` is the active in-lens `/`-filter; rows are filtered by reference
/// (see `filter::history_rows`) so no entry is cloned per frame.
pub fn page(
    theme: &Theme,
    data: &LensData,
    filter: &str,
    focused: bool,
    sel: usize,
) -> Option<Page> {
    let LensData::History(entries) = data else {
        return None;
    };

    let rows = crate::tui::filter::history_rows(entries, filter)
        .map(|e| {
            let when = e.timestamp.format("%Y-%m-%d %H:%M").to_string();
            let source = e.result.protocol().unwrap_or("—");
            let registrar = sanitize_line(&or_dash(e.result.registrar()));
            Row::new(vec![
                when,
                sanitize_line(&e.domain),
                source.to_string(),
                registrar,
            ])
        })
        .collect();

    // The detail follows the visible (filtered) row the table highlights.
    let detail = focused
        .then(|| crate::tui::filter::history_rows(entries, filter).nth(sel))
        .flatten()
        .map_or(Detail::None, |e| {
            let (expires, registrar) = e.result.expiration_info();
            Detail::Fields(vec![
                Field::new("domain", e.domain.clone()),
                Field::new(
                    "looked up",
                    e.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                ),
                Field::new("source", e.result.protocol().unwrap_or("—")),
                Field::new("registrar", or_dash(registrar)),
                Field::new(
                    "expires",
                    or_dash(expires.map(|d| d.format("%Y-%m-%d").to_string())),
                ),
            ])
        });
    let table = TableBlock::new(
        vec!["WHEN", "DOMAIN", "SOURCE", "REGISTRAR"],
        vec![
            Constraint::Length(17),
            Constraint::Percentage(30),
            Constraint::Length(6),
            Constraint::Percentage(40),
        ],
        rows,
    )
    .selected(focused.then_some(sel))
    .detail(detail);
    Some(
        Page::new("Lookup History", theme.teal)
            .push(Block::Table(table))
            .push(Block::Gap)
            .push(Block::Lines(vec![Line::from(Span::styled(
                "↵ replay · c clear all (press twice)",
                Style::default().fg(theme.overlay0),
            ))])),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::widgets::page;

    /// Draw this lens's page as the TUI does.
    fn render(
        f: &mut ratatui::Frame,
        area: ratatui::layout::Rect,
        theme: &Theme,
        data: &LensData,
        filter: &str,
        focused: bool,
        sel: usize,
    ) {
        if let Some(p) = page(theme, data, filter, focused, sel) {
            page::draw(f, area, theme, p, focused);
        }
    }
    use crate::tui::test_util::{render_lines, render_text};

    fn entry(domain: &str) -> seer_core::HistoryEntry {
        use seer_core::{HistoryEntry, LookupResult, WhoisResponse};
        let whois = WhoisResponse {
            domain: domain.to_string(),
            registrar: Some("Example Registrar".into()),
            ..Default::default()
        };
        HistoryEntry {
            domain: domain.to_string(),
            timestamp: chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0).unwrap(),
            result: LookupResult::Whois {
                data: whois,
                rdap_error: None,
                rdap_fallback: None,
                dns_nameservers: None,
            },
        }
    }

    #[test]
    fn focused_entry_shows_full_timestamp_and_registrar() {
        let theme = Theme::frappe();
        let data = LensData::History(vec![entry("old.com")]);
        let s = render_lines(100, 20, |f| render(f, f.area(), &theme, &data, "", true, 0));
        assert!(s.contains("1970-01-01 00:00:00 UTC"), "{s}");
        let nav = render_lines(100, 20, |f| {
            render(f, f.area(), &theme, &data, "", false, 0);
        });
        assert!(!nav.contains("00:00:00 UTC"), "{nav}");
    }

    #[test]
    fn renders_empty_history_without_panic() {
        let theme = Theme::frappe();
        let data = LensData::History(vec![]);
        let text = render_text(80, 12, |f| render(f, f.area(), &theme, &data, "", false, 0));
        // Should not panic, and the empty state still renders the panel
        // title and the hint line.
        assert!(text.contains("History"), "panel title missing: {text:?}");
        assert!(text.contains("replay"), "hint line missing: {text:?}");
    }
}
