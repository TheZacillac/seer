//! History lens — selectable table of past lookups; while focused, the
//! selected entry's full timestamp, registrar and expiry show beneath it.
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Row, Table};
use ratatui::Frame;
use seer_core::output::sanitize_line;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::inspector::{self, Field};
use crate::tui::widgets::{or_dash, panel, row_style, scroll_to, stack, Band};

/// `filter` is the active in-lens `/`-filter; rows are filtered by reference
/// (see `filter::history_rows`) so no entry is cloned per frame.
pub fn render(
    f: &mut Frame,
    area: Rect,
    theme: &Theme,
    data: &LensData,
    filter: &str,
    focused: bool,
    sel: usize,
) {
    let LensData::History(entries) = data else {
        return;
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(area);

    let inner = panel::render(f, chunks[0], theme, "Lookup History", theme.teal, focused);

    let header = Row::new(["WHEN", "DOMAIN", "SOURCE", "REGISTRAR"])
        .style(Style::default().fg(theme.overlay0));

    let rows = crate::tui::filter::history_rows(entries, filter)
        .enumerate()
        .map(|(i, e)| {
            let when = e.timestamp.format("%Y-%m-%d %H:%M").to_string();
            let source = e.result.protocol().unwrap_or("—");
            let registrar = sanitize_line(&or_dash(e.result.registrar()));
            Row::new(vec![
                when,
                sanitize_line(&e.domain),
                source.to_string(),
                registrar,
            ])
            .style(row_style(theme, focused && i == sel))
        });

    let table = Table::new(
        rows,
        [
            Constraint::Length(17),
            Constraint::Percentage(30),
            Constraint::Length(6),
            Constraint::Percentage(40),
        ],
    )
    .header(header)
    .column_spacing(1);
    // The detail follows the visible (filtered) row the table highlights.
    let detail = focused
        .then(|| crate::tui::filter::history_rows(entries, filter).nth(sel))
        .flatten()
        .map(|e| {
            let (expires, registrar) = e.result.expiration_info();
            let fields = [
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
            ];
            inspector::lines(theme, &fields, inner.width)
        })
        .unwrap_or_default();
    let rows = |n: usize| u16::try_from(n).unwrap_or(u16::MAX);
    let n = crate::tui::filter::history_rows(entries, filter).count();
    // The table keeps its header and a few rows; the detail takes the rest.
    let mut layout = vec![Band::shrinking(
        rows(n + 1),
        rows(1 + n.min(inspector::MIN_ROWS)),
    )];
    if !detail.is_empty() {
        layout.push(inspector::band(&detail));
    }
    let bands = stack(inner, &layout);
    let mut state = scroll_to(focused.then_some(sel));
    f.render_stateful_widget(table, bands[0], &mut state);
    if let Some(band) = bands.get(1) {
        inspector::draw(f, *band, theme, detail);
    }

    // Hint line
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "↵ replay · c clear all (press twice)",
            Style::default().fg(theme.overlay0),
        ))),
        chunks[1],
    );
}

#[cfg(test)]
mod tests {
    use super::*;
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
