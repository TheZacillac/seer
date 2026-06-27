//! TLD Browser lens — live-filterable, scrollable list over the full TLD
//! catalog with a per-TLD registry detail panel.
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Row, Table};
use ratatui::Frame;

use crate::tui::panes::tld::{filter_catalog, TldState};
use crate::tui::theme::Theme;
use crate::tui::widgets::{kv, panel, scroll_to};
use seer_core::TldInfo;

/// Render the TLD browser. `loaded` is the detail for the most recently fetched
/// TLD (if any); `loading` is true while a fetch is in flight; `editing` is the
/// in-progress filter buffer when the filter field is active (drives live
/// filtering).
pub fn render(
    f: &mut Frame,
    area: Rect,
    theme: &Theme,
    state: &TldState,
    loaded: Option<&TldInfo>,
    loading: bool,
    editing: Option<&str>,
) {
    let block = panel::block(theme, "TLD Browser", theme.maroon, false);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // filter line
            Constraint::Length(1), // hint line
            Constraint::Min(3),    // list
            Constraint::Length(8), // detail
        ])
        .split(inner);

    // The list filters live against the in-progress edit buffer when the filter
    // field is active, otherwise against the committed filter.
    let effective_filter = editing.unwrap_or(&state.filter);
    let list = filter_catalog(effective_filter);
    let sel = if list.is_empty() {
        0
    } else {
        state.sel.min(list.len() - 1)
    };

    // ── filter line ──────────────────────────────────────────────────────────
    let filter_line = if let Some(buf) = editing {
        Line::from(vec![
            Span::styled("filter: ", Style::default().fg(theme.overlay0)),
            Span::styled(format!("{buf}▏"), Style::default().fg(theme.text)),
            Span::styled(
                format!("   {} match{}", list.len(), plural(list.len())),
                Style::default().fg(theme.overlay0),
            ),
        ])
    } else if state.filter.is_empty() {
        Line::from(vec![
            Span::styled("filter: ", Style::default().fg(theme.overlay0)),
            Span::styled(
                format!("(all {} TLDs)", list.len()),
                Style::default().fg(theme.overlay0),
            ),
        ])
    } else {
        Line::from(vec![
            Span::styled("filter: ", Style::default().fg(theme.overlay0)),
            Span::styled(state.filter.clone(), Style::default().fg(theme.sky)),
            Span::styled(
                format!("   {} match{}", list.len(), plural(list.len())),
                Style::default().fg(theme.overlay0),
            ),
        ])
    };
    f.render_widget(Paragraph::new(filter_line), chunks[0]);

    // ── hint line ──────────────────────────────────────────────────────────
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "/ filter  ·  j/k move  ·  g/G top/bottom  ·  ↵ load details",
            Style::default().fg(theme.overlay0),
        ))),
        chunks[1],
    );

    // ── list ─────────────────────────────────────────────────────────────────
    if list.is_empty() {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "no TLDs match — adjust the filter",
                Style::default().fg(theme.overlay0),
            ))),
            chunks[2],
        );
    } else {
        let rows = list.iter().enumerate().map(|(i, tld)| {
            let style = if i == sel {
                Style::default().fg(theme.text).bg(theme.surface0)
            } else {
                Style::default().fg(theme.subtext)
            };
            Row::new(vec![Line::from(format!(".{tld}"))]).style(style)
        });
        let table = Table::new(rows, [Constraint::Percentage(100)]).column_spacing(0);
        let mut ts = scroll_to(Some(sel));
        f.render_stateful_widget(table, chunks[2], &mut ts);
    }

    // ── detail ─────────────────────────────────────────────────────────────
    let detail_block = panel::block(theme, "Registry", theme.maroon, false);
    let detail_inner = detail_block.inner(chunks[3]);
    f.render_widget(detail_block, chunks[3]);

    let selected_dotted = list.get(sel).map(|t| format!(".{t}")).unwrap_or_default();

    if loading {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                format!("querying {selected_dotted}…"),
                Style::default().fg(theme.overlay),
            ))),
            detail_inner,
        );
        return;
    }

    // Only show the loaded detail when it matches the highlighted TLD, so moving
    // the selection without reloading doesn't show stale data for another TLD.
    let detail_matches = loaded.is_some_and(|t| {
        let want = selected_dotted.trim_start_matches('.');
        t.tld.trim_start_matches('.') == want
    });

    if let (true, Some(t)) = (detail_matches, loaded) {
        let dash = || "—".to_string();
        let rows: Vec<(String, String)> = vec![
            ("tld".into(), t.tld.clone()),
            ("type".into(), t.tld_type.clone()),
            ("whois".into(), t.whois_server.clone().unwrap_or_else(dash)),
            ("rdap".into(), t.rdap_url.clone().unwrap_or_else(dash)),
            (
                "registry".into(),
                t.registry_url.clone().unwrap_or_else(dash),
            ),
        ];
        kv::render(f, detail_inner, theme, theme.maroon, &rows);
    } else {
        let hint = if selected_dotted.is_empty() {
            "—".to_string()
        } else {
            format!("press ↵ to load details for {selected_dotted}")
        };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                hint,
                Style::default().fg(theme.overlay0),
            ))),
            detail_inner,
        );
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "es"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::panes::tld::TldState;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use seer_core::TldInfo;

    fn buf_text(buf: &ratatui::buffer::Buffer) -> String {
        let a = buf.area();
        let mut s = String::new();
        for y in 0..a.height {
            for x in 0..a.width {
                s.push_str(buf[(x, y)].symbol());
            }
        }
        s
    }

    fn com_info() -> TldInfo {
        TldInfo {
            tld: "com".into(),
            whois_server: Some("whois.verisign-grs.com".into()),
            rdap_url: None,
            registry_url: None,
            tld_type: "generic".into(),
        }
    }

    fn draw(state: &TldState, loaded: Option<&TldInfo>, editing: Option<&str>) -> String {
        let theme = Theme::frappe();
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, state, loaded, false, editing))
            .unwrap();
        buf_text(terminal.backend().buffer())
    }

    #[test]
    fn lists_many_tlds_and_count() {
        let state = TldState::default();
        let text = draw(&state, None, None);
        // The "(all N TLDs)" count should reflect the full catalog.
        assert!(text.contains("all "), "should show the all-TLDs count");
        assert!(text.contains("TLDs"), "should label the count");
        // A few well-known TLDs should be visible somewhere in the rendered list.
        assert!(text.contains(".com"), "list should contain .com");
    }

    #[test]
    fn live_filter_buffer_narrows_the_list() {
        let state = TldState::default();
        // Editing buffer "shop" filters live without mutating committed state.
        let text = draw(&state, None, Some("shop"));
        assert!(text.contains("filter: shop"), "shows the edit buffer");
        assert!(text.contains(".shop"), "filtered list shows .shop");
        assert!(!text.contains(".com "), "unrelated TLDs filtered out");
    }

    #[test]
    fn detail_shows_loaded_tld_matching_selection() {
        let state = TldState::default(); // selected .com
        let info = com_info();
        let text = draw(&state, Some(&info), None);
        assert!(
            text.contains("whois.verisign-grs.com"),
            "detail panel should render the loaded TLD's whois server"
        );
    }

    #[test]
    fn detail_hint_when_nothing_loaded() {
        let state = TldState::default();
        let text = draw(&state, None, None);
        assert!(
            text.contains("press ↵ to load details"),
            "should prompt to load details when none are loaded"
        );
    }

    #[test]
    fn empty_filter_match_shows_placeholder() {
        let state = TldState::default();
        let text = draw(&state, None, Some("zzzznotatld"));
        assert!(
            text.contains("no TLDs match"),
            "empty match set should show a placeholder"
        );
    }
}
