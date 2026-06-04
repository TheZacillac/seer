//! TLD Info lens — chip switcher + KV display of TLD registry data.
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::tui::action::LensData;
use crate::tui::panes::{tld::TLDS, Panes};
use crate::tui::theme::Theme;
use crate::tui::widgets::{kv, panel};

pub fn render(f: &mut Frame, area: Rect, theme: &Theme, data: &LensData, panes: &Panes) {
    let LensData::Tld(t) = data else {
        return;
    };

    let block = panel::block(theme, "TLD Info", theme.maroon, false);
    let inner = block.inner(area);
    f.render_widget(block, area);

    // Split into: chips row (1 line) + hint (1 line) + KV
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .split(inner);

    // Chip row — highlight selected TLD with mauve, others with subtext
    let selected = panes.tld.idx;
    let mut spans: Vec<Span> = Vec::new();
    for (i, tld) in TLDS.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw(" "));
        }
        let style = if i == selected {
            Style::default().fg(theme.base).bg(theme.mauve)
        } else {
            Style::default().fg(theme.subtext).bg(theme.surface0)
        };
        spans.push(Span::styled(format!(" {tld} "), style));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), chunks[0]);

    // Hint line
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "h/l switch TLD",
            Style::default().fg(theme.overlay0),
        ))),
        chunks[1],
    );

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
    kv::render(f, chunks[2], theme, theme.maroon, &rows);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::panes::Panes;
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

    fn tld_fixture() -> seer_core::TldInfo {
        TldInfo {
            tld: ".com".into(),
            whois_server: Some("whois.verisign-grs.com".into()),
            rdap_url: None,
            registry_url: None,
            tld_type: "gTLD".into(),
        }
    }

    #[test]
    fn renders_whois_server() {
        let theme = Theme::frappe();
        let data = LensData::Tld(Box::new(tld_fixture()));
        let panes = Panes::default();
        let backend = TestBackend::new(70, 12);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &data, &panes))
            .unwrap();
        assert!(buf_text(terminal.backend().buffer()).contains("whois.verisign-grs.com"));
    }

    #[test]
    fn renders_chip_row_with_all_tlds() {
        let theme = Theme::frappe();
        let data = LensData::Tld(Box::new(tld_fixture()));
        let panes = Panes::default();
        let backend = TestBackend::new(80, 12);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &data, &panes))
            .unwrap();
        let text = buf_text(terminal.backend().buffer());
        assert!(text.contains(".com"), "chip row should contain .com");
        assert!(text.contains(".net"), "chip row should contain .net");
        assert!(text.contains(".io"), "chip row should contain .io");
    }

    #[test]
    fn selected_chip_matches_pane_idx() {
        let theme = Theme::frappe();
        let data = LensData::Tld(Box::new(tld_fixture()));
        let mut panes = Panes::default();
        panes.tld.idx = 2; // .org
        let backend = TestBackend::new(80, 12);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &data, &panes))
            .unwrap();
        let text = buf_text(terminal.backend().buffer());
        assert!(
            text.contains(".org"),
            "selected chip .org should be visible"
        );
    }
}
