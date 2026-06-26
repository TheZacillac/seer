//! Subdomains lens — selectable single-column table of CT-log subdomains.
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Row, Table};
use ratatui::Frame;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::{panel, scroll_to};

pub fn render(
    f: &mut Frame,
    area: Rect,
    theme: &Theme,
    data: &LensData,
    focused: bool,
    sel: usize,
) {
    let LensData::Subdomains(s) = data else {
        return;
    };

    let title = format!("Subdomains · {} via {}", s.count, s.source);
    let block = panel::block(theme, &title, theme.pink, focused);
    let inner = block.inner(area);
    f.render_widget(block, area);

    if s.subdomains.is_empty() {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "no subdomains found",
                Style::default()
                    .fg(theme.overlay0)
                    .add_modifier(Modifier::ITALIC),
            ))),
            inner,
        );
        return;
    }

    let header = Row::new(["HOST"]).style(Style::default().fg(theme.overlay0));

    let rows = s.subdomains.iter().enumerate().map(|(i, host)| {
        let style = if focused && i == sel {
            Style::default().fg(theme.text).bg(theme.surface0)
        } else {
            Style::default().fg(theme.text)
        };
        Row::new(vec![host.clone()]).style(style)
    });

    let table = Table::new(rows, [Constraint::Percentage(100)])
        .header(header)
        .column_spacing(1);
    let mut state = scroll_to(focused.then_some(sel));
    f.render_stateful_widget(table, inner, &mut state);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use seer_core::SubdomainResult;

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

    #[test]
    fn renders_subdomain_rows() {
        let theme = Theme::frappe();
        let data = LensData::Subdomains(Box::new(SubdomainResult {
            domain: "example.com".into(),
            subdomains: vec!["www.example.com".into(), "api.example.com".into()],
            source: "crt.sh".into(),
            count: 2,
        }));
        let backend = TestBackend::new(70, 10);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &data, false, 0))
            .unwrap();
        let text = buf_text(terminal.backend().buffer());
        assert!(text.contains("www.example.com"));
    }

    #[test]
    fn selecting_past_viewport_scrolls_last_row_into_view() {
        let theme = Theme::frappe();
        let hosts: Vec<String> = (0..60).map(|i| format!("h{i}.example.com")).collect();
        let data = LensData::Subdomains(Box::new(SubdomainResult {
            domain: "example.com".into(),
            subdomains: hosts,
            source: "crt.sh".into(),
            count: 60,
        }));
        // Short terminal can't fit 60 rows; without scrolling the last host
        // would never render even when selected.
        let backend = TestBackend::new(60, 10);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &data, true, 59))
            .unwrap();
        let text = buf_text(terminal.backend().buffer());
        assert!(
            text.contains("h59.example.com"),
            "selecting the last row must scroll it into view"
        );
    }

    #[test]
    fn renders_empty_gracefully() {
        let theme = Theme::frappe();
        let data = LensData::Subdomains(Box::new(SubdomainResult {
            domain: "example.com".into(),
            subdomains: vec![],
            source: "crt.sh".into(),
            count: 0,
        }));
        let backend = TestBackend::new(60, 6);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &data, false, 0))
            .unwrap();
        let text = buf_text(terminal.backend().buffer());
        assert!(text.contains("no subdomains found"));
    }
}
