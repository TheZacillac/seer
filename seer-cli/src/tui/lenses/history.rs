//! History lens — selectable table of past lookups.
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
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
    let LensData::History(entries) = data else {
        return;
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(area);

    let block = panel::block(theme, "Lookup History", theme.teal, focused);
    let inner = block.inner(chunks[0]);
    f.render_widget(block, chunks[0]);

    let header = Row::new(["WHEN", "DOMAIN", "SOURCE", "REGISTRAR"])
        .style(Style::default().fg(theme.overlay0));

    let rows = entries.iter().enumerate().map(|(i, e)| {
        let when = e.timestamp.format("%Y-%m-%d %H:%M").to_string();
        let source = if e.result.is_rdap() {
            "RDAP"
        } else if e.result.is_whois() {
            "WHOIS"
        } else {
            "—"
        };
        let registrar = e.result.registrar().unwrap_or_else(|| "—".to_string());

        let style = if focused && i == sel {
            Style::default().fg(theme.text).bg(theme.surface0)
        } else {
            Style::default().fg(theme.text)
        };

        Row::new(vec![when, e.domain.clone(), source.to_string(), registrar]).style(style)
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
    let mut state = scroll_to(focused.then_some(sel));
    f.render_stateful_widget(table, inner, &mut state);

    // Hint line
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "↵ replay · c clear",
            Style::default().fg(theme.overlay0),
        ))),
        chunks[1],
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

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
    fn renders_empty_history_without_panic() {
        let theme = Theme::frappe();
        let data = LensData::History(vec![]);
        let backend = TestBackend::new(80, 12);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &data, false, 0))
            .unwrap();
        // Should not panic, and the empty state still renders the panel
        // title and the hint line.
        let text = buf_text(terminal.backend().buffer());
        assert!(text.contains("History"), "panel title missing: {text:?}");
        assert!(text.contains("replay"), "hint line missing: {text:?}");
    }
}
