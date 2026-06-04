//! Availability lens — big verdict header + KV details.
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::{kv, panel};

pub fn render(f: &mut Frame, area: Rect, theme: &Theme, data: &LensData) {
    let LensData::Avail(a) = data else {
        return;
    };
    let block = panel::block(theme, "Availability", theme.peach, false);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(0)])
        .split(inner);

    // Big verdict header
    let verdict = a.verdict();
    let verdict_color = if a.available {
        theme.green
    } else {
        theme.peach
    };
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            verdict.to_uppercase(),
            Style::default()
                .fg(verdict_color)
                .add_modifier(Modifier::BOLD),
        ))),
        chunks[0],
    );

    let rows: Vec<(String, String)> = vec![
        ("domain".into(), a.domain.clone()),
        ("available".into(), a.available.to_string()),
        ("confidence".into(), a.confidence.clone()),
        ("method".into(), a.method.clone()),
        (
            "details".into(),
            a.details.clone().unwrap_or_else(|| "—".to_string()),
        ),
    ];
    kv::render(f, chunks[1], theme, theme.peach, &rows);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use seer_core::AvailabilityResult;

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
    fn renders_availability_fields() {
        let theme = Theme::frappe();
        let data = LensData::Avail(Box::new(AvailabilityResult {
            domain: "x.com".into(),
            available: true,
            confidence: "high".into(),
            method: "rdap".into(),
            details: None,
        }));
        let backend = TestBackend::new(70, 10);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &data))
            .unwrap();
        let text = buf_text(terminal.backend().buffer());
        assert!(text.contains("available"));
    }
}
