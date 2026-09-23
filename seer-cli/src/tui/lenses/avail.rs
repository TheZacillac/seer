//! Availability lens — big verdict header + KV details.
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::{kv, or_dash, panel};

pub fn render(f: &mut Frame, area: Rect, theme: &Theme, data: &LensData) {
    let LensData::Avail(a) = data else {
        return;
    };
    let inner = panel::render(f, area, theme, "Availability", theme.peach, false);

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

    let rows = [
        ("domain", a.domain.clone()),
        ("available", a.available.to_string()),
        ("confidence", a.confidence.clone()),
        ("method", a.method.clone()),
        ("details", or_dash(a.details.as_deref())),
    ];
    kv::render(f, chunks[1], theme, theme.peach, &rows);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::test_util::render_text;
    use seer_core::AvailabilityResult;

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
        let text = render_text(70, 10, |f| render(f, f.area(), &theme, &data));
        assert!(text.contains("available"));
    }
}
