//! Availability lens — big verdict header + KV details.
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::or_dash;
use crate::tui::widgets::page::{Block, Page};

pub fn page(theme: &Theme, data: &LensData) -> Option<Page> {
    let LensData::Avail(a) = data else {
        return None;
    };
    // Big verdict header
    let verdict_color = if a.available {
        theme.green
    } else {
        theme.peach
    };
    let verdict = Line::from(Span::styled(
        a.verdict().to_uppercase(),
        Style::default()
            .fg(verdict_color)
            .add_modifier(Modifier::BOLD),
    ));
    let rows = vec![
        ("domain", a.domain.clone()),
        ("available", a.available.to_string()),
        ("confidence", a.confidence.clone()),
        ("method", a.method.clone()),
        ("details", or_dash(a.details.as_deref())),
    ];
    Some(
        Page::new("Availability", theme.peach)
            .push(Block::Lines(vec![verdict]))
            .push(Block::Gap)
            .push(Block::Kv {
                key_color: theme.peach,
                rows,
            }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::widgets::page;

    /// Draw this lens's page as the TUI does.
    fn render(f: &mut ratatui::Frame, area: ratatui::layout::Rect, theme: &Theme, data: &LensData) {
        if let Some(p) = page(theme, data) {
            page::draw(f, area, theme, p, false);
        }
    }
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
