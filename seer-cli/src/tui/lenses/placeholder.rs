//! "Planned — not yet wired" pane for lenses not implemented this pass.
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::tui::theme::Theme;
use crate::tui::widgets::panel;

pub fn render(f: &mut Frame, area: Rect, theme: &Theme, label: &str) {
    let block = panel::block(theme, label, theme.overlay0, false);
    let inner = block.inner(area);
    f.render_widget(block, area);
    let lines = vec![
        Line::from(Span::styled(
            "planned — not yet wired",
            Style::default()
                .fg(theme.overlay)
                .add_modifier(Modifier::ITALIC),
        )),
        Line::raw(""),
        Line::from(Span::styled(
            "this lens is part of a follow-up pass",
            Style::default().fg(theme.overlay0),
        )),
    ];
    f.render_widget(Paragraph::new(lines), inner);
}
