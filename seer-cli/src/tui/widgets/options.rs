//! The 3 Options section's content: each field as `Label ‹value›`, laid
//! left to right and wrapped whole onto more rows. The cursor field is
//! highlighted while the section is focused, an open editor shows its
//! caret, and a refused value is red. Values are sanitized: Diff's and
//! Bulk's are typed or pasted.
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use seer_core::output::sanitize_line;

use crate::tui::line_editor::LineEditor;
use crate::tui::theme::Theme;

/// One option as the box shows it.
pub struct Field<'a> {
    pub label: &'static str,
    pub value: String,
    /// The value is a hint for an unset field, drawn dim.
    pub placeholder: bool,
    /// The section's cursor is on this field.
    pub selected: bool,
    /// The open editor, if this field is being typed into.
    pub editing: Option<&'a LineEditor>,
    /// The last commit of this field was refused.
    pub invalid: bool,
}

/// Gap between fields on a row.
const GAP: &str = "   ";

/// The box's rows at `width` (inner width, borders excluded).
pub fn lines(theme: &Theme, fields: &[Field], width: u16, focused: bool) -> Vec<Line<'static>> {
    let width = usize::from(width.max(1));
    let mut rows: Vec<Vec<Span<'static>>> = vec![vec![]];
    let mut used = 0usize;
    for f in fields {
        let value = match f.editing {
            Some(buf) => sanitize_line(&buf.with_caret("▏")),
            None => sanitize_line(&f.value),
        };
        let value_style = if f.invalid {
            Style::default().fg(theme.red)
        } else if f.placeholder && f.editing.is_none() {
            Style::default()
                .fg(theme.overlay0)
                .add_modifier(Modifier::ITALIC)
        } else {
            Style::default().fg(theme.text)
        };
        let value_style = if focused && f.selected {
            value_style.bg(theme.surface0).add_modifier(Modifier::BOLD)
        } else {
            value_style
        };
        let label = format!("{} ", f.label);
        let chip = format!("‹{value}›");
        let w = label.chars().count() + chip.chars().count();
        let gap = if used == 0 { 0 } else { GAP.len() };
        if used > 0 && used + gap + w > width {
            rows.push(vec![]);
            used = 0;
        }
        let row = rows.last_mut().expect("rows starts non-empty");
        if used > 0 {
            row.push(Span::raw(GAP));
            used += GAP.len();
        }
        row.push(Span::styled(label, Style::default().fg(theme.subtext)));
        row.push(Span::styled(chip, value_style));
        used += w;
    }
    rows.into_iter().map(Line::from).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::theme::Theme;

    fn text(lines: &[Line]) -> Vec<String> {
        lines
            .iter()
            .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect())
            .collect()
    }

    fn field(label: &'static str, value: &str) -> Field<'static> {
        Field {
            label,
            value: value.into(),
            placeholder: false,
            selected: false,
            editing: None,
            invalid: false,
        }
    }

    #[test]
    fn fields_wrap_whole_onto_more_rows() {
        let t = Theme::frappe();
        let fields = [
            field("Op", "status"),
            field("Source", "domains"),
            field("Domains", "a.com b.com"),
        ];
        assert_eq!(text(&lines(&t, &fields, 80, false)).len(), 1);
        let rows = text(&lines(&t, &fields, 30, false));
        assert!(rows.len() > 1);
        assert!(
            rows.iter().all(|r| !r.ends_with("Domains")),
            "a label never splits from its value"
        );
    }

    #[test]
    fn remote_text_is_sanitized() {
        let t = Theme::frappe();
        let rows = text(&lines(
            &t,
            &[field("Compare with", "evil\u{1b}[2J.com")],
            80,
            false,
        ));
        assert!(!rows[0].contains('\u{1b}'));
    }
}
