//! The 3 Options section's content: each field as `Label ‹value›`, laid
//! left to right and wrapped whole onto more rows. The cursor field is
//! highlighted while the section is focused, an open editor shows its
//! caret, and a refused value is red. Values are sanitized (Diff's and
//! Bulk's are typed or pasted) and a value wider than the box shows its
//! tail — or, in an open editor, the stretch around the caret, so it
//! stays visible.
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use seer_core::output::sanitize_line;

use crate::tui::line_editor::LineEditor;
use crate::tui::theme::Theme;
use crate::tui::widgets::{fit_caret, fit_tail};

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

/// The box's rows at `width` (inner width, borders excluded), plus the row
/// the `selected` field is on (0 if none is), so a box shorter than its rows
/// can scroll to the cursor.
pub fn rows(
    theme: &Theme,
    fields: &[Field],
    width: u16,
    focused: bool,
) -> (Vec<Line<'static>>, usize) {
    let width = usize::from(width.max(1));
    let mut selected_row = 0;
    let mut rows: Vec<Vec<Span<'static>>> = vec![vec![]];
    let mut used = 0usize;
    for f in fields {
        let label = format!("{} ", f.label);
        let label_w = Span::raw(label.as_str()).width();
        // One field never outgrows the box: label, `‹` and `›` stay.
        let room = width.saturating_sub(label_w + 2).max(1);
        let value = match f.editing {
            // An open editor keeps its caret in view, wherever it is.
            Some(buf) => {
                let (before, after) = buf.split_at_cursor();
                fit_caret(&sanitize_line(before), &sanitize_line(after), "▏", room)
            }
            None => fit_tail(&sanitize_line(&f.value), room),
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
        let chip = format!("‹{value}›");
        let w = label_w + Span::raw(chip.as_str()).width();
        let gap = if used == 0 { 0 } else { GAP.len() };
        if used > 0 && used + gap + w > width {
            rows.push(vec![]);
            used = 0;
        }
        if f.selected {
            selected_row = rows.len() - 1;
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
    (rows.into_iter().map(Line::from).collect(), selected_row)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::theme::Theme;

    fn lines(theme: &Theme, fields: &[Field], width: u16, focused: bool) -> Vec<Line<'static>> {
        rows(theme, fields, width, focused).0
    }

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
    fn a_long_value_keeps_its_tail_and_caret_within_the_width() {
        let t = Theme::frappe();
        let buf: LineEditor = "a.com b.com c.com d.com e.com f.com g.com".into();
        let mut f = field("Domains", "");
        f.editing = Some(&buf);
        let rows = text(&lines(&t, &[f], 30, true));
        assert_eq!(rows.len(), 1);
        assert!(
            rows[0].contains("…") && rows[0].contains("g.com▏›"),
            "{rows:?}"
        );
        assert!(Span::raw(rows[0].as_str()).width() <= 30, "{rows:?}");
    }

    #[test]
    fn wrapping_counts_display_columns() {
        let t = Theme::frappe();
        // Each field is 8 columns wide (CJK is 2 per char); `chars()` would say 6.
        let fields = [field("A", "日本"), field("B", "日本")];
        assert_eq!(lines(&t, &fields, 16, false).len(), 2);
        assert_eq!(lines(&t, &fields, 20, false).len(), 1);
    }

    #[test]
    fn the_selected_fields_row_is_reported() {
        let t = Theme::frappe();
        let mut fields = [
            field("Op", "status"),
            field("Source", "domains"),
            field("Domains", "a.com b.com"),
        ];
        fields[2].selected = true;
        assert_eq!(rows(&t, &fields, 30, true).1, 1);
        assert_eq!(rows(&t, &fields, 80, true).1, 0);
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
