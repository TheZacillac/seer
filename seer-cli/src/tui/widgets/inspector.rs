//! The selected row's detail, drawn as a band under a lens's table: one
//! `label  value` field per line, labels sharing a gutter, values sanitized
//! and wrapped (long unbroken values split) under the value column. Also
//! home of `fit`/`more`, the cut-short mark every stacked band uses.
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;
use seer_core::output::sanitize_line;

use crate::tui::theme::Theme;
use crate::tui::widgets::wrap_hard;

/// The fewest rows a band cut short keeps: a table this many rows under its
/// header, a detail band this many lines.
pub const MIN_ROWS: usize = 3;
/// Widest label gutter, so a long label cannot squeeze the values.
const MAX_LABEL: usize = 14;
/// Value columns the label gutter always leaves, shrinking itself to do so.
const MIN_VALUE: usize = 8;

/// One `label  value` line of the detail. `tone` is a `Theme::tone` name
/// for the value's color; `None` is body text.
#[derive(Debug, Clone)]
pub struct Field {
    pub label: &'static str,
    pub value: String,
    pub tone: Option<&'static str>,
}

impl Field {
    pub fn new(label: &'static str, value: impl Into<String>) -> Self {
        Self {
            label,
            value: value.into(),
            tone: None,
        }
    }

    pub fn tone(self, tone: &'static str) -> Self {
        Self {
            tone: Some(tone),
            ..self
        }
    }
}

/// `fields` as lines `width` columns wide.
pub fn lines(theme: &Theme, fields: &[Field], width: u16) -> Vec<Line<'static>> {
    let label_w = fields
        .iter()
        .map(|f| Span::raw(f.label).width())
        .max()
        .unwrap_or(0)
        .min(MAX_LABEL);
    // The gutter gives way before the values do: it shrinks (labels cut to
    // fit) to leave MIN_VALUE columns, and goes entirely when that leaves no
    // room for a label, so no line is wider than `width`.
    let width = usize::from(width);
    let mut gutter = (label_w + 2).min(width.saturating_sub(MIN_VALUE));
    if gutter < 3 {
        gutter = 0;
    }
    let value_w = u16::try_from(width.saturating_sub(gutter).max(1)).unwrap_or(u16::MAX);
    let mut out = Vec::new();
    for field in fields {
        let color = field.tone.map_or(theme.text, |t| theme.tone(t));
        let mut chunks = wrap_hard(&sanitize_line(&field.value), value_w);
        if chunks.is_empty() {
            chunks.push("—".to_string());
        }
        for (i, chunk) in chunks.into_iter().enumerate() {
            let label: String = if i == 0 && gutter > 0 {
                field.label.chars().take(gutter - 2).collect()
            } else {
                String::new()
            };
            out.push(Line::from(vec![
                Span::styled(
                    format!("{label:<gutter$}"),
                    Style::default().fg(theme.overlay),
                ),
                Span::styled(chunk, Style::default().fg(color)),
            ]));
        }
    }
    out
}

/// Draw `lines` into `area`, cut short with a [`more`] mark when they do
/// not fit.
pub fn draw(f: &mut Frame, area: Rect, theme: &Theme, mut lines: Vec<Line<'static>>) {
    let (shown, hidden) = fit(lines.len(), area.height);
    lines.truncate(shown);
    if hidden > 0 {
        lines.push(more(theme, hidden, "lines"));
    }
    f.render_widget(Paragraph::new(lines), area);
}

/// How many of `total` rows fit in `rows`, and how many are left out: when
/// not all fit, the last row goes to the [`more`] mark, so a mark always
/// stands for two rows or more (a single one would fit in its place).
pub fn fit(total: usize, rows: u16) -> (usize, usize) {
    let rows = usize::from(rows);
    if total <= rows {
        (total, 0)
    } else {
        let shown = rows.saturating_sub(1);
        (shown, total - shown)
    }
}

/// The mark closing a band that was cut short: `… N more <rows>`.
pub fn more(theme: &Theme, hidden: usize, rows: &str) -> Line<'static> {
    Line::from(Span::styled(
        format!("… {hidden} more {rows}"),
        Style::default().fg(theme.overlay0),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::test_util::render_lines;

    fn text(lines: &[Line]) -> Vec<String> {
        lines
            .iter()
            .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect())
            .collect()
    }

    #[test]
    fn labels_share_a_gutter_and_values_wrap_under_the_value_column() {
        let theme = Theme::frappe();
        let fields = [
            Field::new("host", "example.com"),
            Field::new("remediation", "Publish a DMARC record at _dmarc"),
        ];
        let got = text(&lines(&theme, &fields, 30));
        assert_eq!(
            got,
            [
                "host         example.com",
                "remediation  Publish a DMARC",
                "             record at _dmarc",
            ]
        );
    }

    #[test]
    fn values_are_sanitized_and_empty_values_show_a_dash() {
        let theme = Theme::frappe();
        let fields = [Field::new("v", "a\x1b[31mred\nb"), Field::new("e", "")];
        let got = text(&lines(&theme, &fields, 40)).join("|");
        assert!(!got.contains('\x1b') && !got.contains('\n'), "{got:?}");
        assert!(got.contains("e  —"), "{got:?}");
    }

    /// On a narrow pane the label gutter gives way, so no line is wider
    /// than the band (a wider one would be clipped at its edge).
    #[test]
    fn lines_never_exceed_a_narrow_width() {
        let theme = Theme::frappe();
        let fields = [Field::new("remediation", "x".repeat(60))];
        for width in [6u16, 12, 20] {
            for line in lines(&theme, &fields, width) {
                assert!(line.width() <= usize::from(width), "{width}: {line:?}");
            }
        }
    }

    #[test]
    fn draw_truncates_with_a_more_mark() {
        let theme = Theme::frappe();
        let fields: Vec<Field> = (0..6).map(|i| Field::new("row", format!("v{i}"))).collect();
        let l = lines(&theme, &fields, 30);
        let s = render_lines(30, 3, |f| draw(f, f.area(), &theme, l));
        assert!(s.contains("v1") && !s.contains("v2"), "{s}");
        assert!(s.contains("… 4 more lines"), "{s}");
    }

    #[test]
    fn fit_reserves_the_last_row_for_the_mark() {
        assert_eq!(fit(3, 5), (3, 0));
        assert_eq!(fit(6, 3), (2, 4));
        assert_eq!(fit(4, 0), (0, 4));
    }
}
