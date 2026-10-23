//! The one layout every lens is drawn through. A lens describes a [`Page`]:
//! a titled, bordered panel holding [`Block`]s top to bottom. [`draw`]
//! measures the blocks at the pane's width and, when they do not all fit,
//! takes rows in a fixed order — blank gaps, then table rows (down to the
//! header and three rows), then a table's detail (down to three lines),
//! then scrolling text, then key/value rows (each down to one line) — so
//! verdicts and notes are never the part cut. What still does not fit is
//! clipped at the bottom; rows left over go to the page's last panel, so a
//! bottom panel reaches the frame edge. A band cut short ends with
//! `… N more <unit>`.
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Row, Table};
use ratatui::Frame;
use seer_core::output::sanitize_line;

use crate::tui::theme::Theme;
use crate::tui::widgets::inspector::{self, Field};
use crate::tui::widgets::{kv, panel, row_style, scroll_to, wrap};

/// A lens's content: a titled panel of blocks, top to bottom.
pub struct Page {
    pub title: String,
    pub accent: Color,
    pub blocks: Vec<Block>,
}

impl Page {
    pub fn new(title: impl Into<String>, accent: Color) -> Self {
        Self {
            title: title.into(),
            accent,
            blocks: Vec::new(),
        }
    }

    pub fn push(mut self, block: Block) -> Self {
        self.blocks.push(block);
        self
    }

    /// [`Page::push`] when `cond` holds.
    pub fn push_if(self, cond: bool, block: impl FnOnce() -> Block) -> Self {
        if cond {
            self.push(block())
        } else {
            self
        }
    }
}

/// One piece of a [`Page`]; see the module doc for which give rows up.
pub enum Block {
    /// One blank row.
    Gap,
    /// Rows kept whole: a gauge, a verdict, a row of chips.
    Lines(Vec<Line<'static>>),
    /// Remote text, sanitized and wrapped to the width, kept whole.
    Note { text: String, color: Color },
    /// Rows that give space up, after skipping `offset` of them.
    Scroll {
        lines: Vec<Line<'static>>,
        offset: u16,
        unit: &'static str,
    },
    /// Key/value rows (`kv`), wrapping long values.
    Kv {
        key_color: Color,
        rows: Vec<(&'static str, String)>,
    },
    /// A selectable table, and the selected row's detail.
    Table(TableBlock),
    /// A nested bordered page.
    Panel(Page),
}

/// The selected row's detail beneath a table.
pub enum Detail {
    None,
    /// `label  value` fields (the inspector).
    Fields(Vec<Field>),
    /// Free text, each wrapped to the width in its color.
    Notes(Vec<(String, Color)>),
}

/// A table [`Block`]: no header row when `header` is empty. The renderer
/// paints the selection band on the selected row. A table with a selection
/// scrolls to it; one without, cut short, ends with `… N more <unit>`.
pub struct TableBlock {
    header: Vec<&'static str>,
    widths: Vec<Constraint>,
    rows: Vec<Row<'static>>,
    selected: Option<usize>,
    detail: Detail,
    unit: &'static str,
}

impl TableBlock {
    pub fn new(
        header: Vec<&'static str>,
        widths: Vec<Constraint>,
        rows: Vec<Row<'static>>,
    ) -> Self {
        Self {
            header,
            widths,
            rows,
            selected: None,
            detail: Detail::None,
            unit: "rows",
        }
    }

    /// What the cut-short mark counts (`rows` by default).
    pub fn unit(self, unit: &'static str) -> Self {
        Self { unit, ..self }
    }

    pub fn selected(self, selected: Option<usize>) -> Self {
        Self { selected, ..self }
    }

    pub fn detail(self, detail: Detail) -> Self {
        Self { detail, ..self }
    }
}

// Shrink priorities: lower gives rows up first.
const GAP: u8 = 0;
const TABLE: u8 = 1;
const DETAIL: u8 = 2;
const SCROLL: u8 = 3;
const KV: u8 = 4;

/// A block measured at a width: what it draws and how it may shrink.
enum Part {
    Gap,
    Fixed(Vec<Line<'static>>),
    Shrink {
        lines: Vec<Line<'static>>,
        unit: &'static str,
        priority: u8,
        min: usize,
    },
    Rows {
        header: Vec<&'static str>,
        widths: Vec<Constraint>,
        rows: Vec<Row<'static>>,
        selected: Option<usize>,
        unit: &'static str,
    },
    Panel {
        title: String,
        accent: Color,
        parts: Vec<Part>,
    },
}

impl Part {
    fn want(&self) -> usize {
        match self {
            Part::Gap => 1,
            Part::Fixed(lines) | Part::Shrink { lines, .. } => lines.len(),
            Part::Rows { header, rows, .. } => usize::from(!header.is_empty()) + rows.len(),
            Part::Panel { parts, .. } => 2 + parts.iter().map(Part::want).sum::<usize>(),
        }
    }

    fn min(&self) -> usize {
        match self {
            Part::Gap => 0,
            Part::Fixed(lines) => lines.len(),
            Part::Shrink { lines, min, .. } => lines.len().min(*min),
            Part::Rows { header, rows, .. } => {
                usize::from(!header.is_empty()) + rows.len().min(inspector::MIN_ROWS)
            }
            Part::Panel { parts, .. } => 2 + parts.iter().map(Part::min).sum::<usize>(),
        }
    }

    /// The rows this part can give up in the `priority` pass. A panel gives
    /// what its own parts of that priority can, so nesting never changes the
    /// order rows are taken in.
    fn give(&self, priority: u8) -> usize {
        let own = |p: u8| {
            if p == priority {
                self.want() - self.min()
            } else {
                0
            }
        };
        match self {
            Part::Gap => own(GAP),
            Part::Fixed(_) => 0,
            Part::Shrink { priority: p, .. } => own(*p),
            Part::Rows { .. } => own(TABLE),
            Part::Panel { parts, .. } => parts.iter().map(|p| p.give(priority)).sum(),
        }
    }
}

/// `blocks` measured at `width`.
fn prepare(theme: &Theme, blocks: Vec<Block>, width: u16) -> Vec<Part> {
    let mut parts = Vec::new();
    for block in blocks {
        match block {
            Block::Gap => parts.push(Part::Gap),
            Block::Lines(lines) => parts.push(Part::Fixed(lines)),
            Block::Note { text, color } => parts.push(Part::Fixed(note(&text, color, width))),
            Block::Scroll {
                lines,
                offset,
                unit,
            } => parts.push(Part::Shrink {
                lines: lines.into_iter().skip(usize::from(offset)).collect(),
                unit,
                priority: SCROLL,
                min: 1,
            }),
            Block::Kv { key_color, rows } => parts.push(Part::Shrink {
                lines: kv::lines(theme, key_color, &rows, width),
                unit: "lines",
                priority: KV,
                min: 1,
            }),
            Block::Table(t) => {
                parts.push(Part::Rows {
                    header: t.header,
                    widths: t.widths,
                    rows: t.rows,
                    selected: t.selected,
                    unit: t.unit,
                });
                let detail = match t.detail {
                    Detail::None => Vec::new(),
                    Detail::Fields(fields) => inspector::lines(theme, &fields, width),
                    Detail::Notes(notes) => notes
                        .into_iter()
                        .flat_map(|(text, color)| note(&text, color, width))
                        .collect(),
                };
                if !detail.is_empty() {
                    parts.push(Part::Gap);
                    parts.push(Part::Shrink {
                        lines: detail,
                        unit: "lines",
                        priority: DETAIL,
                        min: inspector::MIN_ROWS,
                    });
                }
            }
            Block::Panel(page) => parts.push(Part::Panel {
                title: page.title,
                accent: page.accent,
                parts: prepare(theme, page.blocks, width.saturating_sub(2)),
            }),
        }
    }
    parts
}

/// `text` sanitized and wrapped to `width`, in `color`.
fn note(text: &str, color: Color, width: u16) -> Vec<Line<'static>> {
    wrap(&sanitize_line(text), width)
        .into_iter()
        .map(|l| Line::from(Span::styled(l, Style::default().fg(color))))
        .collect()
}

/// Heights for `parts` in `avail` rows: all they want, then rows taken in
/// priority order (first part first within one) down to each minimum; a
/// panel's own parts are taken from in the same passes when it is drawn.
/// Rows left over go to the last part when it is a panel.
fn allocate(parts: &[Part], avail: usize) -> Vec<usize> {
    let mut heights: Vec<usize> = parts.iter().map(Part::want).collect();
    let mut over = heights.iter().sum::<usize>().saturating_sub(avail);
    for priority in [GAP, TABLE, DETAIL, SCROLL, KV] {
        for (i, part) in parts.iter().enumerate() {
            if over == 0 {
                break;
            }
            let give = part.give(priority).min(over);
            heights[i] -= give;
            over -= give;
        }
    }
    let used: usize = heights.iter().sum();
    if let (Some(Part::Panel { .. }), Some(last)) = (parts.last(), heights.last_mut()) {
        *last += avail.saturating_sub(used);
    }
    heights
}

/// Draw `page` over `area`; `focused` brightens its border.
pub fn draw(f: &mut Frame, area: Rect, theme: &Theme, page: Page, focused: bool) {
    let inner = panel::render(f, area, theme, &page.title, page.accent, focused);
    let parts = prepare(theme, page.blocks, inner.width);
    draw_parts(f, inner, theme, parts);
}

fn draw_parts(f: &mut Frame, area: Rect, theme: &Theme, parts: Vec<Part>) {
    let heights = allocate(&parts, usize::from(area.height));
    let mut y = area.y;
    for (part, height) in parts.into_iter().zip(heights) {
        let top = y.min(area.bottom());
        let height = u16::try_from(height)
            .unwrap_or(u16::MAX)
            .min(area.bottom() - top);
        y = top + height;
        let rect = Rect {
            y: top,
            height,
            ..area
        };
        if height == 0 {
            continue;
        }
        match part {
            Part::Gap => {}
            Part::Fixed(lines) => f.render_widget(Paragraph::new(lines), rect),
            Part::Shrink { lines, unit, .. } => {
                let mut lines = lines;
                let (shown, hidden) = inspector::fit(lines.len(), height);
                lines.truncate(shown);
                if hidden > 0 {
                    lines.push(inspector::more(theme, hidden, unit));
                }
                f.render_widget(Paragraph::new(lines), rect);
            }
            Part::Rows {
                header,
                widths,
                rows,
                selected,
                unit,
            } => {
                let header_rows = usize::from(!header.is_empty());
                let total = rows.len();
                let mut rows: Vec<Row> = rows
                    .into_iter()
                    .enumerate()
                    .map(|(i, row)| {
                        if selected == Some(i) {
                            row.style(row_style(theme, true))
                        } else {
                            row
                        }
                    })
                    .collect();
                // Unselected, the table cannot scroll: say what was cut.
                let mut mark = None;
                if selected.is_none() {
                    let body = usize::from(height).saturating_sub(header_rows);
                    let (shown, hidden) =
                        inspector::fit(total, u16::try_from(body).unwrap_or(u16::MAX));
                    if hidden > 0 {
                        rows.truncate(shown);
                        mark = Some(inspector::more(theme, hidden, unit));
                    }
                }
                let mut table = Table::new(rows, widths).column_spacing(1);
                if !header.is_empty() {
                    table =
                        table.header(Row::new(header).style(Style::default().fg(theme.overlay0)));
                }
                let mut state = scroll_to(selected);
                f.render_stateful_widget(table, rect, &mut state);
                if let Some(mark) = mark {
                    let last = Rect {
                        y: rect.bottom() - 1,
                        height: 1,
                        ..rect
                    };
                    f.render_widget(Paragraph::new(mark), last);
                }
            }
            Part::Panel {
                title,
                accent,
                parts,
            } => {
                let inner = panel::render(f, rect, theme, &title, accent, false);
                draw_parts(f, inner, theme, parts);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::test_util::render_lines;

    fn lines(n: usize, tag: &str) -> Block {
        Block::Lines((0..n).map(|i| Line::from(format!("{tag}{i}"))).collect())
    }

    fn table(n: usize, sel: Option<usize>, detail: usize) -> Block {
        let rows = (0..n).map(|i| Row::new([format!("row{i}")])).collect();
        let fields = (0..detail)
            .map(|i| Field::new("d", format!("det{i}")))
            .collect();
        Block::Table(
            TableBlock::new(vec!["NAME"], vec![Constraint::Min(0)], rows)
                .selected(sel)
                .detail(Detail::Fields(fields)),
        )
    }

    fn draw_page(w: u16, h: u16, page: Page) -> String {
        let theme = Theme::frappe();
        render_lines(w, h, |f| draw(f, f.area(), &theme, page, true))
    }

    fn page() -> Page {
        Page::new("T", Color::Reset)
    }

    #[test]
    fn fits_draw_every_block_in_order() {
        let s = draw_page(40, 20, page().push(lines(2, "a")).push(table(2, None, 0)));
        let a = s.find("a1").unwrap();
        let r = s.find("row1").unwrap();
        assert!(a < r && s.contains("NAME"), "{s}");
    }

    #[test]
    fn table_shrinks_before_lines_and_keeps_header_plus_three() {
        let s = draw_page(
            40,
            10,
            page().push(lines(4, "keep")).push(table(20, Some(0), 0)),
        );
        assert!(s.contains("keep3"), "kept-whole lines survive: {s}");
        assert!(s.contains("NAME") && s.contains("row2"), "{s}");
    }

    #[test]
    fn detail_shrinks_after_the_table_reaches_its_minimum() {
        let s = draw_page(40, 12, page().push(table(10, Some(0), 20)));
        assert!(
            s.contains("NAME") && s.contains("row2"),
            "header + 3 rows: {s}"
        );
        assert!(s.contains("det0") && s.contains("more lines"), "{s}");
    }

    #[test]
    fn a_gap_gives_its_row_up_first() {
        let s = draw_page(
            40,
            6,
            page()
                .push(lines(2, "a"))
                .push(Block::Gap)
                .push(lines(2, "b")),
        );
        assert!(s.contains("b1"), "{s}");
    }

    #[test]
    fn the_last_panel_fills_to_the_bottom() {
        let inner = page().push(lines(1, "x"));
        let s = draw_page(30, 12, page().push(lines(1, "a")).push(Block::Panel(inner)));
        let rows: Vec<&str> = s.lines().collect();
        assert!(
            rows[10].contains('╰'),
            "inner border on the last inner row: {s}"
        );
    }

    #[test]
    fn notes_are_sanitized_and_wrapped() {
        let note = Block::Note {
            text: "alpha beta\x1b[2J gamma delta".into(),
            color: Color::Reset,
        };
        let s = draw_page(16, 8, page().push(note));
        assert!(!s.contains('\x1b') && s.contains("gamma"), "{s}");
    }

    #[test]
    fn scroll_skips_its_offset_and_marks_the_rest() {
        let b = Block::Scroll {
            lines: (0..20).map(|i| Line::from(format!("s{i}"))).collect(),
            offset: 5,
            unit: "lines",
        };
        let s = draw_page(30, 8, page().push(b));
        assert!(s.contains("s5") && !s.contains("s4 "), "{s}");
        assert!(s.contains("more lines"), "{s}");
    }

    /// A table without a selection cannot be scrolled, so cutting it short
    /// says how many rows it left out, in the table's own unit.
    #[test]
    fn an_unselected_table_cut_short_counts_what_it_left_out() {
        let rows = (0..12).map(|i| Row::new([format!("r{i}")])).collect();
        let t = TableBlock::new(vec!["H"], vec![Constraint::Min(0)], rows).unit("answers");
        let s = draw_page(30, 8, page().push(lines(1, "a")).push(Block::Table(t)));
        // Header, three rows and the mark, which takes a row of its own.
        assert!(s.contains("r2") && s.contains("… 9 more answers"), "{s}");
    }

    /// Only the selected row is restyled: other rows keep their own colors.
    #[test]
    fn unselected_rows_keep_their_row_style() {
        let rows = vec![
            Row::new(["a"]).style(Style::default().fg(Color::Red)),
            Row::new(["b"]),
        ];
        let t = TableBlock::new(vec![], vec![Constraint::Min(0)], rows).selected(Some(1));
        let theme = Theme::frappe();
        let buf = crate::tui::test_util::render_buffer(10, 6, |f| {
            draw(f, f.area(), &theme, page().push(Block::Table(t)), false);
        });
        assert_eq!(buf[(1, 1)].fg, Color::Red);
        assert_eq!(buf[(1, 2)].bg, theme.surface0);
    }

    /// A panel gives rows up in the same order as everything else: its
    /// key/value rows go after a sibling table's, not with its own gap.
    #[test]
    fn a_panel_shrinks_child_by_child_in_priority_order() {
        let rows = (0..10).map(|i| ("k", format!("v{i}"))).collect();
        let inner = page().push(Block::Gap).push(Block::Kv {
            key_color: Color::Reset,
            rows,
        });
        let s = draw_page(
            40,
            20,
            page().push(table(30, Some(0), 0)).push(Block::Panel(inner)),
        );
        assert!(s.contains("v9"), "the panel's kv keeps its rows: {s}");
        assert!(
            !s.contains("row9"),
            "the outer table gave up rows first: {s}"
        );
    }

    /// A detail inside a panel outlasts a sibling table's rows.
    #[test]
    fn a_nested_detail_outlasts_a_sibling_table() {
        let inner = page().push(table(10, Some(0), 10));
        let s = draw_page(
            40,
            24,
            page().push(table(30, Some(0), 0)).push(Block::Panel(inner)),
        );
        assert!(s.contains("det9"), "the nested detail is whole: {s}");
    }

    #[test]
    fn the_selected_row_scrolls_into_view() {
        let s = draw_page(30, 8, page().push(table(40, Some(30), 0)));
        assert!(s.contains("row30"), "{s}");
    }

    #[test]
    fn kv_gives_rows_before_a_kept_line_is_cut() {
        let rows = (0..10).map(|i| ("k", format!("v{i}"))).collect();
        let s = draw_page(
            30,
            7,
            page()
                .push(Block::Kv {
                    key_color: Color::Reset,
                    rows,
                })
                .push(lines(1, "tail")),
        );
        assert!(s.contains("tail0") && s.contains("more lines"), "{s}");
    }

    #[test]
    fn a_shrinking_panel_never_draws_outside_the_area() {
        let inner = page().push(table(30, None, 0));
        let theme = Theme::frappe();
        let buf = crate::tui::test_util::render_buffer(30, 10, |f| {
            let area = Rect::new(0, 0, 30, 6);
            draw(f, area, &theme, page().push(Block::Panel(inner)), false);
        });
        for x in 0..30 {
            assert_eq!(buf[(x, 7)].symbol(), " ", "row 7 is outside the area");
        }
    }
}
