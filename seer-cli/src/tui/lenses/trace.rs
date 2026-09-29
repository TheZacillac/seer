//! DNS Trace tab renderer — the iterative walk from the root servers down to
//! the authoritative answer (`seer dig +trace`): one selectable row per
//! delegation hop, the selected hop's referral and failed servers, then the
//! final answer and why the walk ended. The wording is
//! `seer_core::output::dig`'s and every remote string goes through
//! `sanitize_line`, as in the Records tab.
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table};
use ratatui::Frame;
use seer_core::output::dig as wording;
use seer_core::output::sanitize_line;
use seer_core::{DnsTrace, TraceHop};

use crate::tui::action::LensData;
use crate::tui::lenses::dns::{record_table, status_color, status_spans, verdict_color};
use crate::tui::theme::Theme;
use crate::tui::widgets::{panel, row_style, scroll_to, stack, wrap, Band};

pub fn render(
    f: &mut Frame,
    area: Rect,
    theme: &Theme,
    data: &LensData,
    focused: bool,
    sel: usize,
) {
    let LensData::Trace(trace) = data else { return };
    let title = format!(
        "trace · {} {}",
        sanitize_line(&trace.name),
        trace.record_type
    );
    let inner = panel::render(f, area, theme, &title, theme.sky, focused);

    // The hop the selection is on (the first one until the pane is entered).
    let selected = sel.min(trace.hops.len().saturating_sub(1));
    let mut detail = trace
        .hops
        .get(selected)
        .map(|hop| hop_detail(theme, selected + 1, hop, inner.width))
        .unwrap_or_default();
    let outcome = outcome_lines(theme, trace, inner.width);

    // Status line, hops, the selected hop's detail, the final answer, the
    // outcome — stacked from the top, each band only when it has content.
    // When they do not all fit, the hop table gives up rows first but keeps
    // its header and a few hops (it scrolls to the selection), then the
    // detail and the answers are cut short, each saying how much it left
    // out, so the status line and the outcome stay whole.
    let rows = |n: usize| u16::try_from(n).unwrap_or(u16::MAX);
    let hops = trace.hops.len();
    let mut layout = vec![
        Band::fixed(1),
        Band::shrinking(rows(hops + 1), rows(1 + hops.min(MIN_ROWS))),
    ];
    if !detail.is_empty() {
        layout.push(Band::shrinking(
            rows(detail.len()),
            rows(detail.len().min(MIN_ROWS)),
        ));
    }
    if !trace.answers.is_empty() {
        let answers = trace.answers.len() + 1;
        layout.push(Band::shrinking(rows(answers), rows(answers.min(MIN_ROWS))));
    }
    if !outcome.is_empty() {
        layout.push(Band::fixed(rows(outcome.len())));
    }
    let mut bands = stack(inner, &layout).into_iter();
    let mut next_band = || bands.next().unwrap_or_default();

    let mut status = Vec::from(status_spans(theme, trace.status));
    status.push(Span::styled(
        format!(
            "  {hops} {} from the root",
            if hops == 1 { "hop" } else { "hops" }
        ),
        Style::default().fg(theme.overlay0),
    ));
    f.render_widget(Paragraph::new(Line::from(status)), next_band());

    let mut state = scroll_to(focused.then_some(sel));
    f.render_stateful_widget(
        hop_table(theme, trace, focused.then_some(sel)),
        next_band(),
        &mut state,
    );
    if !detail.is_empty() {
        let band = next_band();
        let (shown, hidden) = fit(detail.len(), band.height);
        detail.truncate(shown);
        if hidden > 0 {
            detail.push(more(theme, hidden, "lines"));
        }
        f.render_widget(Paragraph::new(detail), band);
    }
    if !trace.answers.is_empty() {
        let band = next_band();
        // The column header, then the answers that fit.
        let body = band.height.saturating_sub(1);
        let (shown, hidden) = fit(trace.answers.len(), body);
        let answers = trace.answers.iter().take(shown).map(|r| (r, true));
        f.render_widget(record_table(theme, "ANSWER", answers, None), band);
        if hidden > 0 && body > 0 {
            let last = Rect {
                y: band.bottom() - 1,
                height: 1,
                ..band
            };
            f.render_widget(Paragraph::new(more(theme, hidden, "answers")), last);
        }
    }
    if !outcome.is_empty() {
        f.render_widget(Paragraph::new(outcome), next_band());
    }
}

/// The fewest rows a band cut short keeps: the hop table this many hops
/// under its header, the detail and the answer table (header included) this
/// many rows.
const MIN_ROWS: usize = 3;

/// How many of `total` rows fit in `rows`, and how many are left out: when
/// not all fit, the last row goes to the [`more`] mark, so a mark always
/// stands for two rows or more (a single one would fit in its place).
fn fit(total: usize, rows: u16) -> (usize, usize) {
    let rows = usize::from(rows);
    if total <= rows {
        (total, 0)
    } else {
        let shown = rows.saturating_sub(1);
        (shown, total - shown)
    }
}

/// The mark closing a band that was cut short: `… N more <rows>`.
fn more(theme: &Theme, hidden: usize, rows: &str) -> Line<'static> {
    Line::from(Span::styled(
        format!("… {hidden} more {rows}"),
        Style::default().fg(theme.overlay0),
    ))
}

/// One row per hop: the zone asked, the server and address that answered,
/// how long it took, its status (`aa` when authoritative) and where it led.
fn hop_table(theme: &Theme, trace: &DnsTrace, selected: Option<usize>) -> Table<'static> {
    let header = Row::new(["#", "ZONE", "SERVER", "ADDRESS", "TIME", "STATUS", "NEXT"])
        .style(Style::default().fg(theme.overlay0));
    let rows: Vec<Row> = trace
        .hops
        .iter()
        .enumerate()
        .map(|(i, hop)| {
            let mut status = vec![Span::styled(
                hop.status.to_string(),
                Style::default().fg(status_color(theme, hop.status)),
            )];
            if hop.authoritative {
                status.push(Span::styled(" aa", Style::default().fg(theme.overlay)));
            }
            Row::new([
                Cell::from((i + 1).to_string()).style(Style::default().fg(theme.overlay0)),
                Cell::from(format!(
                    "{}{}",
                    sanitize_line(&hop.zone),
                    wording::zone_suffix(&hop.zone)
                )),
                Cell::from(sanitize_line(&hop.server)),
                Cell::from(sanitize_line(&hop.address)).style(Style::default().fg(theme.subtext)),
                Cell::from(format!("{} ms", hop.query_time_ms))
                    .style(Style::default().fg(theme.overlay)),
                Cell::from(Line::from(status)),
                Cell::from(next_step(hop)).style(Style::default().fg(theme.subtext)),
            ])
            .style(row_style(theme, selected == Some(i)))
        })
        .collect();
    Table::new(
        rows,
        [
            Constraint::Length(2),
            Constraint::Percentage(18),
            Constraint::Percentage(24),
            Constraint::Percentage(16),
            Constraint::Length(7),
            Constraint::Length(11),
            Constraint::Min(0),
        ],
    )
    .header(header)
    .column_spacing(1)
}

/// Where a hop led: the zone it delegated to, or its answer.
fn next_step(hop: &TraceHop) -> String {
    match &hop.referral_zone {
        Some(zone) => format!("→ {} ({} NS)", sanitize_line(zone), hop.referral.len()),
        None if hop.answers.len() == 1 => "1 answer".to_string(),
        None if !hop.answers.is_empty() => format!("{} answers", hop.answers.len()),
        None => "—".to_string(),
    }
}

/// The selected hop's detail, wrapped to `width`: the nameservers it
/// referred to and the servers at its level that failed before one answered.
/// Empty when it has neither.
fn hop_detail(theme: &Theme, number: usize, hop: &TraceHop, width: u16) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if let Some(zone) = &hop.referral_zone {
        let servers: Vec<String> = hop.referral.iter().map(|ns| sanitize_line(ns)).collect();
        let text = format!(
            "Hop {number} referral to {}: {}",
            sanitize_line(zone),
            servers.join(" ")
        );
        lines.extend(styled(wrap(&text, width), theme.subtext));
    }
    for failure in &hop.failed_servers {
        let text = format!("✗ {}", sanitize_line(failure));
        lines.extend(styled(wrap(&text, width), theme.red));
    }
    lines
}

/// Why the walk ended, wrapped to `width`: the verdict for an answer without
/// records of the type and the CNAME a trace does not follow — or, for a
/// walk that stopped short, its error.
fn outcome_lines(theme: &Theme, trace: &DnsTrace, width: u16) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if let Some(error) = &trace.error {
        let text = format!("Error: {}", sanitize_line(error));
        lines.extend(styled(wrap(&text, width), theme.red));
        return lines;
    }
    if let Some(verdict) = wording::trace_verdict(trace, sanitize_line) {
        lines.extend(styled(
            wrap(&verdict, width),
            verdict_color(theme, trace.status),
        ));
    }
    if let Some(target) = wording::unfollowed_cname(trace) {
        let note = wording::cname_note(sanitize_line(target));
        lines.extend(styled(wrap(&note, width), theme.overlay));
    }
    lines
}

fn styled(lines: Vec<String>, color: Color) -> impl Iterator<Item = Line<'static>> {
    lines
        .into_iter()
        .map(move |line| Line::from(Span::styled(line, Style::default().fg(color))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::fixtures;
    use crate::tui::test_util::render_lines;
    use seer_core::DnsStatus;

    fn draw(trace: DnsTrace, sel: Option<usize>) -> String {
        let theme = Theme::frappe();
        let data = LensData::Trace(Box::new(trace));
        render_lines(110, 22, |f| {
            render(f, f.area(), &theme, &data, sel.is_some(), sel.unwrap_or(0));
        })
    }

    fn row_with<'t>(text: &'t str, needle: &str) -> &'t str {
        text.lines()
            .find(|l| l.contains(needle))
            .unwrap_or_else(|| panic!("no row with {needle:?} in\n{text}"))
    }

    /// A root hop referring to 13 nameservers, and a final answer of
    /// `answers` addresses — more than a small terminal holds.
    fn long_trace(answers: u8, error: Option<&str>) -> DnsTrace {
        let records = (1..=answers)
            .map(|i| fixtures::a("www.seer.test", &format!("192.0.2.{i}")))
            .collect();
        let mut trace = fixtures::trace(records, error);
        trace.hops[0].referral = (b'a'..=b'm')
            .map(|c| format!("{}.gtld-servers.net.", char::from(c)))
            .collect();
        trace
    }

    fn draw_at(width: u16, height: u16, trace: &DnsTrace, sel: Option<usize>) -> String {
        let theme = Theme::frappe();
        let data = LensData::Trace(Box::new(trace.clone()));
        render_lines(width, height, |f| {
            render(f, f.area(), &theme, &data, sel.is_some(), sel.unwrap_or(0));
        })
    }

    #[test]
    fn a_long_referral_and_answer_leave_the_hop_table_in_view() {
        let trace = long_trace(12, None);
        for (width, height, sel) in [
            (80, 20, None),
            (80, 20, Some(0)),
            (80, 20, Some(1)),
            (110, 22, Some(0)),
            // The lens area of an 80x24 terminal.
            (54, 21, Some(0)),
        ] {
            let text = draw_at(width, height, &trace, sel);
            let at = format!("{width}x{height} sel {sel:?}\n{text}");
            assert!(text.contains("ZONE"), "{at}");
            // Both hops fit, the selected one among them.
            assert!(text.contains(". (root)"), "{at}");
            assert!(text.contains("NOERROR aa"), "{at}");
            // The answers are cut short, and say by how much.
            let mark = row_with(&text, "more answers");
            let hidden: usize = mark
                .split_whitespace()
                .find_map(|word| word.parse().ok())
                .unwrap_or_else(|| panic!("no count in {mark:?}"));
            let shown = (1..=12)
                .filter(|i| text.contains(&format!("192.0.2.{i} ")))
                .count();
            assert_eq!(shown + hidden, 12, "{at}");
            assert!(shown >= 1, "{at}");
            assert!(text.contains(&format!("192.0.2.{shown} ")), "{at}");
        }
        // Where the answers fit, nothing is cut.
        let text = draw_at(110, 40, &trace, Some(0));
        assert!(text.contains("192.0.2.12"), "{text}");
        assert!(!text.contains(" more "), "{text}");
        assert!(text.contains("m.gtld-servers.net."), "{text}");
    }

    #[test]
    fn a_long_referral_is_cut_short_before_the_outcome() {
        let trace = long_trace(0, Some("every server failed"));
        let text = draw_at(54, 14, &trace, Some(0));
        row_with(&text, "ZONE");
        row_with(&text, "Hop 1 referral to seer.test.:");
        row_with(&text, "more lines");
        assert!(!text.contains("m.gtld-servers.net."), "{text}");
        row_with(&text, "Error: every server failed");
    }

    #[test]
    fn renders_one_row_per_hop_then_the_answer() {
        let trace = fixtures::trace(vec![fixtures::a("www.seer.test", "192.0.2.7")], None);
        let text = draw(trace, None);
        assert!(text.contains("● NOERROR  2 hops from the root"), "{text}");
        let root = row_with(&text, "a.root-servers.net.");
        assert!(root.contains(". (root)"), "{root}");
        assert!(
            root.contains("192.0.2.53") && root.contains("20 ms"),
            "{root}"
        );
        assert!(root.contains("→ seer.test. (1 NS)"), "{root}");
        assert!(!root.contains(" aa"), "{root}");
        let auth = row_with(&text, "NOERROR aa");
        assert!(auth.contains("ns1.seer.test."), "{auth}");
        assert!(auth.contains("1 answer"), "{auth}");
        // The root hop's referral, listed in full under the table.
        assert!(
            text.contains("Hop 1 referral to seer.test.: ns1.seer.test."),
            "{text}"
        );
        let answer = row_with(&text, "192.0.2.7");
        assert!(
            answer.contains("www.seer.test") && answer.contains(" A "),
            "{answer}"
        );
        assert!(!text.contains("Error"), "{text}");
    }

    #[test]
    fn the_detail_follows_the_selected_hop() {
        let mut trace = fixtures::trace(vec![fixtures::a("www.seer.test", "192.0.2.7")], None);
        trace.hops[1].failed_servers = vec!["ns0.seer.test. (192.0.2.1): timed out".into()];
        let text = draw(trace, Some(1));
        assert!(!text.contains("Hop 1 referral"), "{text}");
        assert!(
            text.contains("✗ ns0.seer.test. (192.0.2.1): timed out"),
            "{text}"
        );
    }

    #[test]
    fn a_walk_that_stopped_shows_its_error_instead_of_a_verdict() {
        let text = draw(fixtures::trace(vec![], Some("every server failed")), None);
        assert!(text.contains("Error: every server failed"), "{text}");
        assert!(!text.contains("NODATA"), "{text}");
        assert!(!text.contains("ANSWER"), "{text}");
    }

    #[test]
    fn negative_and_cname_outcomes_use_the_shared_wording() {
        let mut nxdomain = fixtures::trace(vec![], None);
        nxdomain.status = DnsStatus::NxDomain;
        let text = draw(nxdomain, None);
        assert!(text.contains("● NXDOMAIN"), "{text}");
        assert!(text.contains("Name does not exist (NXDOMAIN)"), "{text}");

        let cname = fixtures::trace(
            vec![fixtures::cname("www.seer.test", "edge.cdn.test.")],
            None,
        );
        let text = draw(cname, None);
        let flat = text
            .replace('│', " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            flat.contains(
                "The answer is a CNAME to edge.cdn.test., which a trace does not follow: trace \
                 that name next"
            ),
            "{text}"
        );
    }

    #[test]
    fn nxdomain_beside_a_cname_names_the_missing_target() {
        // A dangling in-zone CNAME: the server followed it and answered
        // NXDOMAIN beside it, so www exists and there is nothing to trace.
        let mut dangling = fixtures::trace(
            vec![fixtures::cname("www.seer.test", "gone.seer.test.")],
            None,
        );
        dangling.status = DnsStatus::NxDomain;
        let text = draw(dangling, None);
        assert!(
            text.contains("The CNAME target gone.seer.test. does not exist (NXDOMAIN)"),
            "{text}"
        );
        assert!(!text.contains("Name does not exist"), "{text}");
        assert!(!text.contains("trace does not follow"), "{text}");
    }
}
