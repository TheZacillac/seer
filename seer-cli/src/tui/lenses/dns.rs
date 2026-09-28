//! DNS Records lens — Records tab (tab 0), DNSSEC tab (tab 1), Compare tab
//! (tab 2), Trace tab (tab 3).
//!
//! Records renders a dig-style query result: the response's status line,
//! the ANSWER section (the CNAME chain under its real owners, then the
//! records), and for a response without answers why not — NXDOMAIN, NODATA,
//! a referral or a server failure — with the AUTHORITY records the server
//! sent, and a note when the resolver answered the name itself. The outcome
//! wording is `seer_core::output::dig`'s, shared with `seer dig`, and every
//! remote string goes through `sanitize_line`, as in the CLI formatters.
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table};
use ratatui::Frame;
use seer_core::output::dig::{self as wording, Tone};
use seer_core::output::sanitize_line;
use seer_core::{DnsQueryResult, DnsRecord, DnsStatus};

use crate::tui::action::LensData;
use crate::tui::filter;
use crate::tui::lenses::{compare, dnssec, trace};
use crate::tui::panes::{DnsState, Panes};
use crate::tui::theme::Theme;
use crate::tui::widgets::{panel, row_style, scroll_to, stack, wrap};

#[allow(clippy::too_many_arguments)]
pub fn render(
    f: &mut Frame,
    area: Rect,
    theme: &Theme,
    tab: usize,
    data: &LensData,
    filter: &str,
    focused: bool,
    sel: usize,
    panes: &Panes,
) {
    match tab {
        1 => dnssec::render(f, area, theme, data),
        2 => compare::render(f, area, theme, data),
        3 => trace::render(f, area, theme, data, focused, sel),
        _ => records(f, area, theme, data, filter, focused, sel, &panes.dns),
    }
}

/// The color of a response code: green for NOERROR, yellow for NXDOMAIN,
/// red for a server failure (SERVFAIL, REFUSED, …) — `seer dig`'s scheme.
pub(super) fn status_color(theme: &Theme, status: DnsStatus) -> Color {
    match wording::tone(status) {
        Tone::Answered => theme.green,
        Tone::Negative => theme.yellow,
        Tone::Failed => theme.red,
    }
}

/// The color of a verdict line (`wording::verdict`): yellow for a negative
/// answer, red when the server failed to answer at all.
pub(super) fn verdict_color(theme: &Theme, status: DnsStatus) -> Color {
    match wording::tone(status) {
        Tone::Failed => theme.red,
        Tone::Answered | Tone::Negative => theme.yellow,
    }
}

/// `● STATUS`, bold in the status's color — the head of a status line.
pub(super) fn status_spans(theme: &Theme, status: DnsStatus) -> [Span<'static>; 2] {
    let style = Style::default().fg(status_color(theme, status));
    [
        Span::styled("● ", style),
        Span::styled(status.to_string(), style.add_modifier(Modifier::BOLD)),
    ]
}

/// A table of DNS records in dig's column order — owner, TTL, type, data —
/// under `section` (`ANSWER`, `AUTHORITY`). Each record comes with whether
/// it is an answer proper, whose data is highlighted, rather than a CNAME
/// hop or an authority record. `selected` is the highlighted row, if any.
pub(super) fn record_table<'r>(
    theme: &Theme,
    section: &'static str,
    records: impl IntoIterator<Item = (&'r DnsRecord, bool)>,
    selected: Option<usize>,
) -> Table<'static> {
    let header =
        Row::new([section, "TTL", "TYPE", "DATA"]).style(Style::default().fg(theme.overlay0));
    let rows: Vec<Row> = records
        .into_iter()
        .enumerate()
        .map(|(i, (record, answer))| {
            let data = if answer { theme.green } else { theme.subtext };
            Row::new([
                Cell::from(sanitize_line(&record.name)),
                Cell::from(record.ttl.to_string()).style(Style::default().fg(theme.overlay)),
                Cell::from(record.record_type.as_str()).style(Style::default().fg(theme.lavender)),
                Cell::from(sanitize_line(&record.data.to_string()))
                    .style(Style::default().fg(data)),
            ])
            .style(row_style(theme, selected == Some(i)))
        })
        .collect();
    Table::new(
        rows,
        [
            Constraint::Percentage(30),
            Constraint::Length(7),
            Constraint::Length(8),
            Constraint::Min(0),
        ],
    )
    .header(header)
    .column_spacing(1)
}

/// The Records tab.
#[allow(clippy::too_many_arguments)]
fn records(
    f: &mut Frame,
    area: Rect,
    theme: &Theme,
    data: &LensData,
    filter: &str,
    focused: bool,
    sel: usize,
    dns: &DnsState,
) {
    let LensData::Dig(result) = data else { return };
    let title = format!(
        "dig · {} records · {}",
        result.record_type,
        sanitize_line(&result.name)
    );
    let inner = panel::render(f, area, theme, &title, theme.sky, focused);

    // Layout: nameserver chips + hint + status line + the response
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .split(inner);

    // Nameserver chip row
    let mut ns_spans: Vec<Span> = Vec::new();
    for (i, label) in dns.slot_labels().into_iter().enumerate() {
        if i > 0 {
            ns_spans.push(Span::raw(" "));
        }
        let style = if i == dns.ns_idx {
            Style::default().fg(theme.base).bg(theme.sky)
        } else {
            Style::default().fg(theme.subtext).bg(theme.surface0)
        };
        ns_spans.push(Span::styled(format!(" {label} "), style));
    }
    f.render_widget(Paragraph::new(Line::from(ns_spans)), chunks[0]);

    // Hint line
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("s ", Style::default().fg(theme.overlay0)),
            Span::styled("nameserver  ", Style::default().fg(theme.subtext)),
            Span::styled("/ ", Style::default().fg(theme.overlay0)),
            Span::styled("filter", Style::default().fg(theme.subtext)),
        ])),
        chunks[1],
    );

    f.render_widget(Paragraph::new(status_line(theme, result)), chunks[2]);
    response(f, chunks[3], theme, result, filter, focused.then_some(sel));
}

/// dig's header line: `● NOERROR  flags qr rd ra  server 1.1.1.1  time 12 ms`.
/// A negative or error answer surfaces no header flags (see
/// `DnsQueryResult::flags`), so the field is left out rather than shown
/// empty; `server default` is the default upstream, `server none` a name the
/// resolver answered itself.
fn status_line(theme: &Theme, result: &DnsQueryResult) -> Line<'static> {
    let label = |text: &'static str| Span::styled(text, Style::default().fg(theme.overlay0));
    let value = |text: String| Span::styled(text, Style::default().fg(theme.text));
    let mut spans = Vec::from(status_spans(theme, result.status));
    if !result.flags.is_empty() {
        spans.push(label("  flags "));
        spans.push(value(sanitize_line(&result.flags.join(" "))));
    }
    spans.push(label("  server "));
    spans.push(value(result.server.as_deref().map_or_else(
        || wording::unnamed_server(result).to_string(),
        sanitize_line,
    )));
    spans.push(label("  time "));
    spans.push(value(format!("{} ms", result.query_time_ms)));
    Line::from(spans)
}

/// One band of the response, top to bottom.
enum Section {
    /// The ANSWER table: the visible (filtered) rows, scrolled to `selected`.
    Answers,
    /// Why there is no answer (`wording::query_verdict`), pre-wrapped to
    /// the area's width — a referral's names the zone and can run long.
    Verdict(Vec<String>),
    /// The AUTHORITY records (the SOA of a negative answer, a referral's NS
    /// records).
    Authority,
    /// The local-answer or wildcard note, pre-wrapped to the area's width,
    /// and its color.
    Note(Vec<String>, Color),
}

/// The response below the status line, stacked from the top: the answers,
/// the verdict when there are none, the authority records, and the
/// local-answer or wildcard note. Only the answer table shrinks (and
/// scrolls) when they do not all fit, so the verdict and the notes are never
/// cut.
fn response(
    f: &mut Frame,
    area: Rect,
    theme: &Theme,
    result: &DnsQueryResult,
    filter: &str,
    selected: Option<usize>,
) {
    let mut sections = Vec::new();
    if !result.answers.is_empty() {
        sections.push(Section::Answers);
    }
    if let Some(verdict) = wording::query_verdict(result, sanitize_line) {
        sections.push(Section::Verdict(wrap(&verdict, area.width)));
    }
    if !result.authority.is_empty() {
        sections.push(Section::Authority);
    }
    if result.answered_locally {
        sections.push(Section::Note(
            wrap(wording::LOCAL_NOTE, area.width),
            theme.yellow,
        ));
    }
    if let Some(probe) = &result.wildcard {
        if let Some(note) = wording::wildcard_note(probe, sanitize_line(&probe.probe_name)) {
            // A likely-synthesized answer is the one worth a warning.
            let color = if probe.matches_answer {
                theme.yellow
            } else {
                theme.subtext
            };
            sections.push(Section::Note(
                wrap(&format!("Wildcard: {note}"), area.width),
                color,
            ));
        }
    }

    let rows = filter::dig_rows(result, filter).count();
    let heights: Vec<u16> = sections
        .iter()
        .map(|section| {
            let lines = match section {
                // The column header, then the visible rows.
                Section::Answers => rows + 1,
                Section::Verdict(lines) => lines.len(),
                Section::Authority => result.authority.len() + 1,
                Section::Note(lines, _) => lines.len(),
            };
            u16::try_from(lines).unwrap_or(u16::MAX)
        })
        .collect();
    // The answer table, when there is one, is always the first band.
    let flex = (!result.answers.is_empty()).then_some(0);
    let bands = stack(area, &heights, flex);

    for (section, band) in sections.into_iter().zip(bands) {
        match section {
            Section::Answers => {
                let rows = filter::dig_rows(result, filter);
                let table = record_table(theme, "ANSWER", rows, selected);
                let mut state = scroll_to(selected);
                f.render_stateful_widget(table, band, &mut state);
            }
            Section::Verdict(lines) => f.render_widget(
                colored_lines(lines, verdict_color(theme, result.status)),
                band,
            ),
            Section::Authority => f.render_widget(
                record_table(
                    theme,
                    "AUTHORITY",
                    result.authority.iter().map(|r| (r, false)),
                    None,
                ),
                band,
            ),
            Section::Note(lines, color) => f.render_widget(colored_lines(lines, color), band),
        }
    }
}

/// Pre-wrapped lines in one color.
fn colored_lines(lines: Vec<String>, color: Color) -> Paragraph<'static> {
    let lines: Vec<Line> = lines
        .into_iter()
        .map(|line| Line::from(Span::styled(line, Style::default().fg(color))))
        .collect();
    Paragraph::new(lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::fixtures;
    use crate::tui::test_util::{render_buffer, render_lines, render_text};
    use seer_core::dns::{RecordData, RecordType};
    use seer_core::WildcardProbe;

    fn draw(data: &LensData, panes: &Panes, filter: &str, sel: Option<usize>) -> String {
        let theme = Theme::frappe();
        render_lines(100, 16, |f| {
            render(
                f,
                f.area(),
                &theme,
                0,
                data,
                filter,
                sel.is_some(),
                sel.unwrap_or(0),
                panes,
            );
        })
    }

    fn dig_data(result: DnsQueryResult) -> LensData {
        LensData::Dig(Box::new(result))
    }

    /// `www.seer.test` → `shop.seer.test` → `edge.cdn.test` → two addresses.
    fn chained() -> DnsQueryResult {
        DnsQueryResult {
            server: Some("1.1.1.1".into()),
            ..fixtures::dig(
                RecordType::A,
                vec![
                    fixtures::cname("www.seer.test", "shop.seer.test."),
                    fixtures::cname("shop.seer.test", "edge.cdn.test."),
                    fixtures::a("edge.cdn.test", "192.0.2.7"),
                    fixtures::a("edge.cdn.test", "192.0.2.8"),
                ],
            )
        }
    }

    fn soa(zone: &str) -> DnsRecord {
        DnsRecord {
            name: zone.into(),
            record_type: RecordType::SOA,
            ttl: 900,
            data: RecordData::SOA {
                mname: format!("ns1.{zone}."),
                rname: format!("hostmaster.{zone}."),
                serial: 2024010101,
                refresh: 7200,
                retry: 3600,
                expire: 1209600,
                minimum: 300,
            },
        }
    }

    /// The drawn words in order, borders and line breaks dropped — for a
    /// note that wraps.
    fn flat(text: &str) -> String {
        text.replace(['│', '╭', '╮', '╰', '╯', '─'], " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The row a table shows `needle` on.
    fn row_with<'t>(text: &'t str, needle: &str) -> &'t str {
        text.lines()
            .find(|l| l.contains(needle))
            .unwrap_or_else(|| panic!("no row with {needle:?} in\n{text}"))
    }

    #[test]
    fn a_positive_answer_lists_the_chain_under_its_real_owners() {
        let text = draw(&dig_data(chained()), &Panes::default(), "", None);
        assert!(
            text.contains("dig · A records · www.seer.test"),
            "title names the type and name: {text}"
        );
        assert!(
            text.contains("● NOERROR  flags qr rd ra  server 1.1.1.1  time 12 ms"),
            "{text}"
        );
        // Each hop under its own owner, then the A records under the
        // chain's end, not under the queried name.
        let hop1 = row_with(&text, "shop.seer.test.");
        assert!(
            hop1.contains("www.seer.test") && hop1.contains("CNAME"),
            "{hop1}"
        );
        let hop2 = row_with(&text, "edge.cdn.test.");
        assert!(
            hop2.contains("shop.seer.test") && hop2.contains("CNAME"),
            "{hop2}"
        );
        let a = row_with(&text, "192.0.2.7");
        assert!(a.contains("edge.cdn.test") && a.contains(" A "), "{a}");
        assert!(!a.contains("www.seer.test"), "{a}");
        let order: Vec<usize> = [
            "shop.seer.test.",
            "edge.cdn.test.",
            "192.0.2.7",
            "192.0.2.8",
        ]
        .iter()
        .map(|needle| text.find(needle).unwrap())
        .collect();
        assert!(order.windows(2).all(|w| w[0] < w[1]), "dig's order: {text}");
        assert!(
            !text.contains("NODATA") && !text.contains("NXDOMAIN"),
            "{text}"
        );
    }

    #[test]
    fn answer_data_is_highlighted_but_chain_hops_are_not() {
        let theme = Theme::frappe();
        let data = dig_data(chained());
        let panes = Panes::default();
        let buffer = render_buffer(100, 16, |f| {
            render(f, f.area(), &theme, 0, &data, "", false, 0, &panes);
        });
        let fg_of = |needle: &str| {
            let area = buffer.area();
            (area.top()..area.bottom())
                .find_map(|y| {
                    let row: String = (area.left()..area.right())
                        .map(|x| buffer[(x, y)].symbol())
                        .collect();
                    let col = row.find(needle)?;
                    let x = row[..col].chars().count() as u16;
                    Some(buffer[(x, y)].fg)
                })
                .unwrap_or_else(|| panic!("{needle} not drawn"))
        };
        assert_eq!(fg_of("192.0.2.7"), theme.green);
        assert_eq!(fg_of("edge.cdn.test."), theme.subtext);
        assert_eq!(fg_of("NOERROR"), theme.green);
    }

    #[test]
    fn nxdomain_says_the_name_does_not_exist_and_shows_the_soa() {
        let result = DnsQueryResult {
            authority: vec![soa("seer.test")],
            ..fixtures::dig_status(RecordType::A, DnsStatus::NxDomain)
        };
        let text = draw(&dig_data(result), &Panes::default(), "", None);
        assert!(
            text.contains("● NXDOMAIN  server default  time 12 ms"),
            "{text}"
        );
        assert!(!text.contains("flags"), "no header flags surfaced: {text}");
        assert!(text.contains("Name does not exist (NXDOMAIN)"), "{text}");
        assert!(!text.contains("NODATA"), "{text}");
        assert!(!text.contains("ANSWER"), "no empty answer table: {text}");
        let soa = row_with(&text, "ns1.seer.test.");
        assert!(soa.contains("seer.test") && soa.contains("SOA"), "{soa}");
        assert!(soa.contains("hostmaster.seer.test."), "{soa}");
        assert!(text.contains("AUTHORITY"), "{text}");
    }

    #[test]
    fn nodata_says_the_name_exists_without_the_type() {
        let result = DnsQueryResult {
            authority: vec![soa("seer.test")],
            ..fixtures::dig(RecordType::AAAA, vec![])
        };
        let text = draw(&dig_data(result), &Panes::default(), "", None);
        assert!(text.contains("● NOERROR"), "{text}");
        assert!(
            text.contains("No AAAA records (NODATA — the name exists)"),
            "{text}"
        );
        assert!(!text.contains("NXDOMAIN"), "{text}");
        assert!(text.contains("AUTHORITY"), "{text}");
    }

    #[test]
    fn server_failures_are_told_apart_from_negative_answers() {
        let theme = Theme::frappe();
        for (status, verdict) in [
            (
                DnsStatus::ServFail,
                "No answer: the server failed to resolve the name (SERVFAIL)",
            ),
            (
                DnsStatus::Refused,
                "No answer: the server refused the query (REFUSED)",
            ),
        ] {
            let data = dig_data(fixtures::dig_status(RecordType::A, status));
            let panes = Panes::default();
            let text = draw(&data, &panes, "", None);
            assert!(text.contains(verdict), "{text}");
            assert!(!text.contains("AUTHORITY"), "{text}");
            // The status is drawn in the failure color.
            let buffer = render_buffer(100, 16, |f| {
                render(f, f.area(), &theme, 0, &data, "", false, 0, &panes);
            });
            let status_row = (0..16u16)
                .find(|&y| {
                    (0..100u16)
                        .map(|x| buffer[(x, y)].symbol())
                        .collect::<String>()
                        .contains(&status.to_string())
                })
                .expect("status line");
            let fg: Vec<_> = (0..100u16)
                .filter(|&x| buffer[(x, status_row)].symbol() == "●")
                .map(|x| buffer[(x, status_row)].fg)
                .collect();
            assert_eq!(fg, [theme.red], "{status}");
        }
    }

    #[test]
    fn a_referral_names_its_zone_instead_of_claiming_nodata() {
        let ns = |host: &str| DnsRecord {
            name: "child.seer.test".into(),
            record_type: RecordType::NS,
            ttl: 300,
            data: RecordData::NS {
                nameserver: host.into(),
            },
        };
        let result = DnsQueryResult {
            authority: vec![ns("ns1.child.seer.test."), ns("ns2.child.seer.test.")],
            ..fixtures::dig_status(RecordType::A, DnsStatus::NoError)
        };
        let text = draw(&dig_data(result), &Panes::default(), "", None);
        assert!(
            flat(&text).contains(
                "No answer: referral to child.seer.test — the server is not authoritative for \
                 the name and does not recurse"
            ),
            "{text}"
        );
        assert!(!text.contains("NODATA"), "{text}");
        assert!(text.contains("AUTHORITY"), "{text}");
        assert!(
            row_with(&text, "ns2.child.seer.test.").contains("NS"),
            "{text}"
        );
    }

    #[test]
    fn a_local_answer_says_no_server_was_asked() {
        let result = DnsQueryResult {
            answered_locally: true,
            flags: vec![],
            ..fixtures::dig(
                RecordType::A,
                vec![fixtures::a("foo.localhost", "127.0.0.1")],
            )
        };
        let text = draw(&dig_data(result), &Panes::default(), "", None);
        assert!(
            text.contains("● NOERROR  server none  time 12 ms"),
            "{text}"
        );
        assert!(flat(&text).contains(wording::LOCAL_NOTE), "{text}");
    }

    #[test]
    fn a_wildcard_note_warns_about_a_likely_synthesized_answer() {
        let mut result = fixtures::dig(
            RecordType::A,
            vec![fixtures::a("anything.seer.test", "192.0.2.9")],
        );
        result.wildcard = Some(WildcardProbe {
            probe_name: "seer-probe-3f9a1c2e7b.seer.test".into(),
            present: true,
            matches_answer: true,
        });
        let text = draw(&dig_data(result.clone()), &Panes::default(), "", None);
        // Wrapped to the pane: the words run across a line break.
        assert!(
            flat(&text).contains(
                "Wildcard: a random sibling (seer-probe-3f9a1c2e7b.seer.test) resolves — this \
                 answer matches it and is likely wildcard-synthesized"
            ),
            "{text}"
        );

        // Right under the answers, not at the foot of the pane.
        let lines: Vec<&str> = text.lines().collect();
        let answer = lines.iter().position(|l| l.contains("192.0.2.9")).unwrap();
        assert!(lines[answer + 2].contains("Wildcard:"), "{text}");

        let probe = result.wildcard.as_mut().unwrap();
        probe.matches_answer = false;
        let text = draw(&dig_data(result.clone()), &Panes::default(), "", None);
        assert!(
            flat(&text).contains("resolves too, but with different data"),
            "{text}"
        );

        // A probe that found no wildcard says nothing.
        result.wildcard.as_mut().unwrap().present = false;
        let text = draw(&dig_data(result), &Panes::default(), "", None);
        assert!(!text.contains("Wildcard"), "{text}");
    }

    #[test]
    fn the_filter_narrows_the_answer_rows_but_not_the_verdict() {
        let data = dig_data(chained());
        let text = draw(&data, &Panes::default(), "192.0.2.8", None);
        assert!(text.contains("192.0.2.8"), "{text}");
        assert!(!text.contains("192.0.2.7"), "{text}");
        assert!(!text.contains("shop.seer.test."), "{text}");
        // Nothing matching is an empty table, not a "no records" verdict.
        let text = draw(&data, &Panes::default(), "zzz", None);
        assert!(text.contains("ANSWER"), "{text}");
        assert!(!text.contains("NODATA"), "{text}");
    }

    #[test]
    fn remote_strings_are_sanitized_onto_one_line() {
        let result = fixtures::dig(
            RecordType::TXT,
            vec![DnsRecord {
                name: "seer.test".into(),
                record_type: RecordType::TXT,
                ttl: 300,
                data: RecordData::TXT {
                    text: "v=spf1\x1b[2J -all\n203.0.113.66".into(),
                },
            }],
        );
        let text = draw(&dig_data(result), &Panes::default(), "", None);
        let row = row_with(&text, "v=spf1");
        assert!(row.contains("\"v=spf1 -all 203.0.113.66\""), "{row}");
        assert!(!text.contains("[2J"), "escape sequence removed: {text}");
    }

    #[test]
    fn selecting_past_the_viewport_scrolls_the_row_into_view() {
        let answers: Vec<DnsRecord> = (1..=30)
            .map(|i| fixtures::a("www.seer.test", &format!("192.0.2.{i}")))
            .collect();
        let data = dig_data(fixtures::dig(RecordType::A, answers));
        let text = draw(&data, &Panes::default(), "", Some(29));
        assert!(text.contains("192.0.2.30"), "{text}");
    }

    #[test]
    fn renders_nameserver_chip_row() {
        let data = dig_data(chained());
        let mut panes = Panes::default();
        let text = draw(&data, &panes, "", None);
        assert!(text.contains(" system   8.8.8.8   1.1.1.1 "), "{text}");
        panes.dns.select_server("9.9.9.9".into());
        let text = draw(&data, &panes, "", None);
        assert!(text.contains(" 1.1.1.1   9.9.9.9 "), "custom slot: {text}");
    }

    #[test]
    fn other_tabs_render_their_own_payloads() {
        let theme = Theme::frappe();
        let panes = Panes::default();
        let trace = LensData::Trace(Box::new(fixtures::trace(
            vec![fixtures::a("www.seer.test", "192.0.2.7")],
            None,
        )));
        let text = render_text(100, 20, |f| {
            render(f, f.area(), &theme, 3, &trace, "", false, 0, &panes);
        });
        assert!(text.contains("trace · www.seer.test A"), "{text}");
        // A Records payload under the Trace tab (a stale cache) draws nothing.
        let text = render_text(100, 20, |f| {
            render(
                f,
                f.area(),
                &theme,
                3,
                &dig_data(chained()),
                "",
                false,
                0,
                &panes,
            );
        });
        assert!(!text.contains("192.0.2.7"), "{text}");
    }
}
