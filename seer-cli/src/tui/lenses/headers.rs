//! Headers lens — HTTP security-header grade, per-header verdicts, cookie
//! flags, and advisories.
//!
//! The grade gauge leads (it is the headline number), then the per-header
//! verdicts as a two-column table (selectable once focused, with the
//! selected header's raw value and the reason for its verdict beneath it),
//! then cookies and the advisories, which give rows up first when short. Bands with nothing to show
//! collapse to zero height instead of leaving a labeled empty box.
use ratatui::layout::Constraint;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Row;
use seer_core::output::sanitize_line;
use seer_core::HeaderVerdict;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::inspector::Field;
use crate::tui::widgets::page::{Block, Detail, Page, TableBlock};
use crate::tui::widgets::{dot, gauge};

/// Columns of the grade gauge.
const GAUGE: u16 = 30;

/// Tone for a verdict, using the shared `Theme::tone` vocabulary so these
/// verdicts read the same as every other status in the TUI.
fn verdict_tone(v: HeaderVerdict) -> &'static str {
    match v {
        HeaderVerdict::Strict | HeaderVerdict::Present => "ok",
        // Unknown is posture-only (a failed DNS lookup); headers never grade it.
        HeaderVerdict::Moderate | HeaderVerdict::Weak | HeaderVerdict::Unknown => "warn",
        HeaderVerdict::Absent => "fail",
    }
}

/// Grade band → tone. A/A+ pass, B/C partial, D and below fail.
fn grade_tone(grade: &str) -> &'static str {
    match grade {
        "A+" | "A" => "ok",
        "B" | "C" => "warn",
        _ => "fail",
    }
}

pub fn page(theme: &Theme, data: &LensData, focused: bool, sel: usize) -> Option<Page> {
    let LensData::Headers(h) = data else {
        return None;
    };

    // Grade gauge — score is already 0–100.
    let label = format!("{} ({}/100)", h.grade, h.score);
    let summary = vec![
        gauge::line(
            theme,
            f64::from(h.score) / 100.0,
            GAUGE,
            theme.tone(grade_tone(&h.grade)),
            Some(&label),
        ),
        Line::from(Span::styled(
            format!("{}  [HTTP {}]", sanitize_line(&h.url), h.status),
            Style::default().fg(theme.subtext),
        )),
    ];

    // Per-header verdicts: the header name, then the verdict word colored by
    // severity, so the absent headers stand out among the strict ones.
    let names: Vec<String> = h.headers.iter().map(|f| sanitize_line(&f.header)).collect();
    let name_w = names
        .iter()
        .map(|n| Span::raw(n.as_str()).width())
        .max()
        .unwrap_or(0);
    let rows = h
        .headers
        .iter()
        .zip(names)
        .map(|(finding, name)| {
            Row::new(vec![
                Span::styled(name, Style::default().fg(theme.mauve)),
                Span::styled(
                    finding.verdict.as_str(),
                    Style::default().fg(theme.tone(verdict_tone(finding.verdict))),
                ),
            ])
        })
        .collect();
    let detail = focused
        .then(|| h.headers.get(sel))
        .flatten()
        .map_or(Detail::None, |finding| {
            Detail::Fields(vec![
                Field::new("header", finding.header.clone()),
                Field::new("verdict", finding.verdict.as_str()).tone(verdict_tone(finding.verdict)),
                Field::new("value", finding.value.clone().unwrap_or_default()),
                Field::new("note", finding.note.clone().unwrap_or_default()),
            ])
        });
    // The longest name (or the column title), a space, then the verdict.
    let width = u16::try_from(name_w.max("HEADER".len()) + 1).unwrap_or(u16::MAX);
    let table = TableBlock::new(
        vec!["HEADER", "VERDICT"],
        vec![Constraint::Length(width), Constraint::Min(0)],
        rows,
    )
    .selected(focused.then_some(sel))
    .detail(detail);

    let cookies = (!h.cookies.is_empty()).then(|| {
        let flawed = h.cookies.iter().filter(|c| !c.issues.is_empty()).count();
        let tone = if flawed == 0 { "ok" } else { "warn" };
        dot::line(
            theme,
            tone,
            format!("{} cookie(s), {} with issues", h.cookies.len(), flawed),
        )
    });
    // Advisories give rows up first, so a long list never squeezes the
    // verdicts it explains.
    let advisories = if h.notes.is_empty() {
        Block::Lines(vec![Line::from(Span::styled(
            "no advisories — every graded header is set",
            Style::default()
                .fg(theme.green)
                .add_modifier(Modifier::ITALIC),
        ))])
    } else {
        Block::Scroll {
            lines: h
                .notes
                .iter()
                .map(|n| dot::line(theme, "warn", n.clone()))
                .collect(),
            offset: 0,
            unit: "advisories",
        }
    };
    Some(
        Page::new(
            format!("HTTP Headers · {} · {}/100", h.grade, h.score),
            theme.mauve,
        )
        .push(Block::Lines(summary))
        .push(Block::Gap)
        .push(Block::Table(table))
        .push(Block::Gap)
        .push_if(cookies.is_some(), || {
            Block::Lines(cookies.into_iter().collect())
        })
        .push(advisories),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::widgets::page;

    /// Draw this lens's page as the TUI does.
    fn render(
        f: &mut ratatui::Frame,
        area: ratatui::layout::Rect,
        theme: &Theme,
        data: &LensData,
        focused: bool,
        sel: usize,
    ) {
        if let Some(p) = page(theme, data, focused, sel) {
            page::draw(f, area, theme, p, focused);
        }
    }
    use crate::tui::test_util::{render_buffer, render_lines};
    use seer_core::{CookieFinding, Disclosure, HeaderFinding, HeaderReport};

    fn finding(header: &str, verdict: HeaderVerdict) -> HeaderFinding {
        HeaderFinding {
            header: header.into(),
            present: verdict != HeaderVerdict::Absent,
            value: None,
            verdict,
            note: None,
        }
    }

    fn report() -> HeaderReport {
        HeaderReport {
            domain: "example.com".into(),
            url: "https://example.com/".into(),
            status: 200,
            redirects: 0,
            grade: "C".into(),
            score: 65,
            headers: vec![
                finding("strict-transport-security", HeaderVerdict::Strict),
                finding("content-security-policy", HeaderVerdict::Absent),
            ],
            cookies: vec![CookieFinding {
                name: "session".into(),
                secure: false,
                http_only: true,
                same_site: None,
                verdict: HeaderVerdict::Weak,
                issues: vec!["missing Secure".into()],
            }],
            disclosures: vec![Disclosure {
                header: "server".into(),
                value: "nginx/1.25".into(),
                versioned: true,
            }],
            notes: vec!["content-security-policy: Add a policy.".into()],
        }
    }

    fn render_to_text(data: &LensData, width: u16, height: u16) -> String {
        let theme = Theme::frappe();
        render_lines(width, height, |f| {
            render(f, f.area(), &theme, data, false, 0);
        })
    }

    /// On a short pane a long value must not clip the selected verdict row
    /// out of view; the verdicts scroll to it and the detail is cut short.
    #[test]
    fn selected_verdict_stays_visible_on_a_short_pane() {
        let theme = Theme::frappe();
        let mut r = report();
        r.headers = (0..9)
            .map(|i| finding(&format!("x-header-{i}"), HeaderVerdict::Present))
            .collect();
        r.headers[8].value = Some("a ".repeat(300));
        let data = LensData::Headers(Box::new(r));
        let s = render_lines(60, 18, |f| render(f, f.area(), &theme, &data, true, 8));
        assert!(s.contains("x-header-8 "), "selected row must show: {s}");
        assert!(s.contains("more lines"), "the detail is cut short: {s}");
    }

    /// A header name is remote text: an escape sequence in it is stripped,
    /// and the name column is sized to the name as drawn.
    #[test]
    fn header_names_are_sanitized_and_sized_as_drawn() {
        let mut r = report();
        r.headers = vec![finding("x-\u{1b}[2Jframe", HeaderVerdict::Present)];
        let s = render_to_text(&LensData::Headers(Box::new(r)), 80, 16);
        assert!(!s.contains('\u{1b}'), "{s}");
        assert!(s.contains("x-frame  present"), "{s}");
    }

    #[test]
    fn focused_header_shows_its_value_and_note() {
        let theme = Theme::frappe();
        let mut r = report();
        r.headers[0].value = Some("max-age=63072000; includeSubDomains; preload".into());
        r.headers[0].note = Some("Strict: long max-age with preload.".into());
        let data = LensData::Headers(Box::new(r));
        let s = render_lines(80, 24, |f| render(f, f.area(), &theme, &data, true, 0));
        assert!(s.contains("includeSubDomains; preload"), "{s}");
        assert!(s.contains("long max-age"), "{s}");
        let nav = render_lines(80, 24, |f| render(f, f.area(), &theme, &data, false, 0));
        assert!(!nav.contains("includeSubDomains"), "{nav}");
    }

    #[test]
    fn renders_grade_and_score() {
        let s = render_to_text(&LensData::Headers(Box::new(report())), 80, 16);
        assert!(s.contains("65"), "score must be visible: {s}");
        assert!(s.contains('C'), "grade must be visible: {s}");
    }

    /// The verdict word on `header`'s row. Checking the row itself matters:
    /// a bare `contains("strict")` is always satisfied by the header name
    /// "strict-transport-security".
    fn verdict_on_row(s: &str, header: &str) -> String {
        let row = s
            .lines()
            .find(|l| l.contains(&format!("{header} ")))
            .unwrap_or_else(|| panic!("no verdict row for {header}: {s}"));
        row.trim_end()
            .trim_end_matches('│')
            .split_whitespace()
            .last()
            .unwrap_or_default()
            .to_string()
    }

    #[test]
    fn renders_each_header_with_its_verdict() {
        let s = render_to_text(&LensData::Headers(Box::new(report())), 80, 16);
        assert_eq!(verdict_on_row(&s, "strict-transport-security"), "strict");
        assert_eq!(verdict_on_row(&s, "content-security-policy"), "absent");
    }

    #[test]
    fn renders_cookie_summary_and_advisories() {
        let s = render_to_text(&LensData::Headers(Box::new(report())), 80, 16);
        assert!(s.contains("1 cookie(s), 1 with issues"), "got: {s}");
        assert!(s.contains("Add a policy"), "got: {s}");
    }

    #[test]
    fn clean_report_says_so_rather_than_leaving_a_blank_band() {
        let mut r = report();
        r.notes.clear();
        r.grade = "A+".into();
        r.score = 100;
        let s = render_to_text(&LensData::Headers(Box::new(r)), 80, 16);
        assert!(s.contains("no advisories"), "got: {s}");
    }

    #[test]
    fn wrong_payload_variant_renders_nothing() {
        // The dispatch in lenses::render is keyed by lens, not by payload, so
        // a mismatched variant must be a no-op rather than a panic.
        let theme = Theme::frappe();
        let data = LensData::History(vec![]);
        render_buffer(40, 6, |f| render(f, f.area(), &theme, &data, false, 0));
    }

    #[test]
    fn verdict_tones_follow_severity() {
        assert_eq!(verdict_tone(HeaderVerdict::Strict), "ok");
        assert_eq!(verdict_tone(HeaderVerdict::Present), "ok");
        assert_eq!(verdict_tone(HeaderVerdict::Moderate), "warn");
        assert_eq!(verdict_tone(HeaderVerdict::Weak), "warn");
        assert_eq!(verdict_tone(HeaderVerdict::Absent), "fail");
    }

    #[test]
    fn grade_tones_follow_bands() {
        assert_eq!(grade_tone("A+"), "ok");
        assert_eq!(grade_tone("A"), "ok");
        assert_eq!(grade_tone("B"), "warn");
        assert_eq!(grade_tone("C"), "warn");
        assert_eq!(grade_tone("D"), "fail");
        assert_eq!(grade_tone("F"), "fail");
    }
}
