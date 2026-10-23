//! Headers lens — HTTP security-header grade, per-header verdicts, cookie
//! flags, and advisories.
//!
//! The report has four distinct parts and a fixed nine-header spine, so the
//! layout is vertical bands rather than a table: the grade gauge leads (it is
//! the headline number), the per-header verdicts fill the middle as a KV list
//! (selectable once focused, with the selected header's raw value and the
//! reason for its verdict beneath it), and cookies/advisories take what is
//! left. Bands with nothing to show
//! collapse to zero height instead of leaving a labeled empty box.
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;
use seer_core::output::sanitize_line;
use seer_core::HeaderVerdict;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::inspector::{self, Field};
use crate::tui::widgets::{dot, gauge, kv, panel, row_style};

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

pub fn render(
    f: &mut Frame,
    area: Rect,
    theme: &Theme,
    data: &LensData,
    focused: bool,
    sel: usize,
) {
    let LensData::Headers(h) = data else { return };

    let title = format!("HTTP Headers · {} · {}/100", h.grade, h.score);
    let inner = panel::render(f, area, theme, &title, theme.mauve, focused);

    let detail = focused
        .then(|| h.headers.get(sel))
        .flatten()
        .map(|finding| {
            let fields = [
                Field::new("header", finding.header.clone()),
                Field::new("verdict", finding.verdict.as_str()).tone(verdict_tone(finding.verdict)),
                Field::new("value", finding.value.clone().unwrap_or_default()),
                Field::new("note", finding.note.clone().unwrap_or_default()),
            ];
            inspector::lines(theme, &fields, inner.width)
        })
        .unwrap_or_default();
    let detail_rows = u16::try_from(detail.len()).unwrap_or(u16::MAX);

    let cookie_rows = if h.cookies.is_empty() { 0 } else { 1 };
    // Advisories get whatever vertical space is left, so a long list scrolls
    // off rather than squeezing the verdicts it is explaining.
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),                      // gauge + url
            Constraint::Length(h.headers.len() as u16), // per-header verdicts
            Constraint::Length(detail_rows),            // selected header (focused)
            Constraint::Length(cookie_rows),
            Constraint::Min(0), // advisories
        ])
        .split(inner);

    // Grade gauge — score is already 0–100.
    let ratio = f64::from(h.score) / 100.0;
    let width = chunks[0].width.saturating_sub(20).clamp(10, 40);
    let label = format!("{} ({}/100)", h.grade, h.score);
    f.render_widget(
        Paragraph::new(vec![
            gauge::line(
                theme,
                ratio,
                width,
                theme.tone(grade_tone(&h.grade)),
                Some(&label),
            ),
            Line::from(Span::styled(
                format!("{}  [HTTP {}]", sanitize_line(&h.url), h.status),
                Style::default().fg(theme.subtext),
            )),
        ]),
        chunks[0],
    );

    // Per-header verdicts. The value carries the verdict word; the header name
    // is the key, so this reads as a checklist top to bottom.
    //
    // Built from `kv`'s gutter and leaders rather than `kv::render`: that
    // paints every value one color, and colouring each verdict by severity
    // is the whole point of this band — a column of same-colored words
    // would bury the absent headers among the strict ones.
    let gutter = kv::gutter(h.headers.iter().map(|f| f.header.as_str()), chunks[1].width);
    let lines: Vec<Line> = h
        .headers
        .iter()
        .enumerate()
        .map(|(i, finding)| {
            let header = sanitize_line(&finding.header);
            let mut spans = kv::leader(theme, &header, theme.mauve, gutter).to_vec();
            spans.push(Span::styled(
                finding.verdict.as_str(),
                Style::default().fg(theme.tone(verdict_tone(finding.verdict))),
            ));
            Line::from(spans).style(row_style(theme, focused && i == sel))
        })
        .collect();
    f.render_widget(Paragraph::new(lines), chunks[1]);
    inspector::draw(f, chunks[2], theme, detail);

    if !h.cookies.is_empty() {
        let flawed = h.cookies.iter().filter(|c| !c.issues.is_empty()).count();
        let tone = if flawed == 0 { "ok" } else { "warn" };
        f.render_widget(
            Paragraph::new(dot::line(
                theme,
                tone,
                format!("{} cookie(s), {} with issues", h.cookies.len(), flawed),
            )),
            chunks[3],
        );
    }

    if !h.notes.is_empty() {
        let lines: Vec<Line> = h
            .notes
            .iter()
            .map(|n| dot::line(theme, "warn", n.clone()))
            .collect();
        f.render_widget(Paragraph::new(lines), chunks[4]);
    } else {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "no advisories — every graded header is set",
                Style::default()
                    .fg(theme.green)
                    .add_modifier(Modifier::ITALIC),
            ))),
            chunks[4],
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    /// The verdict word on `header`'s dot-leader row. Checking the row itself
    /// matters: a bare `contains("strict")` is always satisfied by the header
    /// name "strict-transport-security".
    fn verdict_on_row(s: &str, header: &str) -> String {
        let row = s
            .lines()
            .find(|l| l.contains(&format!("{header} ·")))
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
