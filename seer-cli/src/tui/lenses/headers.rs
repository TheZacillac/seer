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
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;
use seer_core::output::sanitize_line;
use seer_core::HeaderVerdict;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::inspector::{self, Field};
use crate::tui::widgets::{dot, gauge, kv, panel, row_style, stack, Band};

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

    // Stacked like the other lenses: when the bands do not all fit, the
    // verdicts give up rows first (scrolling to the selection), then the
    // detail, so the selected row and its value stay in view. Advisories get
    // what is left, so a long list scrolls off rather than squeezing the
    // verdicts it is explaining.
    let rows = |n: usize| u16::try_from(n).unwrap_or(u16::MAX);
    let n = h.headers.len();
    let mut layout = vec![
        Band::fixed(2),
        Band::shrinking(rows(n), rows(n.min(inspector::MIN_ROWS))),
    ];
    if !detail.is_empty() {
        layout.push(inspector::band(&detail));
    }
    if !h.cookies.is_empty() {
        layout.push(Band::fixed(1));
    }
    layout.push(Band::shrinking(rows(h.notes.len().max(1)), 1));
    let mut bands = stack(inner, &layout).into_iter();
    let mut next_band = || bands.next().unwrap_or_default();
    let gauge_area = next_band();
    let verdict_area = next_band();

    // Grade gauge — score is already 0–100.
    let ratio = f64::from(h.score) / 100.0;
    let width = gauge_area.width.saturating_sub(20).clamp(10, 40);
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
        gauge_area,
    );

    // Per-header verdicts. The value carries the verdict word; the header name
    // is the key, so this reads as a checklist top to bottom.
    //
    // Built from `kv`'s gutter and leaders rather than `kv::render`: that
    // paints every value one color, and colouring each verdict by severity
    // is the whole point of this band — a column of same-colored words
    // would bury the absent headers among the strict ones.
    // Sanitized once, so the gutter is measured on the names as drawn.
    let names: Vec<String> = h.headers.iter().map(|f| sanitize_line(&f.header)).collect();
    let gutter = kv::gutter(names.iter().map(String::as_str), verdict_area.width);
    let lines: Vec<Line> = h
        .headers
        .iter()
        .zip(&names)
        .enumerate()
        .map(|(i, (finding, header))| {
            let mut spans = kv::leader(theme, header, theme.mauve, gutter).to_vec();
            spans.push(Span::styled(
                finding.verdict.as_str(),
                Style::default().fg(theme.tone(verdict_tone(finding.verdict))),
            ));
            Line::from(spans).style(row_style(theme, focused && i == sel))
        })
        .collect();
    // Scroll the verdicts so a selection past the band's last row shows.
    let visible = usize::from(verdict_area.height);
    let top = if focused && sel >= visible {
        sel + 1 - visible
    } else {
        0
    };
    f.render_widget(Paragraph::new(lines).scroll((rows(top), 0)), verdict_area);
    if !detail.is_empty() {
        inspector::draw(f, next_band(), theme, detail);
    }

    if !h.cookies.is_empty() {
        let flawed = h.cookies.iter().filter(|c| !c.issues.is_empty()).count();
        let tone = if flawed == 0 { "ok" } else { "warn" };
        f.render_widget(
            Paragraph::new(dot::line(
                theme,
                tone,
                format!("{} cookie(s), {} with issues", h.cookies.len(), flawed),
            )),
            next_band(),
        );
    }

    let notes_area = next_band();
    if !h.notes.is_empty() {
        let lines: Vec<Line> = h
            .notes
            .iter()
            .map(|n| dot::line(theme, "warn", n.clone()))
            .collect();
        f.render_widget(Paragraph::new(lines), notes_area);
    } else {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "no advisories — every graded header is set",
                Style::default()
                    .fg(theme.green)
                    .add_modifier(Modifier::ITALIC),
            ))),
            notes_area,
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
        assert!(s.contains("x-header-8 ·"), "selected row must show: {s}");
        assert!(s.contains("more lines"), "the detail is cut short: {s}");
    }

    /// The gutter is measured on the name as drawn: an escape sequence
    /// stripped from a header name must not widen the leaders.
    #[test]
    fn gutter_is_measured_on_sanitized_header_names() {
        let mut r = report();
        r.headers = vec![finding("x-\u{1b}[2Jframe", HeaderVerdict::Present)];
        let s = render_to_text(&LensData::Headers(Box::new(r)), 80, 16);
        assert!(s.contains("x-frame ·· "), "{s}");
        assert!(!s.contains("x-frame ···"), "{s}");
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
