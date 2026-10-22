//! Audit lens — overall grade, category strip, findings worst-first.
//!
//! Same vertical-band layout as the Headers lens: a fixed header (grade
//! gauge, category strip and, when any check did not finish, an incomplete
//! notice) over a findings table. The table is selectable and scrolls with
//! the selection like the Takeover lens, so a long list never hides rows or
//! the incomplete notice.
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Row, Table};
use ratatui::Frame;
use seer_core::audit::{CategoryState, CheckStatus, Severity};
use seer_core::grade::Letter;
use seer_core::output::sanitize_line;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::{dot, gauge, panel, row_style, scroll_to};

/// Letter band → tone: A/A+ pass, B/C partial, D and below fail.
fn letter_tone(letter: Letter) -> &'static str {
    match letter {
        Letter::APlus | Letter::A => "ok",
        Letter::B | Letter::C => "warn",
        _ => "fail",
    }
}

fn severity_tone(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "fail",
        Severity::Medium | Severity::Low => "warn",
        Severity::Info => "info",
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
    let LensData::Audit(a) = data else { return };

    let title = match &a.overall {
        Some(o) => format!("Security Audit · {} · {}/100", o.letter.as_str(), o.score),
        None => "Security Audit · not graded".to_string(),
    };
    let inner = panel::render(f, area, theme, &title, theme.mauve, focused);
    let skipped = a
        .runs
        .iter()
        .filter(|r| matches!(r.status, CheckStatus::Incomplete { .. }))
        .count();
    // The incomplete notice lives in the fixed header so overflow in the
    // findings list can never hide it.
    let header_rows = 2 + u16::from(!a.complete);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(header_rows), Constraint::Min(0)])
        .split(inner);

    let width = chunks[0].width.saturating_sub(20).clamp(10, 40);
    // Outlives the gauge line, which borrows it.
    let label = a
        .overall
        .as_ref()
        .map(|o| format!("{} ({}/100)", o.letter.as_str(), o.score));
    let headline = match &a.overall {
        Some(o) => gauge::line(
            theme,
            f64::from(o.score) / 100.0,
            width,
            theme.tone(letter_tone(o.letter)),
            label.as_deref(),
        ),
        None => Line::from(Span::styled(
            "not graded — no check completed",
            Style::default().fg(theme.subtext),
        )),
    };
    let strip: Vec<Span> = a
        .categories
        .iter()
        .flat_map(|c| {
            let (text, tone) = match (c.state, c.letter) {
                (CategoryState::Graded, Some(l)) => (l.as_str(), letter_tone(l)),
                (CategoryState::NotApplicable, _) => ("n/a", ""),
                _ => ("?", "warn"),
            };
            [
                Span::styled(
                    format!("{} ", c.category.label()),
                    Style::default().fg(theme.mauve),
                ),
                Span::styled(format!("{text}  "), Style::default().fg(theme.tone(tone))),
            ]
        })
        .collect();
    let mut header = vec![headline, Line::from(strip)];
    if !a.complete {
        header.push(dot::line(
            theme,
            "warn",
            format!("incomplete: {skipped} check(s) did not finish — see raw view"),
        ));
    }
    f.render_widget(Paragraph::new(header), chunks[0]);

    if a.findings.is_empty() {
        // "No findings" is only good news when every check ran and graded.
        if a.complete && a.overall.is_some() {
            f.render_widget(
                Paragraph::new(dot::line(theme, "ok", "no findings")),
                chunks[1],
            );
        }
        return;
    }

    let rows = a.findings.iter().enumerate().map(|(i, finding)| {
        let base = row_style(theme, focused && i == sel);
        Row::new(vec![
            Span::styled(
                finding.severity.as_str().to_ascii_uppercase(),
                base.fg(theme.tone(severity_tone(finding.severity))),
            ),
            Span::styled(sanitize_line(&finding.title), base),
            Span::styled(finding.id, base.fg(theme.subtext)),
        ])
        .style(base)
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(9),
            Constraint::Percentage(55),
            Constraint::Percentage(35),
        ],
    )
    .header(Row::new(["SEVERITY", "FINDING", "CHECK"]).style(Style::default().fg(theme.overlay0)))
    .column_spacing(1);
    let mut state = scroll_to(focused.then_some(sel));
    f.render_stateful_widget(table, chunks[1], &mut state);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::test_util::render_lines;
    use seer_core::audit::{
        AuditReport, Category, CategoryGrade, CategoryState, Finding, OverallGrade, Severity,
    };

    fn report() -> AuditReport {
        AuditReport {
            domain: "example.com".into(),
            host: "example.com".into(),
            overall: Some(OverallGrade {
                score: 72,
                letter: Letter::C,
                capped_by: Some(Severity::High),
            }),
            categories: Category::ALL
                .iter()
                .map(|&c| CategoryGrade {
                    category: c,
                    state: CategoryState::Graded,
                    score: Some(80),
                    letter: Some(Letter::B),
                })
                .collect(),
            findings: vec![Finding {
                id: "email.dmarc.missing",
                category: Category::Email,
                severity: Severity::High,
                host: "example.com".into(),
                title: "No DMARC record".into(),
                evidence: None,
                remediation: None,
            }],
            runs: vec![],
            complete: false,
            fail_under: None,
            passed: true,
        }
    }

    fn render_to_text(data: &LensData) -> String {
        let theme = Theme::frappe();
        render_lines(90, 16, |f| render(f, f.area(), &theme, data, false, 0))
    }

    #[test]
    fn shows_grade_categories_and_findings() {
        let s = render_to_text(&LensData::Audit(Box::new(report())));
        assert!(s.contains("72"), "{s}");
        assert!(s.contains("TLS"), "{s}");
        assert!(s.contains("No DMARC record"), "{s}");
        assert!(s.contains("incomplete"), "{s}");
    }

    #[test]
    fn ungraded_report_says_so() {
        let mut r = report();
        r.overall = None;
        let s = render_to_text(&LensData::Audit(Box::new(r)));
        assert!(s.contains("not graded"), "{s}");
    }

    fn finding(n: usize, title: &str) -> Finding {
        Finding {
            id: "web.headers.missing",
            category: Category::Web,
            severity: Severity::Low,
            host: "example.com".into(),
            title: format!("{title} {n}"),
            evidence: None,
            remediation: None,
        }
    }

    #[test]
    fn selection_scrolls_a_long_findings_list() {
        let mut r = report();
        r.findings = (0..40).map(|n| finding(n, "Finding")).collect();
        let data = LensData::Audit(Box::new(r));
        let theme = Theme::frappe();
        let at = |sel| render_lines(90, 16, |f| render(f, f.area(), &theme, &data, true, sel));
        assert!(!at(0).contains("Finding 39"));
        let s = at(39);
        assert!(s.contains("Finding 39"), "{s}");
        assert!(
            s.contains("incomplete"),
            "the header notice survives scrolling: {s}"
        );
    }

    #[test]
    fn no_findings_line_only_for_a_complete_graded_report() {
        let mut r = report();
        r.findings.clear();
        r.complete = true;
        assert!(render_to_text(&LensData::Audit(Box::new(r.clone()))).contains("no findings"));
        r.complete = false;
        assert!(!render_to_text(&LensData::Audit(Box::new(r.clone()))).contains("no findings"));
        r.complete = true;
        r.overall = None;
        assert!(!render_to_text(&LensData::Audit(Box::new(r))).contains("no findings"));
    }

    #[test]
    fn hostile_titles_render_on_one_row_without_control_characters() {
        let mut r = report();
        r.findings = vec![finding(1, "evil\nsecond\x1b[31mred")];
        let s = render_to_text(&LensData::Audit(Box::new(r)));
        assert!(!s.contains('\x1b'), "{s:?}");
        let row: Vec<&str> = s.lines().filter(|l| l.contains("evil")).collect();
        assert_eq!(row.len(), 1, "{s}");
        assert!(
            row[0].contains("second"),
            "newline joined onto one row: {s}"
        );
    }
}
