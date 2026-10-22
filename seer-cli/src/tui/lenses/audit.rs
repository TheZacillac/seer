//! Audit lens — overall grade, category strip, findings worst-first.
//!
//! Same vertical-band layout as the Headers lens: the grade gauge leads, the
//! category strip sits under it, findings fill the rest (a long list scrolls
//! off the bottom rather than squeezing the headline).
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;
use seer_core::audit::{CategoryState, CheckStatus, Severity};
use seer_core::grade::Letter;
use seer_core::output::sanitize_line;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::{dot, gauge, panel};

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

pub fn render(f: &mut Frame, area: Rect, theme: &Theme, data: &LensData) {
    let LensData::Audit(a) = data else { return };

    let title = match &a.overall {
        Some(o) => format!("Security Audit · {} · {}/100", o.letter.as_str(), o.score),
        None => "Security Audit · not graded".to_string(),
    };
    let inner = panel::render(f, area, theme, &title, theme.mauve, false);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(0)])
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
    f.render_widget(Paragraph::new(vec![headline, Line::from(strip)]), chunks[0]);

    let mut lines: Vec<Line> = a
        .findings
        .iter()
        .map(|finding| {
            dot::line(
                theme,
                severity_tone(finding.severity),
                format!(
                    "{:<8} {} · {}",
                    finding.severity.as_str().to_ascii_uppercase(),
                    sanitize_line(&finding.title),
                    finding.id
                ),
            )
        })
        .collect();
    if a.findings.is_empty() {
        lines.push(dot::line(theme, "ok", "no findings"));
    }
    if !a.complete {
        let skipped = a
            .runs
            .iter()
            .filter(|r| matches!(r.status, CheckStatus::Incomplete { .. }))
            .count();
        lines.push(dot::line(
            theme,
            "warn",
            format!("incomplete: {skipped} check(s) did not finish — see raw view"),
        ));
    }
    f.render_widget(Paragraph::new(lines), chunks[1]);
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
        render_lines(90, 16, |f| render(f, f.area(), &theme, data))
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
}
