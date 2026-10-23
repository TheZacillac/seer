//! Audit lens — overall grade, category strip, findings worst-first.
//!
//! Same vertical-band layout as the Headers lens: a fixed header (grade
//! gauge, category strip and, when any check did not finish, an incomplete
//! notice) over a findings table. The table is selectable and scrolls with
//! the selection like the Takeover lens, so a long list never hides rows or
//! the incomplete notice. While focused, the selected finding's evidence and
//! remediation show beneath it.
use ratatui::layout::Constraint;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Row;
use seer_core::audit::{CategoryState, CheckStatus, Finding, Severity};
use seer_core::grade::Letter;
use seer_core::output::sanitize_line;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::inspector::Field;
use crate::tui::widgets::page::{Block, Detail, Page, TableBlock};
use crate::tui::widgets::{dot, gauge};

/// Columns of the grade gauge.
const GAUGE: u16 = 30;

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

/// The selected finding's detail, in reading order: what, how bad, where,
/// what was seen, how to fix it, and the stable id to grep for.
fn finding_fields(finding: &Finding) -> Vec<Field> {
    let mut fields = vec![
        Field::new("finding", finding.title.clone()),
        Field::new(
            "severity",
            format!(
                "{} · {}",
                finding.severity.as_str(),
                finding.category.label()
            ),
        )
        .tone(severity_tone(finding.severity)),
        Field::new("host", finding.host.clone()),
    ];
    if let Some(evidence) = &finding.evidence {
        fields.push(Field::new("evidence", evidence.clone()));
    }
    if let Some(fix) = &finding.remediation {
        fields.push(Field::new("remediation", fix.clone()));
    }
    fields.push(Field::new("check", finding.id));
    fields
}

pub fn page(theme: &Theme, data: &LensData, focused: bool, sel: usize) -> Option<Page> {
    let LensData::Audit(a) = data else {
        return None;
    };

    let title = match &a.overall {
        Some(o) => format!("Security Audit · {} · {}/100", o.letter.as_str(), o.score),
        None => "Security Audit · not graded".to_string(),
    };
    let skipped = a
        .runs
        .iter()
        .filter(|r| matches!(r.status, CheckStatus::Incomplete { .. }))
        .count();
    let label = a
        .overall
        .as_ref()
        .map(|o| format!("{} ({}/100)", o.letter.as_str(), o.score));
    let headline = match &a.overall {
        Some(o) => gauge::line(
            theme,
            f64::from(o.score) / 100.0,
            GAUGE,
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
    // The incomplete notice is kept whole, so a long findings list can
    // never hide it.
    let mut header = vec![headline, Line::from(strip)];
    if !a.complete {
        header.push(dot::line(
            theme,
            "warn",
            format!("incomplete: {skipped} check(s) did not finish — see raw view"),
        ));
    }
    let page = Page::new(title, theme.mauve).push(Block::Lines(header));

    if a.findings.is_empty() {
        // "No findings" is only good news when every check ran and graded.
        let good = a.complete && a.overall.is_some();
        return Some(page.push_if(good, || {
            Block::Lines(vec![dot::line(theme, "ok", "no findings")])
        }));
    }

    let rows = a
        .findings
        .iter()
        .map(|finding| {
            Row::new(vec![
                Span::styled(
                    finding.severity.as_str().to_ascii_uppercase(),
                    Style::default().fg(theme.tone(severity_tone(finding.severity))),
                ),
                Span::raw(sanitize_line(&finding.title)),
                Span::styled(finding.id, Style::default().fg(theme.subtext)),
            ])
        })
        .collect();
    let detail = focused
        .then(|| a.findings.get(sel))
        .flatten()
        .map_or(Detail::None, |finding| {
            Detail::Fields(finding_fields(finding))
        });
    let table = TableBlock::new(
        vec!["SEVERITY", "FINDING", "CHECK"],
        vec![
            Constraint::Length(9),
            Constraint::Percentage(55),
            Constraint::Percentage(35),
        ],
        rows,
    )
    .selected(focused.then_some(sel))
    .detail(detail);
    Some(page.push(Block::Gap).push(Block::Table(table)))
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
    fn focused_selection_shows_evidence_and_remediation() {
        let theme = Theme::frappe();
        let mut r = report();
        r.findings[0].evidence = Some("no TXT at _dmarc.example.com".into());
        r.findings[0].remediation = Some("Publish v=DMARC1; p=quarantine".into());
        let data = LensData::Audit(Box::new(r));
        let focused = render_lines(90, 20, |f| render(f, f.area(), &theme, &data, true, 0));
        assert!(
            focused.contains("no TXT at _dmarc.example.com"),
            "{focused}"
        );
        assert!(focused.contains("Publish v=DMARC1"), "{focused}");
        let nav = render_lines(90, 20, |f| render(f, f.area(), &theme, &data, false, 0));
        assert!(
            !nav.contains("Publish v=DMARC1"),
            "detail only while focused: {nav}"
        );
        // A stale selection past the list shows no detail and does not panic.
        let stale = render_lines(90, 20, |f| render(f, f.area(), &theme, &data, true, 9));
        assert!(!stale.contains("Publish v=DMARC1"), "{stale}");
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
