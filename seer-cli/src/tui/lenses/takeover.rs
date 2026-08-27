//! Takeover lens — selectable table of takeover findings.
//!
//! Only actionable hosts are listed: `scan_takeover` filters `Safe` out of
//! `findings` before returning, so the table is the findings vec and the
//! summary line carries how many hosts were actually checked. A clean scan
//! shows the count and says so rather than rendering an empty grid.
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Row, Table};
use ratatui::Frame;
use seer_core::TakeoverVerdict;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::{panel, scroll_to};

fn verdict_tone(v: TakeoverVerdict) -> &'static str {
    match v {
        TakeoverVerdict::Vulnerable => "fail",
        TakeoverVerdict::Potential => "warn",
        TakeoverVerdict::Safe => "ok",
    }
}

fn verdict_label(v: TakeoverVerdict) -> &'static str {
    match v {
        // Shouted, because a confirmed takeover is the one finding in this
        // tool that warrants dropping everything.
        TakeoverVerdict::Vulnerable => "VULNERABLE",
        TakeoverVerdict::Potential => "potential",
        TakeoverVerdict::Safe => "safe",
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
    let LensData::Takeover(t) = data else { return };

    // Border accent tracks the worst finding, so the panel itself signals
    // severity before any row is read.
    let accent = if t.vulnerable > 0 {
        theme.red
    } else if t.potential > 0 {
        theme.yellow
    } else {
        theme.green
    };
    let title = format!(
        "Takeover · {} checked · {} vulnerable · {} potential",
        t.hosts_checked, t.vulnerable, t.potential
    );
    let block = panel::block(theme, &title, accent, focused);
    let inner = block.inner(area);
    f.render_widget(block, area);

    if t.findings.is_empty() {
        let msg = if t.hosts_checked == 0 {
            "no hosts to scan".to_string()
        } else {
            format!("no takeover signals across {} host(s)", t.hosts_checked)
        };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                msg,
                Style::default()
                    .fg(theme.green)
                    .add_modifier(Modifier::ITALIC),
            ))),
            inner,
        );
        return;
    }

    // Reserve a line for the skipped-hosts note so a truncated scan never
    // silently reads as a complete one.
    let skipped_rows = u16::from(t.hosts_skipped > 0);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(skipped_rows)])
        .split(inner);

    let header = Row::new(["HOST", "VERDICT", "PROVIDER", "EVIDENCE"])
        .style(Style::default().fg(theme.overlay0));

    let rows = t.findings.iter().enumerate().map(|(i, finding)| {
        let base = if focused && i == sel {
            Style::default().fg(theme.text).bg(theme.surface0)
        } else {
            Style::default().fg(theme.text)
        };
        Row::new(vec![
            Span::styled(finding.host.clone(), base),
            Span::styled(
                verdict_label(finding.verdict).to_string(),
                base.fg(theme.tone(verdict_tone(finding.verdict))),
            ),
            Span::styled(finding.provider.clone().unwrap_or_else(|| "—".into()), base),
            // Evidence is the matched fingerprint on a confirmed finding; the
            // probe note explains why an unconfirmed one could not be settled.
            Span::styled(
                finding
                    .evidence
                    .clone()
                    .or_else(|| finding.probe_note.clone())
                    .unwrap_or_else(|| "—".into()),
                base.fg(theme.subtext),
            ),
        ])
        .style(base)
    });

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(32),
            Constraint::Length(11),
            Constraint::Percentage(20),
            Constraint::Percentage(38),
        ],
    )
    .header(header)
    .column_spacing(1);
    let mut state = scroll_to(focused.then_some(sel));
    f.render_stateful_widget(table, chunks[0], &mut state);

    if t.hosts_skipped > 0 {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                format!(
                    "{} host(s) exceeded the scan cap and were not examined",
                    t.hosts_skipped
                ),
                Style::default().fg(theme.yellow),
            ))),
            chunks[1],
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use seer_core::{TakeoverFinding, TakeoverReport};

    fn finding(host: &str, verdict: TakeoverVerdict) -> TakeoverFinding {
        TakeoverFinding {
            host: host.into(),
            verdict,
            provider: Some("GitHub Pages".into()),
            cname: Some("x.github.io".into()),
            addresses: vec![],
            evidence: (verdict == TakeoverVerdict::Vulnerable)
                .then(|| "There isn't a GitHub Pages site here.".to_string()),
            http_status: Some(404),
            probe_note: None,
        }
    }

    fn report(findings: Vec<TakeoverFinding>) -> TakeoverReport {
        let vulnerable = findings
            .iter()
            .filter(|f| f.verdict == TakeoverVerdict::Vulnerable)
            .count();
        let potential = findings
            .iter()
            .filter(|f| f.verdict == TakeoverVerdict::Potential)
            .count();
        TakeoverReport {
            domain: "example.com".into(),
            hosts_checked: 12,
            hosts_skipped: 0,
            vulnerable,
            potential,
            findings,
            notes: vec![],
        }
    }

    fn buf_text(data: &LensData, w: u16, h: u16, focused: bool, sel: usize) -> String {
        let theme = Theme::frappe();
        let backend = TestBackend::new(w, h);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, data, focused, sel))
            .unwrap();
        let buf = terminal.backend().buffer();
        let a = buf.area();
        let mut s = String::new();
        for y in 0..a.height {
            for x in 0..a.width {
                s.push_str(buf[(x, y)].symbol());
            }
            s.push('\n');
        }
        s
    }

    #[test]
    fn renders_vulnerable_row_with_evidence() {
        let data = LensData::Takeover(Box::new(report(vec![finding(
            "gone.example.com",
            TakeoverVerdict::Vulnerable,
        )])));
        let s = buf_text(&data, 110, 10, false, 0);
        assert!(s.contains("gone.example.com"), "got: {s}");
        assert!(s.contains("VULNERABLE"), "got: {s}");
        // The evidence is what makes the claim auditable — it must reach the UI.
        assert!(s.contains("GitHub Pages site here"), "got: {s}");
    }

    #[test]
    fn summary_counts_appear_in_the_title() {
        let data = LensData::Takeover(Box::new(report(vec![
            finding("a.example.com", TakeoverVerdict::Vulnerable),
            finding("b.example.com", TakeoverVerdict::Potential),
        ])));
        let s = buf_text(&data, 110, 10, false, 0);
        assert!(s.contains("12 checked"), "got: {s}");
        assert!(s.contains("1 vulnerable"), "got: {s}");
        assert!(s.contains("1 potential"), "got: {s}");
    }

    #[test]
    fn clean_scan_reports_hosts_checked_not_an_empty_table() {
        let data = LensData::Takeover(Box::new(report(vec![])));
        let s = buf_text(&data, 80, 8, false, 0);
        assert!(
            s.contains("no takeover signals across 12 host(s)"),
            "got: {s}"
        );
    }

    #[test]
    fn skipped_hosts_are_surfaced() {
        let mut r = report(vec![finding("a.example.com", TakeoverVerdict::Potential)]);
        r.hosts_skipped = 37;
        let s = buf_text(&LensData::Takeover(Box::new(r)), 100, 10, false, 0);
        assert!(s.contains("37 host(s) exceeded the scan cap"), "got: {s}");
    }

    #[test]
    fn selecting_past_viewport_scrolls_row_into_view() {
        let findings: Vec<TakeoverFinding> = (0..60)
            .map(|i| finding(&format!("h{i}.example.com"), TakeoverVerdict::Potential))
            .collect();
        let data = LensData::Takeover(Box::new(report(findings)));
        let s = buf_text(&data, 100, 10, true, 59);
        assert!(
            s.contains("h59.example.com"),
            "selecting the last row must scroll it into view: {s}"
        );
    }

    #[test]
    fn verdict_tones_and_labels() {
        assert_eq!(verdict_tone(TakeoverVerdict::Vulnerable), "fail");
        assert_eq!(verdict_tone(TakeoverVerdict::Potential), "warn");
        assert_eq!(verdict_tone(TakeoverVerdict::Safe), "ok");
        assert_eq!(verdict_label(TakeoverVerdict::Vulnerable), "VULNERABLE");
        assert_eq!(verdict_label(TakeoverVerdict::Potential), "potential");
    }

    #[test]
    fn wrong_payload_variant_renders_nothing() {
        let theme = Theme::frappe();
        let backend = TestBackend::new(40, 6);
        let mut terminal = Terminal::new(backend).unwrap();
        let data = LensData::History(vec![]);
        terminal
            .draw(|f| render(f, f.area(), &theme, &data, false, 0))
            .unwrap();
    }
}
