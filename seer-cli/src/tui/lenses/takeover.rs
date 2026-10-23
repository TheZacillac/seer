//! Takeover lens — selectable table of takeover findings.
//!
//! Only actionable hosts are listed: `scan_takeover` filters `Safe` out of
//! `findings` before returning, so the table is the findings vec and the
//! summary line carries how many hosts were actually checked. A clean scan
//! shows the count and says so rather than rendering an empty grid. While
//! focused, the selected finding's CNAME, addresses and probe result show
//! beneath the table.
use ratatui::layout::Constraint;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Row;
use seer_core::output::{sanitize_line, takeover_label};
use seer_core::{TakeoverFinding, TakeoverVerdict};

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::inspector::Field;
use crate::tui::widgets::or_dash;
use crate::tui::widgets::page::{Block, Detail, Page, TableBlock};

fn verdict_tone(v: TakeoverVerdict) -> &'static str {
    match v {
        TakeoverVerdict::Vulnerable => "fail",
        TakeoverVerdict::Potential => "warn",
        TakeoverVerdict::Inconclusive => "info",
        TakeoverVerdict::Safe => "ok",
    }
}

/// The selected finding's detail: the CNAME and addresses behind the
/// verdict, and what the HTTP probe saw.
fn finding_fields(finding: &TakeoverFinding) -> Vec<Field> {
    vec![
        Field::new("host", finding.host.clone()),
        Field::new("verdict", takeover_label(finding.verdict)).tone(verdict_tone(finding.verdict)),
        Field::new("provider", or_dash(finding.provider.as_deref())),
        Field::new("cname", or_dash(finding.cname.as_deref())),
        Field::new("addresses", finding.addresses.join(" ")),
        Field::new("http", or_dash(finding.http_status)),
        Field::new("evidence", or_dash(finding.evidence.as_deref())),
        Field::new("probe", or_dash(finding.probe_note.as_deref())),
    ]
}

pub fn page(theme: &Theme, data: &LensData, focused: bool, sel: usize) -> Option<Page> {
    let LensData::Takeover(t) = data else {
        return None;
    };

    // Border accent tracks the worst finding, so the panel itself signals
    // severity before any row is read.
    let accent = if t.vulnerable > 0 {
        theme.red
    } else if t.potential > 0 {
        theme.yellow
    } else {
        theme.green
    };
    let mut title = format!(
        "Takeover · {} checked · {} vulnerable · {} potential",
        t.hosts_checked, t.vulnerable, t.potential
    );
    if t.inconclusive > 0 {
        title.push_str(&format!(" · {} inconclusive", t.inconclusive));
    }
    let page = Page::new(title, accent);

    if t.findings.is_empty() {
        let msg = if t.hosts_checked == 0 {
            "no hosts to scan".to_string()
        } else {
            format!("no takeover signals across {} host(s)", t.hosts_checked)
        };
        return Some(page.push(Block::Lines(vec![Line::from(Span::styled(
            msg,
            Style::default()
                .fg(theme.green)
                .add_modifier(Modifier::ITALIC),
        ))])));
    }

    let rows = t
        .findings
        .iter()
        .map(|finding| {
            Row::new(vec![
                Span::raw(sanitize_line(&finding.host)),
                Span::styled(
                    takeover_label(finding.verdict).to_string(),
                    Style::default().fg(theme.tone(verdict_tone(finding.verdict))),
                ),
                Span::raw(sanitize_line(&or_dash(finding.provider.as_deref()))),
                // Evidence is the matched fingerprint on a confirmed finding;
                // the probe note explains why an unconfirmed one could not be
                // settled.
                Span::styled(
                    sanitize_line(&or_dash(
                        finding.evidence.as_ref().or(finding.probe_note.as_ref()),
                    )),
                    Style::default().fg(theme.subtext),
                ),
            ])
        })
        .collect();
    let detail = focused
        .then(|| t.findings.get(sel))
        .flatten()
        .map_or(Detail::None, |finding| {
            Detail::Fields(finding_fields(finding))
        });
    let table = TableBlock::new(
        vec!["HOST", "VERDICT", "PROVIDER", "EVIDENCE"],
        vec![
            Constraint::Percentage(32),
            Constraint::Length(11),
            Constraint::Percentage(20),
            Constraint::Percentage(38),
        ],
        rows,
    )
    .selected(focused.then_some(sel))
    .detail(detail);
    // The skipped-hosts note is kept whole, so a truncated scan never
    // silently reads as a complete one.
    Some(
        page.push(Block::Table(table))
            .push_if(t.hosts_skipped > 0, || {
                Block::Lines(vec![Line::from(Span::styled(
                    format!(
                        "{} host(s) exceeded the scan cap and were not examined",
                        t.hosts_skipped
                    ),
                    Style::default().fg(theme.yellow),
                ))])
            }),
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
            inconclusive: findings
                .iter()
                .filter(|f| f.verdict == TakeoverVerdict::Inconclusive)
                .count(),
            findings,
            notes: vec![],
        }
    }

    fn render_to_text(data: &LensData, w: u16, h: u16, focused: bool, sel: usize) -> String {
        let theme = Theme::frappe();
        render_lines(w, h, |f| render(f, f.area(), &theme, data, focused, sel))
    }

    #[test]
    fn focused_finding_shows_cname_addresses_and_probe() {
        let mut f = finding("shop.example.com", TakeoverVerdict::Potential);
        f.cname = Some("shop-example.myshopify.com".into());
        f.addresses = vec!["23.227.38.65".into()];
        f.http_status = Some(404);
        f.probe_note = Some("fingerprint not matched".into());
        let data = LensData::Takeover(Box::new(report(vec![f])));
        let s = render_to_text(&data, 100, 20, true, 0);
        assert!(s.contains("shop-example.myshopify.com"), "{s}");
        assert!(s.contains("23.227.38.65") && s.contains("404"), "{s}");
        let nav = render_to_text(&data, 100, 20, false, 0);
        assert!(!nav.contains("23.227.38.65"), "{nav}");
    }

    #[test]
    fn renders_vulnerable_row_with_evidence() {
        let data = LensData::Takeover(Box::new(report(vec![finding(
            "gone.example.com",
            TakeoverVerdict::Vulnerable,
        )])));
        let s = render_to_text(&data, 110, 10, false, 0);
        assert!(s.contains("gone.example.com"), "got: {s}");
        assert!(s.contains("VULNERABLE"), "got: {s}");
        // The evidence is what makes the claim auditable — it must reach the UI.
        assert!(s.contains("GitHub Pages site here"), "got: {s}");
    }

    /// Evidence is a remote response body: it reached the terminal raw.
    #[test]
    fn remote_strings_are_sanitized() {
        let mut f = finding("gone\u{1b}[2J.example.com", TakeoverVerdict::Vulnerable);
        f.evidence = Some("no site\u{1b}]0;pwned\u{7}\nhere".into());
        f.provider = Some("Evil\u{9b}31m".into());
        let data = LensData::Takeover(Box::new(report(vec![f])));
        let s = render_to_text(&data, 120, 10, false, 0);
        assert!(!s.contains(['\u{1b}', '\u{7}', '\u{9b}']), "got: {s:?}");
        assert!(
            s.contains("gone.example.com") || s.contains("gone"),
            "got: {s}"
        );
    }

    #[test]
    fn summary_counts_appear_in_the_title() {
        let data = LensData::Takeover(Box::new(report(vec![
            finding("a.example.com", TakeoverVerdict::Vulnerable),
            finding("b.example.com", TakeoverVerdict::Potential),
        ])));
        let s = render_to_text(&data, 110, 10, false, 0);
        assert!(s.contains("12 checked"), "got: {s}");
        assert!(s.contains("1 vulnerable"), "got: {s}");
        assert!(s.contains("1 potential"), "got: {s}");
        assert!(
            !s.contains("inconclusive"),
            "no count when there are none: {s}"
        );

        let data = LensData::Takeover(Box::new(report(vec![finding(
            "c.example.com",
            TakeoverVerdict::Inconclusive,
        )])));
        let s = render_to_text(&data, 110, 10, false, 0);
        assert!(s.contains("1 inconclusive"), "got: {s}");
    }

    #[test]
    fn clean_scan_reports_hosts_checked_not_an_empty_table() {
        let data = LensData::Takeover(Box::new(report(vec![])));
        let s = render_to_text(&data, 80, 8, false, 0);
        assert!(
            s.contains("no takeover signals across 12 host(s)"),
            "got: {s}"
        );
    }

    #[test]
    fn skipped_hosts_are_surfaced() {
        let mut r = report(vec![finding("a.example.com", TakeoverVerdict::Potential)]);
        r.hosts_skipped = 37;
        let s = render_to_text(&LensData::Takeover(Box::new(r)), 100, 10, false, 0);
        assert!(s.contains("37 host(s) exceeded the scan cap"), "got: {s}");
    }

    #[test]
    fn selecting_past_viewport_scrolls_row_into_view() {
        let findings: Vec<TakeoverFinding> = (0..60)
            .map(|i| finding(&format!("h{i}.example.com"), TakeoverVerdict::Potential))
            .collect();
        let data = LensData::Takeover(Box::new(report(findings)));
        let s = render_to_text(&data, 100, 10, true, 59);
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
        assert_eq!(takeover_label(TakeoverVerdict::Vulnerable), "VULNERABLE");
        assert_eq!(takeover_label(TakeoverVerdict::Potential), "potential");
    }

    #[test]
    fn wrong_payload_variant_renders_nothing() {
        let theme = Theme::frappe();
        let data = LensData::History(vec![]);
        render_buffer(40, 6, |f| render(f, f.area(), &theme, &data, false, 0));
    }
}
