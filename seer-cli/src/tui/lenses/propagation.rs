//! Propagation lens — verdict gauge + consensus, then one row per resolver.
use ratatui::layout::Constraint;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Row};
use seer_core::dns::{
    PropagationResult, PropagationServerResult, PropagationVerdict, ServerVerdict,
};
use seer_core::output::{propagation_difference, sanitize_line};

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::gauge;
use crate::tui::widgets::page::{Block, Page, TableBlock};

pub fn page(theme: &Theme, data: &LensData, focused: bool, sel: usize) -> Option<Page> {
    let LensData::Prop(p) = data else {
        return None;
    };
    let verdict = p.verdict();
    let color = match verdict {
        PropagationVerdict::Full => theme.green,
        PropagationVerdict::Mostly | PropagationVerdict::Partial => theme.yellow,
        PropagationVerdict::Split | PropagationVerdict::NoAnswer => theme.red,
    };
    let silent = p.servers_checked - p.servers_responding;
    let mut label = format!(
        "{} · {}/{} agree",
        verdict.label(),
        p.servers_agreeing(),
        p.servers_responding
    );
    if silent > 0 {
        label.push_str(&format!(" · {silent} no answer"));
    }
    let ratio = if p.servers_responding > 0 {
        p.propagation_percentage / 100.0
    } else {
        0.0
    };
    let consensus = Line::from(vec![
        Span::styled("consensus ", Style::default().fg(theme.overlay0)),
        Span::styled(consensus_text(p), Style::default().fg(theme.green)),
    ]);

    let rows = p
        .results
        .iter()
        .map(|sr| {
            let verdict = p.server_verdict(sr);
            let (mark, color) = match verdict {
                ServerVerdict::Agrees => ("✓", theme.green),
                ServerVerdict::Differs(_) => ("≠", theme.yellow),
                ServerVerdict::NoAnswer(_) => ("✗", theme.red),
            };
            let time = match verdict {
                ServerVerdict::NoAnswer(_) => "—".to_string(),
                _ => format!("{}ms", sr.response_time_ms),
            };
            let answer_color = match verdict {
                ServerVerdict::Agrees => theme.overlay0,
                _ => color,
            };
            Row::new(vec![
                Cell::from(mark).style(Style::default().fg(color)),
                Cell::from(sanitize_line(&sr.server.name)),
                Cell::from(sr.server.ip.clone()).style(Style::default().fg(theme.subtext)),
                Cell::from(sr.server.location.clone()).style(Style::default().fg(theme.subtext)),
                Cell::from(time),
                Cell::from(answer_text(p, sr)).style(Style::default().fg(answer_color)),
            ])
        })
        .collect();
    let table = TableBlock::new(
        vec!["", "RESOLVER", "IP", "REGION", "TIME", "ANSWER"],
        vec![
            Constraint::Length(1),
            Constraint::Length(18),
            Constraint::Length(15),
            Constraint::Length(13),
            Constraint::Length(7),
            Constraint::Min(10),
        ],
        rows,
    )
    .selected(focused.then_some(sel));
    Some(
        Page::new("Propagation", theme.teal)
            .push(Block::Lines(vec![
                gauge::line(theme, ratio, 30, color, Some(&label)),
                consensus,
            ]))
            .push(Block::Gap)
            .push(Block::Table(table)),
    )
}

/// The consensus on one line: its values, or the empty answer's label.
fn consensus_text(p: &PropagationResult) -> String {
    if p.servers_responding == 0 {
        return "—".to_string();
    }
    if let Some(label) = p.empty_consensus_label() {
        return format!("no records ({label})");
    }
    let values: Vec<&str> = p
        .consensus_values
        .iter()
        .map(|v| v.value.as_str())
        .collect();
    sanitize_line(&values.join(", "))
}

/// A resolver row's ANSWER cell: `matches`, what it answered instead, or why
/// it did not. Also the text the lens filter matches.
pub(crate) fn answer_text(p: &PropagationResult, sr: &PropagationServerResult) -> String {
    match p.server_verdict(sr) {
        ServerVerdict::Agrees => "matches".to_string(),
        ServerVerdict::Differs(inc) => {
            sanitize_line(&propagation_difference(inc, sr.empty_answer_label()))
        }
        ServerVerdict::NoAnswer(reason) => sanitize_line(reason),
    }
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

    /// Three servers: one agrees, one differs, one timed out — the fixture
    /// deserializes the JSON shape the core emits.
    fn fixture() -> PropagationResult {
        let a = |ip: &str| {
            serde_json::to_value(seer_core::dns::DnsRecord {
                name: "example.com".into(),
                record_type: seer_core::dns::RecordType::A,
                ttl: 300,
                data: seer_core::dns::RecordData::A { address: ip.into() },
            })
            .unwrap()
        };
        serde_json::from_value(serde_json::json!({
            "domain": "example.com", "record_type": "A",
            "servers_checked": 3, "servers_responding": 2, "propagation_percentage": 50.0,
            "results": [
                {"server": {"name": "Google", "ip": "8.8.8.8", "location": "North America",
                            "provider": "Google"},
                 "records": [a("192.0.2.1")], "response_time_ms": 12, "success": true,
                 "error": null, "status": "NOERROR"},
                {"server": {"name": "Yandex", "ip": "77.88.8.8", "location": "Europe",
                            "provider": "Yandex"},
                 "records": [a("192.0.2.9")], "response_time_ms": 30, "success": true,
                 "error": null, "status": "NOERROR"},
                {"server": {"name": "Slow DNS", "ip": "192.0.2.53", "location": "Europe",
                            "provider": "Slow"},
                 "records": [], "response_time_ms": 5000, "success": false,
                 "error": "timed out"}
            ],
            "consensus_values": [{"type": "A", "value": "192.0.2.1"}],
            "inconsistencies": [{"type": "A", "server_name": "Yandex", "server_ip": "77.88.8.8",
                                 "values": ["192.0.2.9"], "consensus": ["192.0.2.1"]}],
            "unreachable_servers": [{"name": "Slow DNS", "ip": "192.0.2.53",
                                     "error": "timed out"}],
            "dnssec_validated": false
        }))
        .expect("fixture deserializes")
    }

    #[test]
    fn shows_verdict_consensus_and_why_each_row_differs() {
        let theme = Theme::frappe();
        let data = LensData::Prop(Box::new(fixture()));
        let text = render_lines(100, 12, |f| render(f, f.area(), &theme, &data, false, 0));
        assert!(
            text.contains("Partially propagated · 1/2 agree · 1 no answer"),
            "{text}"
        );
        assert!(text.contains("consensus 192.0.2.1"), "{text}");
        let row = |name: &str| {
            text.lines()
                .find(|l| l.contains(name))
                .unwrap_or_else(|| panic!("no {name} row in\n{text}"))
                .to_string()
        };
        assert!(row("Google").contains('✓') && row("Google").contains("matches"));
        assert!(row("Yandex").contains('≠') && row("Yandex").contains("192.0.2.9"));
        let slow = row("Slow DNS");
        assert!(slow.contains('✗') && slow.contains("timed out") && slow.contains('—'));
        // The region column fits the longest region name.
        assert!(row("Google").contains("North America"), "{text}");
    }
}
