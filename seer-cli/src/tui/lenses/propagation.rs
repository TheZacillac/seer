//! Propagation lens — verdict gauge + consensus, then one row per resolver.
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table};
use ratatui::Frame;
use seer_core::dns::{
    PropagationResult, PropagationServerResult, PropagationVerdict, ServerVerdict,
};
use seer_core::output::{propagation_difference, sanitize_line};

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::{gauge, panel, row_style, scroll_to};

pub fn render(
    f: &mut Frame,
    area: Rect,
    theme: &Theme,
    data: &LensData,
    focused: bool,
    sel: usize,
) {
    let LensData::Prop(p) = data else { return };
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(0)])
        .split(area);

    let top_inner = panel::render(f, rows[0], theme, "Propagation", theme.teal, false);
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
    f.render_widget(
        Paragraph::new(vec![
            gauge::line(theme, ratio, 30, color, Some(&label)),
            consensus,
        ]),
        top_inner,
    );

    let inner = panel::render(f, rows[1], theme, "Resolvers", theme.teal, focused);
    let header = Row::new(["", "RESOLVER", "IP", "REGION", "TIME", "ANSWER"])
        .style(Style::default().fg(theme.overlay0));
    let body = p.results.iter().enumerate().map(|(i, sr)| {
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
        .style(row_style(theme, focused && i == sel))
    });
    let table = Table::new(
        body,
        [
            Constraint::Length(1),
            Constraint::Length(18),
            Constraint::Length(15),
            Constraint::Length(13),
            Constraint::Length(7),
            Constraint::Min(10),
        ],
    )
    .header(header)
    .column_spacing(1);
    let mut state = scroll_to(focused.then_some(sel));
    f.render_stateful_widget(table, inner, &mut state);
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
