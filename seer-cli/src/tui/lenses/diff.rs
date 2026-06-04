//! Diff lens — 3-column comparison table (FIELD | A | B).
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Row, Table};
use ratatui::Frame;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::panel;

pub fn render(f: &mut Frame, area: Rect, theme: &Theme, data: &LensData) {
    let LensData::Diff(d) = data else {
        return;
    };

    let title = format!("A · {}  ⇄  B · {}", d.domain_a, d.domain_b);
    let block = panel::block(theme, &title, theme.yellow, false);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let dash = "—".to_string();

    // Build comparison rows: (field, a_val, b_val)
    let mut raw: Vec<(&str, String, String)> = Vec::new();

    // Registration
    let (ra, rb) = &d.registration.registrar;
    raw.push((
        "registrar",
        ra.clone().unwrap_or_else(|| dash.clone()),
        rb.clone().unwrap_or_else(|| dash.clone()),
    ));
    let (oa, ob) = &d.registration.organization;
    raw.push((
        "organization",
        oa.clone().unwrap_or_else(|| dash.clone()),
        ob.clone().unwrap_or_else(|| dash.clone()),
    ));
    let (ca, cb) = &d.registration.created;
    raw.push((
        "created",
        ca.clone().unwrap_or_else(|| dash.clone()),
        cb.clone().unwrap_or_else(|| dash.clone()),
    ));
    let (ea, eb) = &d.registration.expires;
    raw.push((
        "expires",
        ea.clone().unwrap_or_else(|| dash.clone()),
        eb.clone().unwrap_or_else(|| dash.clone()),
    ));

    // DNS
    raw.push((
        "A records",
        d.dns.a_records.0.join(", "),
        d.dns.a_records.1.join(", "),
    ));
    raw.push((
        "nameservers",
        d.dns.nameservers.0.join(", "),
        d.dns.nameservers.1.join(", "),
    ));
    raw.push((
        "resolves",
        d.dns.resolves.0.to_string(),
        d.dns.resolves.1.to_string(),
    ));

    // SSL
    let (ia, ib) = &d.ssl.issuer;
    raw.push((
        "ssl issuer",
        ia.clone().unwrap_or_else(|| dash.clone()),
        ib.clone().unwrap_or_else(|| dash.clone()),
    ));
    let (vu_a, vu_b) = &d.ssl.valid_until;
    raw.push((
        "ssl valid until",
        vu_a.clone().unwrap_or_else(|| dash.clone()),
        vu_b.clone().unwrap_or_else(|| dash.clone()),
    ));
    let (dr_a, dr_b) = &d.ssl.days_remaining;
    raw.push((
        "ssl days",
        dr_a.map(|n| n.to_string()).unwrap_or_else(|| dash.clone()),
        dr_b.map(|n| n.to_string()).unwrap_or_else(|| dash.clone()),
    ));
    let (iv_a, iv_b) = &d.ssl.is_valid;
    raw.push((
        "ssl ok",
        iv_a.map(|b| b.to_string()).unwrap_or_else(|| dash.clone()),
        iv_b.map(|b| b.to_string()).unwrap_or_else(|| dash.clone()),
    ));

    // Layout: header line + table
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(inner);

    // Header
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                format!("{:<20}", "FIELD"),
                Style::default()
                    .fg(theme.overlay0)
                    .add_modifier(Modifier::DIM),
            ),
            Span::styled(
                format!("{:<30}", "A"),
                Style::default()
                    .fg(theme.overlay0)
                    .add_modifier(Modifier::DIM),
            ),
            Span::styled(
                format!("{:<30}", "B"),
                Style::default()
                    .fg(theme.overlay0)
                    .add_modifier(Modifier::DIM),
            ),
        ])),
        chunks[0],
    );

    // Build table rows
    let rows: Vec<Row> = raw
        .iter()
        .map(|(field, a_val, b_val)| {
            let same = a_val == b_val;
            let indicator = if same { "=" } else { "≠" };
            let value_color = if same { theme.text } else { theme.yellow };
            Row::new(vec![
                ratatui::text::Text::from(Line::from(Span::styled(
                    format!("{indicator} {field:<16}"),
                    Style::default().fg(if same { theme.overlay0 } else { theme.yellow }),
                ))),
                ratatui::text::Text::from(Line::from(Span::styled(
                    a_val.clone(),
                    Style::default().fg(value_color),
                ))),
                ratatui::text::Text::from(Line::from(Span::styled(
                    b_val.clone(),
                    Style::default().fg(value_color),
                ))),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(20),
            Constraint::Percentage(40),
            Constraint::Percentage(40),
        ],
    )
    .column_spacing(1);
    f.render_widget(table, chunks[1]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use seer_core::diff::{DnsDiff, DomainDiff, RegistrationDiff, SslDiff};

    fn buf_text(buf: &ratatui::buffer::Buffer) -> String {
        let a = buf.area();
        let mut s = String::new();
        for y in 0..a.height {
            for x in 0..a.width {
                s.push_str(buf[(x, y)].symbol());
            }
        }
        s
    }

    fn diff_fixture() -> DomainDiff {
        DomainDiff {
            domain_a: "a.com".into(),
            domain_b: "b.com".into(),
            registration: RegistrationDiff {
                registrar: (Some("NameCheap".into()), Some("GoDaddy".into())),
                organization: (None, None),
                created: (None, None),
                expires: (None, None),
            },
            dns: DnsDiff {
                a_records: (vec!["1.2.3.4".into()], vec!["5.6.7.8".into()]),
                nameservers: (vec![], vec![]),
                resolves: (true, true),
            },
            ssl: SslDiff {
                issuer: (None, None),
                valid_until: (None, None),
                days_remaining: (None, None),
                is_valid: (None, None),
            },
        }
    }

    #[test]
    fn renders_domain_names() {
        let theme = Theme::frappe();
        let data = LensData::Diff(Box::new(diff_fixture()));
        let backend = TestBackend::new(90, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &data))
            .unwrap();
        let text = buf_text(terminal.backend().buffer());
        assert!(text.contains("a.com"), "expected a.com in output");
        assert!(text.contains("b.com"), "expected b.com in output");
    }
}
