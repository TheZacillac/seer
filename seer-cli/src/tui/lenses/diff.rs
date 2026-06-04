//! Diff lens — always-visible A⇄B input bar + 3-column comparison (FIELD|A|B).
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Row, Table};
use ratatui::Frame;

use crate::tui::action::{LensData, LensState};
use crate::tui::theme::Theme;
use crate::tui::widgets::panel;

/// Render the Diff lens. Pure function of its inputs (no `App` coupling):
/// - `domain`  current target = domain A
/// - `b`       committed second domain (B)
/// - `editing` `Some(buf)` while the B field is being typed
/// - `focused` whether the pane has focus
/// - `state`   the lens load state (drives the body)
#[allow(clippy::too_many_arguments)]
pub fn render(
    f: &mut Frame,
    area: Rect,
    theme: &Theme,
    domain: Option<&str>,
    b: &str,
    editing: Option<&str>,
    focused: bool,
    state: &LensState,
) {
    let block = panel::block(theme, "Diff", theme.yellow, focused);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // input bar
            Constraint::Length(1), // hint
            Constraint::Min(0),    // body
        ])
        .split(inner);

    // ── input bar: A · <domain>   ⇄   B · <value> ────────────────────────────
    let a = domain.unwrap_or("(no target)");
    let (b_text, b_color) = match editing {
        Some(buf) => (format!("{buf}▏"), theme.text),
        None if !b.is_empty() => (b.to_string(), theme.text),
        None => ("[ press e ]".to_string(), theme.overlay0),
    };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("A · ", Style::default().fg(theme.overlay0)),
            Span::styled(a.to_string(), Style::default().fg(theme.text)),
            Span::styled("   ⇄   ", Style::default().fg(theme.yellow)),
            Span::styled("B · ", Style::default().fg(theme.overlay0)),
            Span::styled(b_text, Style::default().fg(b_color)),
        ])),
        chunks[0],
    );

    // ── hint (focus-aware) ───────────────────────────────────────────────────
    let hint = if focused {
        "e edit B · ↵ compare"
    } else {
        "↵ focus pane"
    };
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            hint,
            Style::default().fg(theme.overlay0),
        ))),
        chunks[1],
    );

    // ── body by state ────────────────────────────────────────────────────────
    match state {
        LensState::Loaded(LensData::Diff(d)) => comparison_table(f, chunks[2], theme, d),
        LensState::Loading => {
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    format!("⠋ comparing {a} ⇄ {b}…"),
                    Style::default().fg(theme.overlay),
                ))),
                chunks[2],
            );
        }
        LensState::Error(msg) => {
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    msg.clone(),
                    Style::default().fg(theme.red),
                ))),
                chunks[2],
            );
        }
        _ => {
            let idle = if domain.is_some() {
                format!("set a second domain (e) to compare against {a}")
            } else {
                "look up a domain first (/)".to_string()
            };
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    idle,
                    Style::default()
                        .fg(theme.overlay0)
                        .add_modifier(Modifier::ITALIC),
                ))),
                chunks[2],
            );
        }
    }
}

/// The FIELD | A | B comparison table for a completed diff.
fn comparison_table(f: &mut Frame, area: Rect, theme: &Theme, d: &seer_core::diff::DomainDiff) {
    let dash = "—".to_string();
    let mut raw: Vec<(&str, String, String)> = Vec::new();

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
    f.render_widget(table, area);
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
    fn idle_shows_input_bar_with_domain_a() {
        let theme = Theme::frappe();
        let backend = TestBackend::new(90, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| {
                render(
                    f,
                    f.area(),
                    &theme,
                    Some("acme.io"),
                    "",
                    None,
                    false,
                    &LensState::Idle,
                )
            })
            .unwrap();
        let text = buf_text(terminal.backend().buffer());
        assert!(text.contains("A ·"), "input bar shows A");
        assert!(text.contains("B ·"), "input bar shows B");
        assert!(text.contains("acme.io"), "shows current domain as A");
        assert!(text.contains("press e"), "prompts how to set B");
    }

    #[test]
    fn editing_shows_live_buffer() {
        let theme = Theme::frappe();
        let backend = TestBackend::new(90, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| {
                render(
                    f,
                    f.area(),
                    &theme,
                    Some("acme.io"),
                    "",
                    Some("typed.io"),
                    true,
                    &LensState::Idle,
                )
            })
            .unwrap();
        assert!(
            buf_text(terminal.backend().buffer()).contains("typed.io"),
            "live edit buffer should render"
        );
    }

    #[test]
    fn loaded_shows_comparison_table() {
        let theme = Theme::frappe();
        let state = LensState::Loaded(LensData::Diff(Box::new(diff_fixture())));
        let backend = TestBackend::new(90, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, Some("a.com"), "b.com", None, false, &state))
            .unwrap();
        let text = buf_text(terminal.backend().buffer());
        assert!(text.contains("NameCheap"), "table renders registrar A");
        assert!(text.contains("GoDaddy"), "table renders registrar B");
    }
}
