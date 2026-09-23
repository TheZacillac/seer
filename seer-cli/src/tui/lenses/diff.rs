//! Diff lens — always-visible A⇄B input bar + 3-column comparison (FIELD|A|B).
use std::fmt::Display;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Row, Table};
use ratatui::Frame;

use crate::tui::action::{LensData, LensState};
use crate::tui::line_editor::LineEditor;
use crate::tui::theme::Theme;
use crate::tui::widgets::{or_dash, panel};

/// Render the Diff lens. Pure function of its inputs (no `App` coupling):
/// - `domain`  domain A (the `:diff` override, else the session target)
/// - `b`       committed second domain (B)
/// - `editing` `Some(editor)` while the B field is being typed
/// - `focused` whether the pane has focus
/// - `state`   the lens load state (drives the body)
///
/// Once a comparison is loaded the input bar names the domains that result
/// is actually for (`domain_a`/`domain_b`), not whatever is configured now.
#[allow(clippy::too_many_arguments)]
pub fn render(
    f: &mut Frame,
    area: Rect,
    theme: &Theme,
    domain: Option<&str>,
    b: &str,
    editing: Option<&LineEditor>,
    focused: bool,
    state: &LensState,
) {
    let inner = panel::render(f, area, theme, "Diff", theme.yellow, focused);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // input bar
            Constraint::Length(1), // hint
            Constraint::Min(0),    // body
        ])
        .split(inner);

    // ── input bar: A · <domain>   ⇄   B · <value> ────────────────────────────
    let loaded = match state {
        LensState::Loaded(LensData::Diff(d)) => Some(d),
        _ => None,
    };
    let a = loaded
        .map(|d| d.domain_a.as_str())
        .or(domain)
        .unwrap_or("(no target)");
    let b = loaded.map(|d| d.domain_b.as_str()).unwrap_or(b);
    let (b_text, b_color) = match editing {
        Some(buf) => (buf.with_caret("▏"), theme.text),
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

/// Both sides of an optional diff field, with missing values dashed.
fn pair<T: Display>((a, b): &(Option<T>, Option<T>)) -> (String, String) {
    (or_dash(a.as_ref()), or_dash(b.as_ref()))
}

/// The FIELD | A | B comparison table for a completed diff.
fn comparison_table(f: &mut Frame, area: Rect, theme: &Theme, d: &seer_core::diff::DomainDiff) {
    let (reg, dns, ssl) = (&d.registration, &d.dns, &d.ssl);
    let joined = |(a, b): &(Vec<String>, Vec<String>)| (a.join(", "), b.join(", "));
    let raw = [
        ("registrar", pair(&reg.registrar)),
        ("organization", pair(&reg.organization)),
        ("created", pair(&reg.created)),
        ("expires", pair(&reg.expires)),
        ("A records", joined(&dns.a_records)),
        ("nameservers", joined(&dns.nameservers)),
        (
            "resolves",
            (dns.resolves.0.to_string(), dns.resolves.1.to_string()),
        ),
        ("ssl issuer", pair(&ssl.issuer)),
        ("ssl valid until", pair(&ssl.valid_until)),
        ("ssl days", pair(&ssl.days_remaining)),
        ("ssl ok", pair(&ssl.is_valid)),
    ];

    let rows: Vec<Row> = raw
        .iter()
        .map(|(field, (a_val, b_val))| {
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
    use crate::tui::test_util::render_text;
    use seer_core::diff::{DnsDiff, DomainDiff, RegistrationDiff, SslDiff};

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
        let text = render_text(90, 20, |f| {
            render(
                f,
                f.area(),
                &theme,
                Some("acme.io"),
                "",
                None,
                false,
                &LensState::Idle,
            );
        });
        assert!(text.contains("A ·"), "input bar shows A");
        assert!(text.contains("B ·"), "input bar shows B");
        assert!(text.contains("acme.io"), "shows current domain as A");
        assert!(text.contains("press e"), "prompts how to set B");
    }

    #[test]
    fn editing_shows_live_buffer() {
        let theme = Theme::frappe();
        let text = render_text(90, 20, |f| {
            render(
                f,
                f.area(),
                &theme,
                Some("acme.io"),
                "",
                Some(&LineEditor::from("typed.io")),
                true,
                &LensState::Idle,
            );
        });
        assert!(text.contains("typed.io"), "live edit buffer should render");
    }

    #[test]
    fn editing_caret_follows_the_cursor() {
        let theme = Theme::frappe();
        let mut editor = LineEditor::from("typed.io");
        editor.home();
        let text = render_text(90, 20, |f| {
            render(
                f,
                f.area(),
                &theme,
                Some("acme.io"),
                "",
                Some(&editor),
                true,
                &LensState::Idle,
            );
        });
        assert!(
            text.contains("B · ▏typed.io"),
            "caret must render at the cursor (Home), not the end"
        );
    }

    #[test]
    fn loaded_input_bar_names_the_results_domains() {
        // `:diff a.com b.com` while the session target is something else: the
        // bar must label the loaded data's domains, not the session domain.
        let theme = Theme::frappe();
        let state = LensState::Loaded(LensData::Diff(Box::new(diff_fixture())));
        let text = render_text(90, 20, |f| {
            render(
                f,
                f.area(),
                &theme,
                Some("session.com"),
                "other.com",
                None,
                false,
                &state,
            );
        });
        assert!(text.contains("A · a.com"), "got: {text}");
        assert!(text.contains("B · b.com"), "got: {text}");
        assert!(!text.contains("session.com"), "got: {text}");
    }

    #[test]
    fn loaded_shows_comparison_table() {
        let theme = Theme::frappe();
        let state = LensState::Loaded(LensData::Diff(Box::new(diff_fixture())));
        let text = render_text(90, 20, |f| {
            render(
                f,
                f.area(),
                &theme,
                Some("a.com"),
                "b.com",
                None,
                false,
                &state,
            );
        });
        assert!(text.contains("NameCheap"), "table renders registrar A");
        assert!(text.contains("GoDaddy"), "table renders registrar B");
    }
}
