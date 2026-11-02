//! Diff lens — always-visible A⇄B bar + 3-column comparison (FIELD|A|B).
//! Domain B is the lens's option (`options::DIFF`), edited in the Options box.
use std::fmt::Display;

use ratatui::layout::Constraint;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Row;
use seer_core::output::sanitize_line;

use crate::tui::action::{LensData, LensState};
use crate::tui::theme::Theme;
use crate::tui::widgets::or_dash;
use crate::tui::widgets::page::{Block, Page, TableBlock};

/// The Diff lens. Pure function of its inputs (no `App` coupling):
/// - `domain`  domain A (the `:diff` override, else the session target)
/// - `b`       the second domain (B), from the Options box
/// - `state`   the lens load state (drives the body)
///
/// Once a comparison is loaded the input bar names the domains that result
/// is actually for (`domain_a`/`domain_b`), not whatever is configured now.
pub fn page(theme: &Theme, domain: Option<&str>, b: &str, state: &LensState) -> Page {
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
    let (b_text, b_color) = if b.is_empty() {
        ("set in Options (3)".to_string(), theme.overlay0)
    } else {
        (sanitize_line(b), theme.text)
    };
    let bar = Line::from(vec![
        Span::styled("A · ", Style::default().fg(theme.overlay0)),
        Span::styled(sanitize_line(a), Style::default().fg(theme.text)),
        Span::styled("   ⇄   ", Style::default().fg(theme.yellow)),
        Span::styled("B · ", Style::default().fg(theme.overlay0)),
        Span::styled(b_text, Style::default().fg(b_color)),
    ]);
    let page = Page::new("Diff", theme.yellow).push(Block::Lines(vec![bar]));

    // ── body by state ────────────────────────────────────────────────────────
    let line =
        |text: String, style: Style| Block::Lines(vec![Line::from(Span::styled(text, style))]);
    match state {
        LensState::Loaded(LensData::Diff(d)) => comparison(theme, page, d),
        LensState::Loading => page.push(line(
            format!("⠋ comparing {} ⇄ {}…", sanitize_line(a), sanitize_line(b)),
            Style::default().fg(theme.overlay),
        )),
        LensState::Error(msg) => page.push(Block::Note {
            text: msg.clone(),
            color: theme.red,
        }),
        _ => {
            let idle = if domain.is_some() {
                format!(
                    "set a second domain in Options (3) to compare against {}",
                    sanitize_line(a)
                )
            } else {
                "look up a domain first (1)".to_string()
            };
            page.push(line(
                idle,
                Style::default()
                    .fg(theme.overlay0)
                    .add_modifier(Modifier::ITALIC),
            ))
        }
    }
}

/// Both sides of an optional diff field, with missing values dashed.
fn pair<T: Display>((a, b): &(Option<T>, Option<T>)) -> (String, String) {
    (
        sanitize_line(&or_dash(a.as_ref())),
        sanitize_line(&or_dash(b.as_ref())),
    )
}

/// The FIELD | A | B comparison for a completed diff, then the checks that
/// failed: their rows read "—", which alone would look like a real absence.
fn comparison(theme: &Theme, page: Page, d: &seer_core::diff::DomainDiff) -> Page {
    let (reg, dns, ssl) = (&d.registration, &d.dns, &d.ssl);
    let joined = |(a, b): &(Vec<String>, Vec<String>)| {
        (sanitize_line(&a.join(", ")), sanitize_line(&b.join(", ")))
    };
    let raw = [
        ("registrar", pair(&reg.registrar)),
        ("organization", pair(&reg.organization)),
        ("created", pair(&reg.created)),
        ("expires", pair(&reg.expires)),
        ("A records", joined(&dns.a_records)),
        ("nameservers", joined(&dns.nameservers)),
        ("resolves", pair(&dns.resolves)),
        ("ssl issuer", pair(&ssl.issuer)),
        ("ssl valid until", pair(&ssl.valid_until)),
        ("ssl days", pair(&ssl.days_remaining)),
        ("ssl ok", pair(&ssl.is_valid)),
    ];
    let rows = raw
        .into_iter()
        .map(|(field, (a_val, b_val))| {
            let same = a_val == b_val;
            let indicator = if same { "=" } else { "≠" };
            let value_color = if same { theme.text } else { theme.yellow };
            Row::new(vec![
                Span::styled(
                    format!("{indicator} {field:<16}"),
                    Style::default().fg(if same { theme.overlay0 } else { theme.yellow }),
                ),
                Span::styled(a_val, Style::default().fg(value_color)),
                Span::styled(b_val, Style::default().fg(value_color)),
            ])
        })
        .collect();
    let table = TableBlock::new(
        vec![],
        vec![
            Constraint::Length(20),
            Constraint::Percentage(40),
            Constraint::Percentage(40),
        ],
        rows,
    );
    let errors: Vec<Line<'static>> = d
        .errors
        .iter()
        .map(|e| {
            Line::from(Span::styled(
                format!("! {}", sanitize_line(e)),
                Style::default().fg(theme.red),
            ))
        })
        .collect();
    page.push(Block::Table(table))
        .push_if(!errors.is_empty(), || Block::Lines(errors))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::widgets::page;

    /// Draw this lens's page as the TUI does.
    #[allow(clippy::too_many_arguments)]
    fn render(
        f: &mut ratatui::Frame,
        area: ratatui::layout::Rect,
        theme: &Theme,
        domain: Option<&str>,
        b: &str,
        focused: bool,
        state: &LensState,
    ) {
        page::draw(f, area, theme, page(theme, domain, b, state), focused);
    }
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
                resolves: (Some(true), Some(true)),
            },
            ssl: SslDiff {
                issuer: (None, None),
                valid_until: (None, None),
                days_remaining: (None, None),
                is_valid: (None, None),
            },
            errors: Vec::new(),
        }
    }

    /// A failed check's rows read "—"; the lens must say the check failed.
    #[test]
    fn failed_checks_are_listed() {
        let theme = Theme::frappe();
        let mut diff = diff_fixture();
        diff.errors = vec!["b.com: status check failed: HTTP request failed".into()];
        let state = LensState::Loaded(LensData::Diff(Box::new(diff)));
        let text = render_text(100, 24, |f| {
            render(f, f.area(), &theme, Some("a.com"), "b.com", false, &state);
        });
        assert!(
            text.contains("b.com: status check failed"),
            "errors are shown: {text}"
        );
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
                false,
                &LensState::Idle,
            );
        });
        assert!(text.contains("A ·"), "input bar shows A");
        assert!(text.contains("B ·"), "input bar shows B");
        assert!(text.contains("acme.io"), "shows current domain as A");
        assert!(text.contains("set in Options (3)"), "prompts how to set B");
        assert!(
            text.contains("set a second domain in Options (3) to compare against acme.io"),
            "idle text names A: {text}"
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
            render(f, f.area(), &theme, Some("a.com"), "b.com", false, &state);
        });
        assert!(text.contains("NameCheap"), "table renders registrar A");
        assert!(text.contains("GoDaddy"), "table renders registrar B");
    }
}
