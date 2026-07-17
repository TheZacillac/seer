//! Overview lens — merged registration summary from the smart lookup.
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use seer_core::LookupResult;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::{kv, panel};

pub fn render(f: &mut Frame, area: Rect, theme: &Theme, data: &LensData) {
    let LensData::Overview(result) = data else {
        return;
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(0)])
        .split(area);

    // Mirror the core human formatter: `Available` is a fallback variant
    // carrying a graded verdict, not proof of availability — a dns_present
    // result is a REGISTERED domain (the issue-#45 inversion bug class).
    let source = match result.as_ref() {
        LookupResult::Rdap { .. } => ("RDAP", theme.mauve),
        LookupResult::Whois { .. } => ("WHOIS", theme.peach),
        LookupResult::Available { data, .. } => match data.verdict() {
            "available" => ("AVAILABLE", theme.green),
            "likely_available" => ("MAY BE AVAILABLE", theme.yellow),
            "registered" => ("REGISTERED", theme.text),
            "likely_registered" => ("LIKELY REGISTERED", theme.yellow),
            _ => ("UNKNOWN", theme.red),
        },
    };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                result.domain_name().unwrap_or_default(),
                Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(
                source.0,
                Style::default().fg(source.1).add_modifier(Modifier::BOLD),
            ),
        ])),
        chunks[0],
    );

    let block = panel::block(theme, "Registration", theme.blue, false);
    let inner = block.inner(chunks[1]);
    f.render_widget(block, chunks[1]);

    let dash = || "—".to_string();
    let (expiry, registrar) = result.expiration_info();
    // The header chip shows the verdict for Available results; the source row
    // names where that verdict came from instead of repeating it.
    let source_row = match result.as_ref() {
        LookupResult::Available { .. } => "availability check".to_string(),
        _ => source.0.to_string(),
    };
    let mut rows: Vec<(String, String)> = vec![
        ("registrar".into(), registrar.unwrap_or_else(dash)),
        (
            "organization".into(),
            result.organization().unwrap_or_else(dash),
        ),
        (
            "expires".into(),
            expiry
                .map(|d| d.date_naive().to_string())
                .unwrap_or_else(dash),
        ),
        ("source".into(), source_row),
    ];
    if let LookupResult::Available { data, .. } = result.as_ref() {
        rows.push(("method".into(), data.method.clone()));
        rows.push(("confidence".into(), data.confidence.clone()));
    }
    kv::render(f, inner, theme, theme.blue, &rows);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use seer_core::AvailabilityResult;

    fn avail_data(available: bool, confidence: &str, method: &str) -> LensData {
        LensData::Overview(Box::new(LookupResult::Available {
            data: Box::new(AvailabilityResult {
                domain: "example.com".into(),
                available,
                confidence: confidence.into(),
                method: method.into(),
                details: None,
            }),
            rdap_error: "connect timeout".into(),
            whois_error: "connect timeout".into(),
            whois_data: None,
        }))
    }

    fn render_to_text(data: &LensData) -> String {
        let theme = Theme::frappe();
        let backend = TestBackend::new(70, 14);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, data))
            .unwrap();
        let a = terminal.backend().buffer().area();
        let mut s = String::new();
        for y in 0..a.height {
            for x in 0..a.width {
                s.push_str(terminal.backend().buffer()[(x, y)].symbol());
            }
            s.push('\n');
        }
        s
    }

    #[test]
    fn dns_present_registered_renders_registered_not_available() {
        // PR #118: both transports failed but DNS proved registration —
        // (available: false, confidence: high) must never read as AVAILABLE.
        let text = render_to_text(&avail_data(false, "high", "dns_present"));
        assert!(text.contains("REGISTERED"), "got: {text}");
        assert!(
            !text.contains("AVAILABLE"),
            "registered domain must not render as AVAILABLE: {text}",
        );
    }

    #[test]
    fn confirmed_available_verdict_renders_available() {
        let text = render_to_text(&avail_data(true, "high", "rdap_404"));
        assert!(text.contains("AVAILABLE"), "got: {text}");
        assert!(!text.contains("MAY BE"), "got: {text}");
        assert!(!text.contains("REGISTERED"), "got: {text}");
    }

    #[test]
    fn inconclusive_verdict_renders_unknown() {
        let text = render_to_text(&avail_data(false, "low", "all_methods_failed"));
        assert!(text.contains("UNKNOWN"), "got: {text}");
        assert!(!text.contains("AVAILABLE"), "got: {text}");
    }
}
