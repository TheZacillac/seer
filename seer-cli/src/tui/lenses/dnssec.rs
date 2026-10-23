//! DNSSEC lens — state header + KV summary + DS records table.
use ratatui::layout::Constraint;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Row;
use seer_core::output::sanitize_line;

use crate::tui::action::LensData;
use crate::tui::theme::Theme;
use crate::tui::widgets::page::{Block, Page, TableBlock};

pub fn page(theme: &Theme, data: &LensData) -> Option<Page> {
    let LensData::Dnssec(r) = data else {
        return None;
    };

    let status_color = if r.chain_valid || r.status == "signed" {
        theme.green
    } else if r.status == "partial" || r.status == "misconfigured" {
        theme.yellow
    } else {
        theme.red
    };
    let rows = vec![
        ("enabled", r.enabled.to_string()),
        ("status", r.status.clone()),
        ("chain valid", r.chain_valid.to_string()),
        ("DS records", r.ds_records.len().to_string()),
        ("DNSKEY records", r.dnskey_records.len().to_string()),
    ];
    let page = Page::new("DNSSEC", status_color)
        .push(Block::Lines(vec![Line::from(Span::styled(
            r.status.to_uppercase(),
            Style::default()
                .fg(status_color)
                .add_modifier(Modifier::BOLD),
        ))]))
        .push(Block::Kv {
            key_color: status_color,
            rows,
        })
        .push_if(!r.issues.is_empty(), || Block::Note {
            text: r.issues.join("  ·  "),
            color: theme.yellow,
        });
    if r.ds_records.is_empty() {
        return Some(page);
    }
    let ds_rows = r
        .ds_records
        .iter()
        .map(|ds| {
            let matched = if ds.matched_key { "✓" } else { "✗" };
            Row::new(vec![
                ds.key_tag.to_string(),
                sanitize_line(&ds.algorithm_name),
                sanitize_line(&ds.digest_type_name),
                matched.to_string(),
            ])
        })
        .collect();
    let table = TableBlock::new(
        vec!["KEY TAG", "ALGORITHM", "DIGEST TYPE", "MATCHED"],
        vec![
            Constraint::Length(10),
            Constraint::Percentage(35),
            Constraint::Percentage(35),
            Constraint::Length(8),
        ],
        ds_rows,
    );
    Some(page.push(Block::Gap).push(Block::Panel(
        Page::new("DS Records", theme.overlay0).push(Block::Table(table)),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::widgets::page;

    /// Draw this lens's page as the TUI does.
    fn render(f: &mut ratatui::Frame, area: ratatui::layout::Rect, theme: &Theme, data: &LensData) {
        if let Some(p) = page(theme, data) {
            page::draw(f, area, theme, p, false);
        }
    }
    use crate::tui::test_util::render_text;
    use seer_core::DnssecReport;

    #[test]
    fn renders_status_field() {
        let theme = Theme::frappe();
        let data = LensData::Dnssec(Box::new(DnssecReport {
            domain: "x".into(),
            enabled: true,
            has_ds_records: true,
            has_dnskey_records: true,
            ds_records: vec![],
            dnskey_records: vec![],
            issues: vec![],
            status: "signed".into(),
            chain_valid: true,
            authentication_tier: seer_core::AuthenticationTier::DigestOnly,
        }));
        let text = render_text(70, 14, |f| render(f, f.area(), &theme, &data));
        assert!(text.contains("signed"));
    }
}
