//! Colored terminal output (`--format human`). One inherent `format_*` method
//! per report type, split into per-concern submodules; label/value rows go
//! through the private `Rows` writer, which passes every value through
//! [`sanitize_line`] against terminal escape injection and forged rows;
//! bespoke layouts call `sanitize_line` by hand. Colors can be disabled
//! (`without_colors`).

use chrono::{DateTime, Utc};
use colored::ColoredString;

use super::OutputFormatter;

// Shared with the per-concern submodules below (each does `use super::*`).
pub(super) use super::contact::{self, Contact, FlatContacts};
pub(super) use super::grouping::render_grouped;
pub(super) use super::{
    day_count, days_until, dnssec_depth, expiry_emphasis, expiry_phrase, format_duration,
    propagation_detail, propagation_difference, sanitize_line, Emphasis, DNSSEC_NOTE, GEO_NOTE,
};
pub(super) use crate::caa::{CaaPolicy, IssuerCaaMatch};
pub(super) use crate::colors::CatppuccinExt;
pub(super) use crate::dns::{DnsRecord, FollowIteration, FollowResult, PropagationResult};
pub(super) use crate::lookup::LookupResult;
pub(super) use crate::rdap::RdapResponse;
pub(super) use crate::status::StatusResponse;
pub(super) use crate::whois::WhoisResponse;
pub(super) use colored::Colorize;

mod delegation;
mod diff;
mod dig;
mod dns;
mod domain_info;
mod lookup;
mod propagation;
mod rdap;
mod security;
mod status;
mod whois;

pub struct HumanFormatter {
    use_colors: bool,
}

impl Default for HumanFormatter {
    fn default() -> Self {
        Self::new()
    }
}

impl HumanFormatter {
    pub fn new() -> Self {
        Self { use_colors: true }
    }

    pub fn without_colors(mut self) -> Self {
        self.use_colors = false;
        self
    }

    /// Applies `style` to `text`, or returns it plain when colors are off.
    fn paint(&self, text: &str, style: impl FnOnce(&str) -> ColoredString) -> String {
        if self.use_colors {
            style(text).to_string()
        } else {
            text.to_string()
        }
    }

    fn label(&self, text: &str) -> String {
        self.paint(text, |t| t.sky().bold())
    }

    fn value(&self, text: &str) -> String {
        self.paint(text, |t| t.ctp_white())
    }

    fn success(&self, text: &str) -> String {
        self.paint(text, |t| t.ctp_green().bold())
    }

    fn warning(&self, text: &str) -> String {
        self.paint(text, |t| t.ctp_yellow().bold())
    }

    fn error(&self, text: &str) -> String {
        self.paint(text, |t| t.ctp_red().bold())
    }

    fn dim(&self, text: &str) -> String {
        self.paint(text, |t| t.overlay1())
    }

    /// Styles `text` by an [`Emphasis`]: green, plain value, yellow, red.
    fn emphasize(&self, text: &str, emphasis: Emphasis) -> String {
        match emphasis {
            Emphasis::Good => self.success(text),
            Emphasis::Neutral => self.value(text),
            Emphasis::Caution => self.warning(text),
            Emphasis::Bad => self.error(text),
        }
    }

    /// A [`Rows`] writer appending `label: value` lines to `out` at `indent`.
    fn rows<'a>(&'a self, out: &'a mut Vec<String>, indent: &str) -> Rows<'a> {
        Rows {
            f: self,
            out,
            indent: indent.to_string(),
        }
    }

    fn header(&self, text: &str) -> String {
        // Underline width is the character count, not the byte length: a header
        // containing an IDN / non-ASCII domain would otherwise be over-ruled by
        // one or more extra dashes per multi-byte char. (Matches the diff
        // formatter's chars().count() convention.)
        let width = text.chars().count();
        if self.use_colors {
            format!(
                "\n{}\n{}",
                text.lavender().bold(),
                "─".repeat(width).subtext0()
            )
        } else {
            format!("\n{}\n{}", text, "-".repeat(width))
        }
    }

    /// Renders the CAA policy block (records, issuer match, note) shared
    /// between `format_status` and `format_ssl`. `indent` is the leading
    /// whitespace per line — typically `"  "`.
    fn render_caa_block(&self, caa: &CaaPolicy, indent: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut block = self.rows(&mut out, indent);
        let mut rows = block.section("CAA Policy");

        if !caa.has_policy {
            let line = format!(
                "{}{}",
                rows.indent,
                self.value("No CAA records (any CA may issue)")
            );
            rows.push(line);
        } else {
            rows.opt("Found at", &caa.effective_domain);
            for r in &caa.records {
                let line = format!(
                    "{}{} {} \"{}\"",
                    rows.indent,
                    self.value(&r.flags.to_string()),
                    self.label(&sanitize_line(&r.tag)),
                    sanitize_line(&r.value)
                );
                rows.push(line);
            }
        }

        if let Some(m) = caa.issuer_match {
            let rendered = match m {
                IssuerCaaMatch::NoPolicy => self.value("no policy — any CA permitted"),
                IssuerCaaMatch::Permitted => self.success("issuer permitted by current CAA policy"),
                IssuerCaaMatch::Mismatch => self
                    .warning("issuer not in current CAA policy (informational — see note below)"),
                IssuerCaaMatch::Indeterminate => {
                    self.warning("CAA present but no issue/issuewild tags")
                }
            };
            rows.kv("Issuer vs CAA", rendered);
        }

        // Note is appended separately by the caller so it can sit at the
        // very bottom of the overall output, un-indented.
        out
    }

    /// Appends the trailing CAA note as the very last lines of an output
    /// buffer: a blank separator line followed by `note: …` with no
    /// indentation, so the explanation reads as a footer to the whole
    /// report rather than part of the CAA block.
    fn push_caa_note_footer(&self, out: &mut Vec<String>, caa: &CaaPolicy) {
        out.push(String::new());
        out.push(format!("note: {}", caa.note));
    }

    /// `<date> (expires in N days)` / `<date> (expired N days ago)`, colored
    /// by urgency ([`expiry_emphasis`]).
    fn format_expiry_status(&self, date: DateTime<Utc>, days_until: i64) -> String {
        let text = format!(
            "{} ({})",
            date.format("%Y-%m-%d"),
            expiry_phrase(days_until)
        );
        self.emphasize(&text, expiry_emphasis(days_until))
    }

    /// The bare expiry phrase for `days_until`, colored by urgency.
    fn expiry_countdown(&self, days_until: i64) -> String {
        self.emphasize(&expiry_phrase(days_until), expiry_emphasis(days_until))
    }
}

/// Appends `label: value` rows at one indent. Remote text goes through
/// [`sanitize_line`] here, so no row can skip the terminal-injection guard or
/// break onto a forged line of its own.
struct Rows<'a> {
    f: &'a HumanFormatter,
    out: &'a mut Vec<String>,
    indent: String,
}

impl Rows<'_> {
    /// Appends a pre-built line as-is.
    fn push(&mut self, line: String) {
        self.out.push(line);
    }

    /// Appends pre-built lines as-is.
    fn extend(&mut self, lines: Vec<String>) {
        self.out.extend(lines);
    }

    /// Appends an empty separator line.
    fn blank(&mut self) {
        self.out.push(String::new());
    }

    /// `label: <styled>` for a value the caller already styled (and, if it is
    /// remote text, sanitized).
    fn kv(&mut self, label: &str, styled: String) {
        let label = self.f.label(label);
        self.out.push(format!("{}{label}: {styled}", self.indent));
    }

    /// `label: value` for remote text: sanitized, then value-styled.
    fn text(&mut self, label: &str, text: &str) {
        let value = self.f.value(&sanitize_line(text));
        self.kv(label, value);
    }

    /// [`Self::text`], skipped when the field is absent.
    fn opt(&mut self, label: &str, text: &Option<String>) {
        if let Some(text) = text {
            self.text(label, text);
        }
    }

    /// `label: YYYY-MM-DD`, skipped when absent.
    fn date(&mut self, label: &str, date: Option<DateTime<Utc>>) {
        if let Some(date) = date {
            let value = self.f.value(&date.format("%Y-%m-%d").to_string());
            self.kv(label, value);
        }
    }

    /// `Expires: <date> (expires in N days)`, colored by urgency (see
    /// [`HumanFormatter::format_expiry_status`]); skipped when absent.
    fn expires(&mut self, date: Option<DateTime<Utc>>) {
        if let Some(date) = date {
            let status = self.f.format_expiry_status(date, days_until(date));
            self.kv("Expires", status);
        }
    }

    /// `label:` then one `- item` row per entry, one level deeper; nothing
    /// for an empty list.
    fn list(&mut self, label: &str, items: &[String]) {
        if items.is_empty() {
            return;
        }
        let label = self.f.label(label);
        self.out.push(format!("{}{label}:", self.indent));
        for item in items {
            let item = self.f.value(&sanitize_line(item));
            self.out.push(format!("{}  - {item}", self.indent));
        }
    }

    /// A writer into the same output at another indent.
    fn at(&mut self, indent: &str) -> Rows<'_> {
        self.f.rows(self.out, indent)
    }

    /// A blank-line-led `label:` heading; returns the writer for its rows,
    /// one level deeper.
    fn section(&mut self, label: &str) -> Rows<'_> {
        let heading = self.f.label(label);
        self.out.push(format!("\n{}{heading}:", self.indent));
        let indent = format!("{}  ", self.indent);
        self.at(&indent)
    }

    /// One contact block: a `<role> Contact` section with a row per populated
    /// field. An empty contact renders nothing, never a bare heading.
    fn contact(&mut self, role: &str, contact: Contact<'_>) {
        if contact.is_empty() {
            return;
        }
        let mut rows = self.section(&format!("{role} Contact"));
        for (label, field) in contact.fields() {
            rows.opt(label, field);
        }
    }

    /// [`Self::contact`] for each of [`contact::ROLES`].
    fn contacts(&mut self, contacts: [Contact<'_>; 3]) {
        for (role, c) in contact::ROLES.into_iter().zip(contacts) {
            self.contact(role, c);
        }
    }
}

with_report_methods!(impl_forwarding!(HumanFormatter;));

#[cfg(test)]
mod tests {
    use super::*;

    fn formatter() -> HumanFormatter {
        HumanFormatter::new().without_colors()
    }

    fn date(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    #[test]
    fn expiry_status_says_expired_days_ago_never_a_negative_count() {
        let out = formatter().format_expiry_status(date("2024-01-01T00:00:00Z"), -3);
        assert_eq!(out, "2024-01-01 (expired 3 days ago)");
        let out = formatter().format_expiry_status(date("2024-01-01T00:00:00Z"), -1);
        assert_eq!(out, "2024-01-01 (expired 1 day ago)");
    }

    #[test]
    fn expiry_status_counts_down_in_every_urgency_band() {
        for days in [0, 15, 30, 60, 300] {
            let out = formatter().format_expiry_status(date("2027-01-01T00:00:00Z"), days);
            let expected = if days == 1 {
                "1 day".into()
            } else {
                format!("{days} days")
            };
            assert_eq!(out, format!("2027-01-01 (expires in {expected})"));
        }
    }

    #[test]
    fn expiry_status_is_colored_by_urgency() {
        colored::control::set_override(true);
        let f = HumanFormatter::new();
        let when = date("2027-01-01T00:00:00Z");
        let (red, yellow, green) = ("\x1b[1;91m", "\x1b[1;93m", "\x1b[1;92m");
        assert!(f.format_expiry_status(when, -3).starts_with(red));
        assert!(f.format_expiry_status(when, 29).starts_with(red));
        assert!(f.format_expiry_status(when, 30).starts_with(yellow));
        assert!(f.format_expiry_status(when, 90).starts_with(green));
        colored::control::unset_override();
    }

    #[test]
    fn rows_fold_remote_newlines_so_a_value_cannot_forge_a_row() {
        // A registrar carrying "\n  Expires: 2099..." used to print as a
        // second, legitimate-looking row under the real ones.
        let mut whois = WhoisResponse::parse("example.com", "whois.test", "Registrar: R\n");
        whois.registrar =
            Some("Evil Registrar\n  Expires: 2099-01-01 (expires in 9999 days)".into());
        whois.nameservers = vec!["ns1.example\n  Status: ok".into()];
        let out = formatter().format_whois(&whois);
        assert!(
            out.contains("  Registrar: Evil Registrar   Expires: 2099-01-01"),
            "got:\n{out}"
        );
        assert!(
            !out.lines()
                .any(|l| l.trim_start().starts_with("Expires: 2099")),
            "forged row:\n{out}"
        );
        assert!(
            !out.lines()
                .any(|l| l.trim_start().starts_with("Status: ok")),
            "forged list row:\n{out}"
        );
    }

    #[test]
    fn domain_info_renders_registrar_detail_and_lifecycle_fields() {
        // The PR #101 registrar-detail + derived-lifecycle fields were
        // computed and serialized but never rendered by the human formatter,
        // so `seer info` (default format) silently hid a documented feature
        // (2026-07-11 review).
        let whois = WhoisResponse::parse(
            "example.com",
            "whois.test",
            "Registrar: Example Registrar\n\
             Creation Date: 2020-01-01T00:00:00Z\n\
             Registry Expiry Date: 2099-01-01T00:00:00Z\n\
             Domain Status: clientTransferProhibited\n",
        );
        let mut info =
            crate::domain_info::DomainInfo::from_sources("example.com", None, Some(&whois));
        info.registrar_abuse_email = Some("abuse@registrar.test".to_string());
        info.registrar_abuse_phone = Some("+1.5555550100".to_string());
        info.registrar_iana_id = Some("9999".to_string());
        info.registrar_url = Some("https://registrar.test".to_string());

        assert!(info.days_until_expiration.is_some(), "lifecycle computed");
        assert!(!info.status_descriptions.is_empty(), "status decoded");

        let out = formatter().format_domain_info(&info);
        for needle in [
            "Registrar Detail",
            "abuse@registrar.test",
            "+1.5555550100",
            "9999",
            "https://registrar.test",
            "Days Until Expiry",
            "Domain Age",
            "Expiry Status",
            "clientTransferProhibited:",
        ] {
            assert!(out.contains(needle), "missing {needle:?} in:\n{out}");
        }
    }

    #[test]
    fn domain_info_sanitizes_nameserver_and_status_fields() {
        // Nameserver/status values come from attacker-controlled WHOIS parsing
        // and were printed without sanitize_line (unlike the adjacent DNSSEC
        // field), so an injected ANSI/OSC sequence reached the terminal.
        let whois = WhoisResponse::parse(
            "evil.example",
            "whois.test",
            "Name Server: ns1.evil\x1b[31mhidden\n\
             Domain Status: ok\x1b]0;pwn\x07\n\
             Registrar: Test Registrar\n\
             Creation Date: 2020-01-01T00:00:00Z\n",
        );
        let info = crate::domain_info::DomainInfo::from_sources("evil.example", None, Some(&whois));
        let out = formatter().format_domain_info(&info);
        assert!(
            !out.contains('\x1b'),
            "ESC must not reach terminal: {out:?}"
        );
        assert!(
            !out.contains('\x07'),
            "BEL must not reach terminal: {out:?}"
        );
    }
}
