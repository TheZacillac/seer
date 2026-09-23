use chrono::{DateTime, TimeDelta, Utc};
use colored::ColoredString;
use regex::Regex;
use std::sync::LazyLock;

use super::OutputFormatter;

// Shared with the per-concern submodules below (each does `use super::*`).
pub(super) use super::contact::{self, Contact, FlatContacts};
pub(super) use super::days_until;
pub(super) use super::grouping::render_grouped;
pub(super) use crate::caa::{CaaPolicy, IssuerCaaMatch};
pub(super) use crate::colors::CatppuccinExt;
pub(super) use crate::dns::{DnsRecord, FollowIteration, FollowResult, PropagationResult};
pub(super) use crate::lookup::LookupResult;
pub(super) use crate::rdap::{ContactInfo, RdapResponse};
pub(super) use crate::status::StatusResponse;
pub(super) use crate::whois::WhoisResponse;
pub(super) use colored::Colorize;

mod delegation;
mod diff;
mod dns;
mod domain_info;
mod lookup;
mod propagation;
mod rdap;
mod security;
mod status;
mod whois;

/// Strips ANSI escape sequences from untrusted external strings to prevent
/// terminal injection via malicious WHOIS/RDAP response data. The OSC branch
/// accepts both BEL (`\x07`) and ST (`\x1b\\`) terminators (and excludes ESC
/// from the payload run so it can't over-consume across sequences).
static ANSI_ESCAPE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[A-Z@-_]")
        .expect("Invalid ANSI escape regex")
});

/// Sanitizes untrusted external text (WHOIS/RDAP field values) for safe display
/// on a terminal. First removes well-formed ANSI escape sequences, then drops
/// any remaining C0/C1 control characters (bare CR, backspace, BEL, stray ESC,
/// the C1 range, DEL) that could overwrite or spoof rendered lines — keeping
/// only `\n` and `\t`, which are legitimate layout. Mirrors the markdown
/// `MdSafe` guard so the human path is no longer the weaker one (issue #53).
pub(super) fn sanitize_display(s: &str) -> String {
    ANSI_ESCAPE_RE
        .replace_all(s, "")
        .chars()
        .filter(|&c| c == '\n' || c == '\t' || !c.is_control())
        .collect()
}

/// Formats a [`TimeDelta`] as a compact human duration (`Ns` / `Nm Ns` /
/// `Nh Nm`). Shared across the human and markdown formatters — `pub(crate)` so
/// the markdown follow formatter can reuse it instead of duplicating the
/// breakdown.
pub(crate) fn format_duration(duration: TimeDelta) -> String {
    let total_secs = duration.num_seconds();
    if total_secs < 60 {
        format!("{}s", total_secs)
    } else if total_secs < 3600 {
        let mins = total_secs / 60;
        let secs = total_secs % 60;
        format!("{}m {}s", mins, secs)
    } else {
        let hours = total_secs / 3600;
        let mins = (total_secs % 3600) / 60;
        format!("{}h {}m", hours, mins)
    }
}

/// [`contact::rdap_views`] as this formatter renders them: the registrant
/// block drops name/organization, which print as the top-level
/// Registrant/Organization lines, so an identity-only registrant opens no
/// empty heading.
pub(super) fn detail_views(contacts: &[Option<ContactInfo>; 3]) -> [Contact<'_>; 3] {
    let [registrant, admin, tech] = contact::rdap_views(contacts);
    [registrant.without_identity(), admin, tech]
}

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
                    self.label(&r.tag),
                    sanitize_display(&r.value)
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

    /// Formats an expiration date with a human-readable status suffix.
    ///
    /// Behaviour:
    /// - already expired (negative days): red "expired N days ago"
    /// - <30 days remaining: red "expires in N days!"
    /// - <90 days remaining: yellow "expires in N days"
    /// - otherwise: green "expires in N days"
    fn format_expiry_status(&self, expiry_str: &str, days_until: i64) -> String {
        if days_until < 0 {
            self.error(&format!(
                "{} (expired {} days ago)",
                expiry_str, -days_until
            ))
        } else if days_until < 30 {
            self.error(&format!("{} (expires in {} days!)", expiry_str, days_until))
        } else if days_until < 90 {
            self.warning(&format!("{} (expires in {} days)", expiry_str, days_until))
        } else {
            self.success(&format!("{} (expires in {} days)", expiry_str, days_until))
        }
    }
}

/// Appends `label: value` rows at one indent. Remote text goes through
/// [`sanitize_display`] here, so no row can skip the terminal-injection guard.
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
        let value = self.f.value(&sanitize_display(text));
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
            let status = self
                .f
                .format_expiry_status(&date.format("%Y-%m-%d").to_string(), days_until(date));
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
            let item = self.f.value(&sanitize_display(item));
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

    #[test]
    fn expired_shows_days_ago() {
        let f = formatter();
        let out = f.format_expiry_status("2024-01-01", -3);
        assert!(out.contains("expired 3 days ago"), "got: {}", out);
        assert!(!out.contains("-3"), "got: {}", out);
    }

    #[test]
    fn expiring_soon_shows_expires_in() {
        let f = formatter();
        let out = f.format_expiry_status("2026-05-01", 15);
        assert!(out.contains("expires in 15 days"), "got: {}", out);
        assert!(!out.contains("days ago"), "got: {}", out);
    }

    #[test]
    fn warning_window_uses_expires_in() {
        let f = formatter();
        let out = f.format_expiry_status("2026-07-01", 60);
        assert!(out.contains("expires in 60 days"), "got: {}", out);
        assert!(!out.contains("!"), "got: {}", out);
    }

    #[test]
    fn healthy_expiry_uses_expires_in() {
        let f = formatter();
        let out = f.format_expiry_status("2027-01-01", 300);
        assert!(out.contains("expires in 300 days"), "got: {}", out);
        assert!(!out.contains("!"), "got: {}", out);
    }

    #[test]
    fn expired_one_day_is_pluralized_simply() {
        // We don't singularize; verify the raw format.
        let f = formatter();
        let out = f.format_expiry_status("2024-01-01", -1);
        assert!(out.contains("expired 1 days ago"), "got: {}", out);
    }

    #[test]
    fn boundary_30_days_is_warning_not_error() {
        let f = formatter();
        // 30 days -> not <30, so warning branch, no "!"
        let out = f.format_expiry_status("2026-05-15", 30);
        assert!(out.contains("expires in 30 days"), "got: {}", out);
        assert!(!out.contains("!"), "got: {}", out);
    }

    // --- #53: terminal-escape / control-char sanitization ---------------

    #[test]
    fn sanitize_display_strips_bare_control_chars_keeps_newline_tab() {
        // The old regex only removed ESC-introduced sequences; bare C0/C1
        // control chars (CR, backspace, BEL, C1 CSI 0x9B) survived and could
        // overwrite or spoof rendered lines. They must be stripped; newline
        // and tab are legitimate layout and must be preserved.
        let evil = "a\rb\x08c\x07d\u{009b}e";
        let clean = sanitize_display(evil);
        for bad in ['\r', '\x08', '\x07', '\u{009b}', '\u{001b}'] {
            assert!(
                !clean.contains(bad),
                "{bad:?} must be stripped from {clean:?}"
            );
        }
        assert!(
            clean.contains('a') && clean.contains('e'),
            "text kept: {clean:?}"
        );
        assert_eq!(
            sanitize_display("line1\nline2\tcol"),
            "line1\nline2\tcol",
            "newline and tab must be preserved"
        );
    }

    #[test]
    fn sanitize_display_strips_osc_with_st_terminator() {
        // OSC terminated by ST (ESC \\) rather than BEL previously slipped
        // through, leaking the payload as visible text.
        let clean = sanitize_display("\x1b]0;malicious title\x1b\\visible");
        assert_eq!(
            clean, "visible",
            "OSC+ST sequence must be fully removed: {clean:?}"
        );
        assert!(!clean.contains('\x1b'));
        // Regression: classic CSI color codes still stripped.
        assert_eq!(sanitize_display("\x1b[31mred\x1b[0m"), "red");
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
        // and were printed without sanitize_display (unlike the adjacent DNSSEC
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
