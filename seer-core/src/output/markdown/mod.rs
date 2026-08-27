use std::fmt::{self, Write as _};

use super::OutputFormatter;

// Shared with the per-concern submodules below (each does `use super::*`).
pub(super) use super::grouping::render_grouped;
pub(super) use crate::caa::{CaaPolicy, IssuerCaaMatch};
pub(super) use crate::dns::{DnsRecord, FollowIteration, FollowResult, PropagationResult};
pub(super) use crate::lookup::LookupResult;
pub(super) use crate::rdap::RdapResponse;
pub(super) use crate::status::StatusResponse;
pub(super) use crate::whois::WhoisResponse;

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

/// `Display` adapter that renders attacker-controlled WHOIS/RDAP/DNS/SSL
/// strings safely inside Markdown that will be forwarded to an LLM (via
/// the MCP server). Strips ANSI escape sequences and ASCII control
/// characters, collapses newlines/CR/tabs to spaces (so attacker text
/// cannot break out of a table row or look like a new heading), neutralizes
/// backticks (so an attacker can't terminate a code span and inject Markdown
/// structure), and escapes the table-cell delimiter `|` (so a value can't add
/// columns or break out of a cell).
pub(super) struct MdSafe<'a>(pub &'a str);

impl fmt::Display for MdSafe<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut iter = self.0.chars().peekable();
        while let Some(c) = iter.next() {
            match c {
                '\x1b' => consume_escape(&mut iter),
                '\n' | '\r' | '\t' => f.write_str(" ")?,
                '`' => f.write_str("'")?,
                // GFM table-cell delimiter: a bare `|` from attacker-controlled
                // data would add columns / break out of the cell (and, with a
                // backtick, escape the code-span defense). Backslash-pipe is the
                // spec escape and renders as a literal `|` in and out of tables.
                '|' => f.write_str("\\|")?,
                c if c.is_control() => {}
                c => f.write_char(c)?,
            }
        }
        Ok(())
    }
}

/// Maximum chars consumed while scanning for an ANSI escape terminator. A
/// well-formed CSI/OSC/DCS sequence is far shorter; the cap stops a malformed
/// sequence from eating an unbounded run of legitimate text.
const ANSI_SCAN_CAP: usize = 64;

/// Consumes the remainder of an ANSI escape sequence after the leading ESC has
/// already been read, given a peekable char iterator positioned at the
/// introducer.
///
/// Critically, the introducer is only consumed when it is *actually* one — a
/// lone/truncated ESC (e.g. `ESC` then `X` or `|`) drops only the ESC and
/// leaves the following character for normal escaping, instead of swallowing
/// it. Scans also bail on a newline/CR so a terminator-less sequence can't eat
/// across a line.
fn consume_escape(iter: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    match iter.peek() {
        // CSI: `ESC [` … final byte in `@`-`~` (0x40-0x7E).
        Some('[') => {
            iter.next(); // consume '['
            for _ in 0..ANSI_SCAN_CAP {
                match iter.peek() {
                    // Bail before consuming a newline/CR — it's layout, not
                    // part of the (malformed, unterminated) sequence.
                    Some('\n') | Some('\r') | None => break,
                    Some(&ch) => {
                        iter.next();
                        if matches!(ch as u32, 0x40..=0x7E) {
                            break;
                        }
                    }
                }
            }
        }
        // String-type sequences: OSC (`ESC ]`) and DCS (`ESC P`). Both run
        // until BEL (0x07) or ST (`ESC \\`).
        Some(']') | Some('P') => {
            iter.next(); // consume introducer
            for _ in 0..ANSI_SCAN_CAP {
                match iter.peek() {
                    Some('\n') | Some('\r') | None => break,
                    Some('\x07') => {
                        iter.next();
                        break;
                    }
                    Some('\x1b') => {
                        // Possible ST: consume ESC, then `\\` if present.
                        iter.next();
                        if iter.peek() == Some(&'\\') {
                            iter.next();
                        }
                        break;
                    }
                    Some(_) => {
                        iter.next();
                    }
                }
            }
        }
        // Charset-designation escapes: `ESC ( <id>` / `ESC ) <id>` and the
        // 96-char variants `ESC * <id>` / `ESC + <id>`. Consume the introducer
        // plus exactly the one designator char (never a newline).
        Some('(') | Some(')') | Some('*') | Some('+') => {
            iter.next(); // consume introducer
            if !matches!(iter.peek(), Some('\n') | Some('\r') | None) {
                iter.next();
            }
        }
        // Not a recognized introducer (lone/truncated ESC). Drop only the ESC;
        // leave the next char to be escaped normally by the main loop.
        _ => {}
    }
}

/// Markdown output formatter that produces clean, readable Markdown.
pub struct MarkdownFormatter;

impl Default for MarkdownFormatter {
    fn default() -> Self {
        Self::new()
    }
}

impl MarkdownFormatter {
    pub fn new() -> Self {
        Self
    }

    /// Renders the CAA policy as a Markdown section shared between SSL and
    /// status reports.
    fn render_caa_section(&self, caa: &CaaPolicy) -> Vec<String> {
        let mut out = Vec::new();
        out.push(String::new());
        out.push("### CAA Policy".to_string());
        out.push(String::new());

        if !caa.has_policy {
            out.push("*No CAA records (any CA may issue)*".to_string());
        } else {
            if let Some(ref eff) = caa.effective_domain {
                out.push(format!("- **Found at**: `{}`", MdSafe(eff)));
            }
            out.push(String::new());
            out.push("| Flags | Tag | Value |".to_string());
            out.push("| --- | --- | --- |".to_string());
            for r in &caa.records {
                out.push(format!(
                    "| {} | `{}` | `{}` |",
                    r.flags,
                    MdSafe(&r.tag),
                    MdSafe(&r.value)
                ));
            }
        }

        if let Some(m) = caa.issuer_match {
            let rendered = match m {
                IssuerCaaMatch::NoPolicy => "no policy — any CA permitted",
                IssuerCaaMatch::Permitted => "issuer permitted by current CAA policy",
                IssuerCaaMatch::Mismatch => "issuer not in current CAA policy (informational)",
                IssuerCaaMatch::Indeterminate => "CAA present but no issue/issuewild tags",
            };
            out.push(String::new());
            out.push(format!("- **Issuer vs CAA**: {}", rendered));
        }

        out.push(String::new());
        out.push(format!("> **Note:** {}", caa.note));
        out
    }

    /// Formats a contact section for RDAP entities.
    fn format_rdap_contact(
        &self,
        output: &mut Vec<String>,
        label: &str,
        contact: &crate::rdap::ContactInfo,
    ) {
        if !contact.has_info() {
            return;
        }
        output.push(String::new());
        output.push(format!("### {}", label));
        output.push(String::new());
        if let Some(ref name) = contact.name {
            output.push(format!("- **Name**: {}", MdSafe(name)));
        }
        if let Some(ref org) = contact.organization {
            output.push(format!("- **Organization**: {}", MdSafe(org)));
        }
        if let Some(ref email) = contact.email {
            output.push(format!("- **Email**: `{}`", MdSafe(email)));
        }
        if let Some(ref phone) = contact.phone {
            output.push(format!("- **Phone**: {}", MdSafe(phone)));
        }
        if let Some(ref address) = contact.address {
            output.push(format!("- **Address**: {}", MdSafe(address)));
        }
        if let Some(ref country) = contact.country {
            output.push(format!("- **Country**: {}", MdSafe(country)));
        }
    }

    /// Formats WHOIS contact fields as a markdown subsection.
    fn format_whois_contact(
        &self,
        output: &mut Vec<String>,
        label: &str,
        name: &Option<String>,
        organization: &Option<String>,
        email: &Option<String>,
        phone: &Option<String>,
    ) {
        let has_info =
            name.is_some() || organization.is_some() || email.is_some() || phone.is_some();
        if !has_info {
            return;
        }
        output.push(String::new());
        output.push(format!("### {}", label));
        output.push(String::new());
        if let Some(ref v) = *name {
            output.push(format!("- **Name**: {}", MdSafe(v)));
        }
        if let Some(ref v) = *organization {
            output.push(format!("- **Organization**: {}", MdSafe(v)));
        }
        if let Some(ref v) = *email {
            output.push(format!("- **Email**: `{}`", MdSafe(v)));
        }
        if let Some(ref v) = *phone {
            output.push(format!("- **Phone**: {}", MdSafe(v)));
        }
    }
}

// Thin dispatch layer: each trait method forwards to the inherent
// method of the same name defined in the per-concern submodule. Rust
// resolves the inherent method first, so this does not recurse.
impl OutputFormatter for MarkdownFormatter {
    fn format_whois(&self, response: &WhoisResponse) -> String {
        self.format_whois(response)
    }
    fn format_rdap(&self, response: &RdapResponse) -> String {
        self.format_rdap(response)
    }
    fn format_dns(&self, records: &[DnsRecord]) -> String {
        self.format_dns(records)
    }
    fn format_propagation(&self, result: &PropagationResult) -> String {
        self.format_propagation(result)
    }
    fn format_lookup(&self, result: &LookupResult) -> String {
        self.format_lookup(result)
    }
    fn format_status(&self, response: &StatusResponse) -> String {
        self.format_status(response)
    }
    fn format_follow_iteration(&self, iteration: &FollowIteration) -> String {
        self.format_follow_iteration(iteration)
    }
    fn format_follow(&self, result: &FollowResult) -> String {
        self.format_follow(result)
    }
    fn format_availability(&self, result: &crate::availability::AvailabilityResult) -> String {
        self.format_availability(result)
    }
    fn format_tld(&self, info: &crate::tld::TldInfo) -> String {
        self.format_tld(info)
    }
    fn format_dnssec(&self, report: &crate::dns::DnssecReport) -> String {
        self.format_dnssec(report)
    }
    fn format_delegation(&self, report: &crate::dns::DelegationReport) -> String {
        self.format_delegation(report)
    }
    fn format_dns_comparison(&self, comparison: &crate::dns::DnsComparison) -> String {
        self.format_dns_comparison(comparison)
    }
    fn format_subdomains(&self, result: &crate::subdomains::SubdomainResult) -> String {
        self.format_subdomains(result)
    }
    fn format_diff(&self, diff: &crate::diff::DomainDiff) -> String {
        self.format_diff(diff)
    }
    fn format_ssl(&self, report: &crate::ssl::SslReport) -> String {
        self.format_ssl(report)
    }
    fn format_watch(&self, report: &crate::watchlist::WatchReport) -> String {
        self.format_watch(report)
    }
    fn format_domain_info(&self, info: &crate::domain_info::DomainInfo) -> String {
        self.format_domain_info(info)
    }
    fn format_drift(&self, report: &crate::drift::DriftReport) -> String {
        self.format_drift(report)
    }
    fn format_posture(&self, posture: &crate::posture::EmailPosture) -> String {
        self.format_posture(posture)
    }
    fn format_headers(&self, report: &crate::headers::HeaderReport) -> String {
        self.format_headers(report)
    }
    fn format_takeover(&self, report: &crate::takeover::TakeoverReport) -> String {
        self.format_takeover(report)
    }
    fn format_caa(&self, policy: &CaaPolicy) -> String {
        self.format_caa(policy)
    }
    fn format_confusables(&self, report: &crate::confusables::ConfusableReport) -> String {
        self.format_confusables(report)
    }
    fn format_subdomain_classification(
        &self,
        result: &crate::subdomains::SubdomainClassification,
    ) -> String {
        self.format_subdomain_classification(result)
    }
    fn format_subdomain_baseline_diff(
        &self,
        report: &crate::subdomains::SubdomainBaselineDiff,
    ) -> String {
        self.format_subdomain_baseline_diff(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- MdSafe sanitization tests -----------------------------------------

    fn md(s: &str) -> String {
        format!("{}", MdSafe(s))
    }

    #[test]
    fn test_mdsafe_strips_ansi_escape() {
        assert_eq!(md("\x1b[31mfoo\x1b[0m"), "foo");
    }

    #[test]
    fn test_mdsafe_collapses_newlines_cr_tab() {
        assert_eq!(md("a\nb"), "a b");
        assert_eq!(md("a\rb"), "a b");
        assert_eq!(md("a\tb"), "a b");
        // CRLF becomes two spaces (each replaced individually); that's fine —
        // the goal is to prevent breaking the line, not perfect whitespace.
        assert_eq!(md("a\r\nb"), "a  b");
    }

    #[test]
    fn test_mdsafe_neutralizes_backticks() {
        assert_eq!(md("`bad`"), "'bad'");
        assert_eq!(md("a `b` c"), "a 'b' c");
    }

    #[test]
    fn test_mdsafe_escapes_table_pipe() {
        // A bare `|` from attacker-controlled data (DNS TXT, cert subject,
        // WHOIS contact) breaks out of a Markdown table cell / fabricates
        // columns. GFM's cell escape is backslash-pipe, a literal `|` both
        // inside and outside tables.
        assert_eq!(md("a|b"), "a\\|b");
        assert_eq!(md("x | y | z"), "x \\| y \\| z");
    }

    #[test]
    fn test_mdsafe_drops_other_control_chars() {
        // NUL and DEL must vanish entirely.
        assert_eq!(md("a\0b\x7fc"), "abc");
    }

    #[test]
    fn test_mdsafe_preserves_unicode() {
        assert_eq!(md("café — résumé"), "café — résumé");
    }

    #[test]
    fn test_mdsafe_lone_esc_does_not_swallow_following_text() {
        // A bare ESC not followed by a real ANSI introducer must drop only the
        // ESC, not the following characters. `X` is not a CSI/OSC introducer, so
        // "hello" must survive — and the `|` is still escaped for table safety.
        assert_eq!(md("\x1bXhello|world"), "Xhello\\|world");
    }

    #[test]
    fn test_mdsafe_truncated_escape_does_not_swallow_newline_or_text() {
        // ESC + introducer `[` with no terminator before a newline: the scan
        // must bail at the newline (re-emitting it as a space) rather than
        // consuming "Ignore" while hunting for a terminator that never comes.
        assert_eq!(md("\x1b[\nIgnore"), " Ignore");
    }

    #[test]
    fn test_mdsafe_still_strips_wellformed_ansi() {
        // Regression: a complete CSI color sequence is still fully removed.
        assert_eq!(md("\x1b[31mfoo\x1b[0m"), "foo");
        // OSC terminated by BEL is still removed.
        assert_eq!(md("\x1b]0;title\x07rest"), "rest");
    }

    #[test]
    fn test_mdsafe_esc_then_pipe_still_escapes_pipe() {
        // After dropping a lone ESC, a following structural `|` must still be
        // escaped — the ANSI handling must not bypass the table-cell defense.
        assert_eq!(md("\x1b|col"), "\\|col");
    }

    #[test]
    fn domain_info_renders_registrar_detail_and_lifecycle_fields() {
        // Mirror of the human-formatter regression: the PR #101
        // registrar-detail + derived-lifecycle fields must be visible in
        // `--format markdown`, not just JSON/YAML (2026-07-11 review).
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

        let out = MarkdownFormatter::new().format_domain_info(&info);
        for needle in [
            "Registrar Detail",
            "abuse@registrar.test",
            "+1.5555550100",
            "9999",
            "https://registrar.test",
            "Days Until Expiry",
            "Domain Age",
            "Expiry Status",
            "clientTransferProhibited",
        ] {
            assert!(out.contains(needle), "missing {needle:?} in:\n{out}");
        }
    }
}
