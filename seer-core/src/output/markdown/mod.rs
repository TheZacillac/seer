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

mod diff;
mod dns;
mod domain_info;
mod lookup;
mod propagation;
mod rdap;
mod status;
mod whois;

/// `Display` adapter that renders attacker-controlled WHOIS/RDAP/DNS/SSL
/// strings safely inside Markdown that will be forwarded to an LLM (via
/// the MCP server). Strips ANSI escape sequences and ASCII control
/// characters, collapses newlines/CR/tabs to spaces (so attacker text
/// cannot break out of a table row or look like a new heading), and
/// neutralizes backticks (so an attacker can't terminate a code span and
/// inject Markdown structure).
pub(super) struct MdSafe<'a>(pub &'a str);

impl fmt::Display for MdSafe<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut iter = self.0.chars();
        while let Some(c) = iter.next() {
            match c {
                '\x1b' => {
                    // Consume the rest of the ANSI escape sequence (CSI or
                    // OSC). The byte right after ESC is the introducer
                    // (`[` for CSI, `]` for OSC, etc.) — skip it
                    // unconditionally so it isn't treated as a terminator.
                    // Then look for the terminator: CSI ends on a byte in
                    // `@`-`~`; OSC ends on BEL (0x07) or ST. Cap
                    // consumption defensively.
                    let _ = iter.next();
                    for inner in iter.by_ref().take(64) {
                        if matches!(inner as u32, 0x40..=0x7E) || inner == '\x07' {
                            break;
                        }
                    }
                }
                '\n' | '\r' | '\t' => f.write_str(" ")?,
                '`' => f.write_str("'")?,
                c if c.is_control() => {}
                c => f.write_char(c)?,
            }
        }
        Ok(())
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
    fn test_mdsafe_drops_other_control_chars() {
        // NUL and DEL must vanish entirely.
        assert_eq!(md("a\0b\x7fc"), "abc");
    }

    #[test]
    fn test_mdsafe_preserves_unicode() {
        assert_eq!(md("café — résumé"), "café — résumé");
    }
}
