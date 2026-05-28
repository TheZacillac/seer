use chrono::TimeDelta;
use once_cell::sync::Lazy;
use regex::Regex;

use super::OutputFormatter;

// Shared with the per-concern submodules below (each does `use super::*`).
pub(super) use super::grouping::render_grouped;
pub(super) use crate::caa::{CaaPolicy, IssuerCaaMatch};
pub(super) use crate::colors::CatppuccinExt;
pub(super) use crate::dns::{DnsRecord, FollowIteration, FollowResult, PropagationResult};
pub(super) use crate::lookup::LookupResult;
pub(super) use crate::rdap::RdapResponse;
pub(super) use crate::status::StatusResponse;
pub(super) use crate::whois::WhoisResponse;
pub(super) use colored::Colorize;

mod diff;
mod dns;
mod domain_info;
mod lookup;
mod propagation;
mod rdap;
mod status;
mod whois;

/// Strips ANSI escape sequences from untrusted external strings to prevent
/// terminal injection via malicious WHOIS/RDAP response data.
static ANSI_ESCAPE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x07]*\x07|\x1b[A-Z@-_]")
        .expect("Invalid ANSI escape regex")
});

pub(super) fn sanitize_display(s: &str) -> String {
    ANSI_ESCAPE_RE.replace_all(s, "").to_string()
}

pub(super) fn format_duration(duration: TimeDelta) -> String {
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

    fn label(&self, text: &str) -> String {
        if self.use_colors {
            text.sky().bold().to_string()
        } else {
            text.to_string()
        }
    }

    fn value(&self, text: &str) -> String {
        if self.use_colors {
            text.ctp_white().to_string()
        } else {
            text.to_string()
        }
    }

    fn success(&self, text: &str) -> String {
        if self.use_colors {
            text.ctp_green().bold().to_string()
        } else {
            text.to_string()
        }
    }

    fn warning(&self, text: &str) -> String {
        if self.use_colors {
            text.ctp_yellow().bold().to_string()
        } else {
            text.to_string()
        }
    }

    fn error(&self, text: &str) -> String {
        if self.use_colors {
            text.ctp_red().bold().to_string()
        } else {
            text.to_string()
        }
    }

    fn dim(&self, text: &str) -> String {
        if self.use_colors {
            text.overlay1().to_string()
        } else {
            text.to_string()
        }
    }

    fn header(&self, text: &str) -> String {
        if self.use_colors {
            format!(
                "\n{}\n{}",
                text.lavender().bold(),
                "─".repeat(text.len()).subtext0()
            )
        } else {
            format!("\n{}\n{}", text, "-".repeat(text.len()))
        }
    }

    /// Renders the CAA policy block (records, issuer match, note) shared
    /// between `format_status` and `format_ssl`. `indent` is the leading
    /// whitespace per line — typically `"  "`.
    fn render_caa_block(&self, caa: &CaaPolicy, indent: &str) -> Vec<String> {
        let mut out = Vec::new();
        out.push(format!("\n{}{}:", indent, self.label("CAA Policy")));

        if !caa.has_policy {
            out.push(format!(
                "{}  {}",
                indent,
                self.value("No CAA records (any CA may issue)")
            ));
        } else {
            if let Some(ref eff) = caa.effective_domain {
                out.push(format!(
                    "{}  {}: {}",
                    indent,
                    self.label("Found at"),
                    self.value(&sanitize_display(eff))
                ));
            }
            for r in &caa.records {
                out.push(format!(
                    "{}  {} {} \"{}\"",
                    indent,
                    self.value(&r.flags.to_string()),
                    self.label(&r.tag),
                    sanitize_display(&r.value)
                ));
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
            out.push(format!(
                "{}  {}: {}",
                indent,
                self.label("Issuer vs CAA"),
                rendered
            ));
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

// Thin dispatch layer: each trait method forwards to the inherent
// method of the same name defined in the per-concern submodule. Rust
// resolves the inherent method first, so this does not recurse.
impl OutputFormatter for HumanFormatter {
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
    fn format_dnssec(&self, report: &crate::dns::DnssecReport) -> String {
        self.format_dnssec(report)
    }
    fn format_tld(&self, info: &crate::tld::TldInfo) -> String {
        self.format_tld(info)
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
}
