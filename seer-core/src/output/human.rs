use chrono::TimeDelta;
use colored::Colorize;
use once_cell::sync::Lazy;
use regex::Regex;

use super::OutputFormatter;
use crate::caa::{CaaPolicy, IssuerCaaMatch};
use crate::colors::CatppuccinExt;
use crate::dns::{DnsRecord, FollowIteration, FollowResult, PropagationResult};
use crate::lookup::LookupResult;
use crate::rdap::RdapResponse;
use crate::status::StatusResponse;
use crate::whois::WhoisResponse;

/// Strips ANSI escape sequences from untrusted external strings to prevent
/// terminal injection via malicious WHOIS/RDAP response data.
static ANSI_ESCAPE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x07]*\x07|\x1b[A-Z@-_]")
        .expect("Invalid ANSI escape regex")
});

fn sanitize_display(s: &str) -> String {
    ANSI_ESCAPE_RE.replace_all(s, "").to_string()
}

fn format_duration(duration: TimeDelta) -> String {
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

impl OutputFormatter for HumanFormatter {
    fn format_whois(&self, response: &WhoisResponse) -> String {
        let mut output = Vec::new();

        output.push(self.header(&format!("WHOIS: {}", sanitize_display(&response.domain))));

        if response.is_available() {
            output.push(format!("  {} Domain is available", self.success("✓")));
            return output.join("\n");
        }

        if let Some(ref registrar) = response.registrar {
            output.push(format!(
                "  {}: {}",
                self.label("Registrar"),
                self.value(&sanitize_display(registrar))
            ));
        }

        if let Some(ref registrant) = response.registrant {
            output.push(format!(
                "  {}: {}",
                self.label("Registrant"),
                self.value(&sanitize_display(registrant))
            ));
        }

        if let Some(ref organization) = response.organization {
            output.push(format!(
                "  {}: {}",
                self.label("Organization"),
                self.value(&sanitize_display(organization))
            ));
        }

        // Registrant contact details
        let has_registrant_details = response.registrant_email.is_some()
            || response.registrant_phone.is_some()
            || response.registrant_address.is_some()
            || response.registrant_country.is_some();

        if has_registrant_details {
            output.push(format!("\n  {}:", self.label("Registrant Contact")));
            if let Some(ref email) = response.registrant_email {
                output.push(format!(
                    "    {}: {}",
                    self.label("Email"),
                    self.value(&sanitize_display(email))
                ));
            }
            if let Some(ref phone) = response.registrant_phone {
                output.push(format!(
                    "    {}: {}",
                    self.label("Phone"),
                    self.value(&sanitize_display(phone))
                ));
            }
            if let Some(ref address) = response.registrant_address {
                output.push(format!(
                    "    {}: {}",
                    self.label("Address"),
                    self.value(&sanitize_display(address))
                ));
            }
            if let Some(ref country) = response.registrant_country {
                output.push(format!(
                    "    {}: {}",
                    self.label("Country"),
                    self.value(&sanitize_display(country))
                ));
            }
        }

        // Admin contact
        let has_admin_contact = response.admin_name.is_some()
            || response.admin_organization.is_some()
            || response.admin_email.is_some()
            || response.admin_phone.is_some();

        if has_admin_contact {
            output.push(format!("\n  {}:", self.label("Admin Contact")));
            if let Some(ref name) = response.admin_name {
                output.push(format!(
                    "    {}: {}",
                    self.label("Name"),
                    self.value(&sanitize_display(name))
                ));
            }
            if let Some(ref org) = response.admin_organization {
                output.push(format!(
                    "    {}: {}",
                    self.label("Organization"),
                    self.value(&sanitize_display(org))
                ));
            }
            if let Some(ref email) = response.admin_email {
                output.push(format!(
                    "    {}: {}",
                    self.label("Email"),
                    self.value(&sanitize_display(email))
                ));
            }
            if let Some(ref phone) = response.admin_phone {
                output.push(format!(
                    "    {}: {}",
                    self.label("Phone"),
                    self.value(&sanitize_display(phone))
                ));
            }
        }

        // Tech contact
        let has_tech_contact = response.tech_name.is_some()
            || response.tech_organization.is_some()
            || response.tech_email.is_some()
            || response.tech_phone.is_some();

        if has_tech_contact {
            output.push(format!("\n  {}:", self.label("Tech Contact")));
            if let Some(ref name) = response.tech_name {
                output.push(format!(
                    "    {}: {}",
                    self.label("Name"),
                    self.value(&sanitize_display(name))
                ));
            }
            if let Some(ref org) = response.tech_organization {
                output.push(format!(
                    "    {}: {}",
                    self.label("Organization"),
                    self.value(&sanitize_display(org))
                ));
            }
            if let Some(ref email) = response.tech_email {
                output.push(format!(
                    "    {}: {}",
                    self.label("Email"),
                    self.value(&sanitize_display(email))
                ));
            }
            if let Some(ref phone) = response.tech_phone {
                output.push(format!(
                    "    {}: {}",
                    self.label("Phone"),
                    self.value(&sanitize_display(phone))
                ));
            }
        }

        if let Some(created) = response.creation_date {
            output.push(format!(
                "  {}: {}",
                self.label("Created"),
                self.value(&created.format("%Y-%m-%d").to_string())
            ));
        }

        if let Some(expires) = response.expiration_date {
            let days_until = (expires - chrono::Utc::now()).num_days();
            let expiry_str = expires.format("%Y-%m-%d").to_string();
            let status = self.format_expiry_status(&expiry_str, days_until);
            output.push(format!("  {}: {}", self.label("Expires"), status));
        }

        if let Some(updated) = response.updated_date {
            output.push(format!(
                "  {}: {}",
                self.label("Updated"),
                self.value(&updated.format("%Y-%m-%d").to_string())
            ));
        }

        if !response.nameservers.is_empty() {
            output.push(format!("  {}:", self.label("Nameservers")));
            for ns in &response.nameservers {
                output.push(format!("    - {}", self.value(&sanitize_display(ns))));
            }
        }

        if !response.status.is_empty() {
            output.push(format!("  {}:", self.label("Status")));
            for status in &response.status {
                output.push(format!("    - {}", self.value(&sanitize_display(status))));
            }
        }

        if let Some(ref dnssec) = response.dnssec {
            output.push(format!(
                "  {}: {}",
                self.label("DNSSEC"),
                self.value(&sanitize_display(dnssec))
            ));
        }

        output.push(format!(
            "  {}: {}",
            self.label("WHOIS Server"),
            self.value(&sanitize_display(&response.whois_server))
        ));

        output.join("\n")
    }

    fn format_rdap(&self, response: &RdapResponse) -> String {
        let mut output = Vec::new();

        let name = response
            .domain_name()
            .or(response.name.as_deref())
            .unwrap_or("Unknown");
        output.push(self.header(&format!("RDAP: {}", sanitize_display(name))));

        if let Some(handle) = &response.handle {
            output.push(format!(
                "  {}: {}",
                self.label("Handle"),
                self.value(&sanitize_display(handle))
            ));
        }

        if let Some(registrar) = response.get_registrar() {
            output.push(format!(
                "  {}: {}",
                self.label("Registrar"),
                self.value(&sanitize_display(&registrar))
            ));
        }

        if let Some(registrant) = response.get_registrant() {
            output.push(format!(
                "  {}: {}",
                self.label("Registrant"),
                self.value(&sanitize_display(&registrant))
            ));
        }

        if let Some(organization) = response.get_registrant_organization() {
            output.push(format!(
                "  {}: {}",
                self.label("Organization"),
                self.value(&sanitize_display(&organization))
            ));
        }

        // Registrant contact details
        if let Some(contact) = response.get_registrant_contact() {
            if contact.has_info() {
                output.push(format!("\n  {}:", self.label("Registrant Contact")));
                if let Some(ref email) = contact.email {
                    output.push(format!(
                        "    {}: {}",
                        self.label("Email"),
                        self.value(&sanitize_display(email))
                    ));
                }
                if let Some(ref phone) = contact.phone {
                    output.push(format!(
                        "    {}: {}",
                        self.label("Phone"),
                        self.value(&sanitize_display(phone))
                    ));
                }
                if let Some(ref address) = contact.address {
                    output.push(format!(
                        "    {}: {}",
                        self.label("Address"),
                        self.value(&sanitize_display(address))
                    ));
                }
                if let Some(ref country) = contact.country {
                    output.push(format!(
                        "    {}: {}",
                        self.label("Country"),
                        self.value(&sanitize_display(country))
                    ));
                }
            }
        }

        // Admin contact
        if let Some(contact) = response.get_admin_contact() {
            if contact.has_info() {
                output.push(format!("\n  {}:", self.label("Admin Contact")));
                if let Some(ref name) = contact.name {
                    output.push(format!(
                        "    {}: {}",
                        self.label("Name"),
                        self.value(&sanitize_display(name))
                    ));
                }
                if let Some(ref org) = contact.organization {
                    output.push(format!(
                        "    {}: {}",
                        self.label("Organization"),
                        self.value(&sanitize_display(org))
                    ));
                }
                if let Some(ref email) = contact.email {
                    output.push(format!(
                        "    {}: {}",
                        self.label("Email"),
                        self.value(&sanitize_display(email))
                    ));
                }
                if let Some(ref phone) = contact.phone {
                    output.push(format!(
                        "    {}: {}",
                        self.label("Phone"),
                        self.value(&sanitize_display(phone))
                    ));
                }
                if let Some(ref address) = contact.address {
                    output.push(format!(
                        "    {}: {}",
                        self.label("Address"),
                        self.value(&sanitize_display(address))
                    ));
                }
                if let Some(ref country) = contact.country {
                    output.push(format!(
                        "    {}: {}",
                        self.label("Country"),
                        self.value(&sanitize_display(country))
                    ));
                }
            }
        }

        // Tech contact
        if let Some(contact) = response.get_tech_contact() {
            if contact.has_info() {
                output.push(format!("\n  {}:", self.label("Tech Contact")));
                if let Some(ref name) = contact.name {
                    output.push(format!(
                        "    {}: {}",
                        self.label("Name"),
                        self.value(&sanitize_display(name))
                    ));
                }
                if let Some(ref org) = contact.organization {
                    output.push(format!(
                        "    {}: {}",
                        self.label("Organization"),
                        self.value(&sanitize_display(org))
                    ));
                }
                if let Some(ref email) = contact.email {
                    output.push(format!(
                        "    {}: {}",
                        self.label("Email"),
                        self.value(&sanitize_display(email))
                    ));
                }
                if let Some(ref phone) = contact.phone {
                    output.push(format!(
                        "    {}: {}",
                        self.label("Phone"),
                        self.value(&sanitize_display(phone))
                    ));
                }
                if let Some(ref address) = contact.address {
                    output.push(format!(
                        "    {}: {}",
                        self.label("Address"),
                        self.value(&sanitize_display(address))
                    ));
                }
                if let Some(ref country) = contact.country {
                    output.push(format!(
                        "    {}: {}",
                        self.label("Country"),
                        self.value(&sanitize_display(country))
                    ));
                }
            }
        }

        // Billing contact
        if let Some(contact) = response.get_billing_contact() {
            if contact.has_info() {
                output.push(format!("\n  {}:", self.label("Billing Contact")));
                if let Some(ref name) = contact.name {
                    output.push(format!(
                        "    {}: {}",
                        self.label("Name"),
                        self.value(&sanitize_display(name))
                    ));
                }
                if let Some(ref org) = contact.organization {
                    output.push(format!(
                        "    {}: {}",
                        self.label("Organization"),
                        self.value(&sanitize_display(org))
                    ));
                }
                if let Some(ref email) = contact.email {
                    output.push(format!(
                        "    {}: {}",
                        self.label("Email"),
                        self.value(&sanitize_display(email))
                    ));
                }
                if let Some(ref phone) = contact.phone {
                    output.push(format!(
                        "    {}: {}",
                        self.label("Phone"),
                        self.value(&sanitize_display(phone))
                    ));
                }
                if let Some(ref address) = contact.address {
                    output.push(format!(
                        "    {}: {}",
                        self.label("Address"),
                        self.value(&sanitize_display(address))
                    ));
                }
                if let Some(ref country) = contact.country {
                    output.push(format!(
                        "    {}: {}",
                        self.label("Country"),
                        self.value(&sanitize_display(country))
                    ));
                }
            }
        }

        if let Some(created) = response.creation_date() {
            output.push(format!(
                "  {}: {}",
                self.label("Created"),
                self.value(&created.format("%Y-%m-%d").to_string())
            ));
        }

        if let Some(expires) = response.expiration_date() {
            let days_until = (expires - chrono::Utc::now()).num_days();
            let expiry_str = expires.format("%Y-%m-%d").to_string();
            let status = self.format_expiry_status(&expiry_str, days_until);
            output.push(format!("  {}: {}", self.label("Expires"), status));
        }

        if let Some(updated) = response.last_updated() {
            output.push(format!(
                "  {}: {}",
                self.label("Updated"),
                self.value(&updated.format("%Y-%m-%d").to_string())
            ));
        }

        if !response.status.is_empty() {
            output.push(format!("  {}:", self.label("Status")));
            for status in &response.status {
                output.push(format!("    - {}", self.value(&sanitize_display(status))));
            }
        }

        let nameservers = response.nameserver_names();
        if !nameservers.is_empty() {
            output.push(format!("  {}:", self.label("Nameservers")));
            for ns in &nameservers {
                output.push(format!("    - {}", self.value(&sanitize_display(ns))));
            }
        }

        if response.is_dnssec_signed() {
            output.push(format!(
                "  {}: {}",
                self.label("DNSSEC"),
                self.success("signed")
            ));
        }

        // IP-specific fields
        if let Some(ref start) = response.start_address {
            output.push(format!(
                "  {}: {}",
                self.label("Start Address"),
                self.value(&sanitize_display(start))
            ));
        }

        if let Some(ref end) = response.end_address {
            output.push(format!(
                "  {}: {}",
                self.label("End Address"),
                self.value(&sanitize_display(end))
            ));
        }

        if let Some(ref country) = response.country {
            output.push(format!(
                "  {}: {}",
                self.label("Country"),
                self.value(&sanitize_display(country))
            ));
        }

        // ASN-specific fields
        if let Some(start) = response.start_autnum {
            output.push(format!(
                "  {}: {}",
                self.label("AS Number"),
                self.value(&format!(
                    "AS{} - AS{}",
                    start,
                    response.end_autnum.unwrap_or(start)
                ))
            ));
        }

        output.join("\n")
    }

    fn format_dns(&self, records: &[DnsRecord]) -> String {
        let mut output = Vec::new();

        if records.is_empty() {
            output.push(self.warning("No records found"));
            // DNSSEC disclaimer applies whether or not records were returned.
            output.push(String::new());
            output.push(self.warning("Note: DNS responses are not DNSSEC-validated"));
            return output.join("\n");
        }

        let domain = &records[0].name;
        let record_type = &records[0].record_type;
        output.push(self.header(&format!(
            "DNS {} Records: {}",
            record_type,
            sanitize_display(domain)
        )));

        for record in records {
            output.push(format!(
                "  {} {} {} {}",
                self.value(&sanitize_display(&record.name)),
                self.label(&format!("{}", record.ttl)),
                self.label(&format!("{}", record.record_type)),
                self.success(&sanitize_display(&record.data.to_string()))
            ));
        }

        // DNSSEC disclosure (M12): Seer's resolver does not validate DNSSEC,
        // and UDP DNS is trivially spoofable. Surface this once per DNS block.
        output.push(String::new());
        output.push(self.warning("Note: DNS responses are not DNSSEC-validated"));

        output.join("\n")
    }

    fn format_propagation(&self, result: &PropagationResult) -> String {
        let mut output = Vec::new();

        output.push(self.header(&format!(
            "Propagation Check: {} {}",
            result.domain, result.record_type
        )));

        // Summary
        let percentage = result.propagation_percentage;
        let percentage_str = format!("{:.1}%", percentage);
        let status = if percentage >= 100.0 {
            self.success(&format!("✓ Fully propagated ({})", percentage_str))
        } else if percentage >= 80.0 {
            self.warning(&format!("◐ Mostly propagated ({})", percentage_str))
        } else if percentage >= 50.0 {
            self.warning(&format!("◑ Partially propagated ({})", percentage_str))
        } else {
            self.error(&format!("✗ Not propagated ({})", percentage_str))
        };
        output.push(format!("  {}", status));

        output.push(format!(
            "  {}: {}/{}",
            self.label("Servers responding"),
            result.servers_responding,
            result.servers_checked
        ));

        // Consensus values
        if !result.consensus_values.is_empty() {
            output.push(format!("  {}:", self.label("Consensus values")));
            for value in &result.consensus_values {
                output.push(format!("    - {}", self.success(&sanitize_display(value))));
            }
        }

        // Inconsistencies (genuine answer conflicts only)
        if !result.inconsistencies.is_empty() {
            output.push(format!("  {}:", self.label("Inconsistencies")));
            for inconsistency in &result.inconsistencies {
                output.push(format!(
                    "    - {}",
                    self.warning(&sanitize_display(inconsistency))
                ));
            }
        }

        // Unreachable servers (timeouts, network errors) — distinct from
        // answer conflicts. Reporting these separately prevents a single
        // timeout from being misread as divergent DNS state.
        if !result.unreachable_servers.is_empty() {
            output.push(format!("  {}:", self.label("Unreachable servers")));
            for unreachable in &result.unreachable_servers {
                let error_msg = unreachable.error.as_deref().unwrap_or("no response");
                output.push(format!(
                    "    - {} ({}): {}",
                    self.warning(&sanitize_display(&unreachable.name)),
                    sanitize_display(&unreachable.ip),
                    sanitize_display(error_msg),
                ));
            }
        }

        // Group results by region
        let mut by_region: std::collections::HashMap<&str, Vec<_>> =
            std::collections::HashMap::new();
        for server_result in &result.results {
            by_region
                .entry(server_result.server.location.as_str())
                .or_default()
                .push(server_result);
        }

        // Sort regions for consistent output
        let mut regions: Vec<_> = by_region.keys().cloned().collect();
        regions.sort();

        output.push(format!("\n  {}:", self.label("Results by Region")));
        for region in &regions {
            output.push(format!("\n    {}:", self.label(region)));
            if let Some(server_results) = by_region.get(region) {
                for server_result in server_results {
                    let status_icon = if server_result.success { "✓" } else { "✗" };
                    let status_colored = if server_result.success {
                        self.success(status_icon)
                    } else {
                        self.error(status_icon)
                    };

                    let values = if server_result.success {
                        if server_result.records.is_empty() {
                            "NXDOMAIN".to_string()
                        } else {
                            server_result
                                .records
                                .iter()
                                .map(|r| {
                                    let short = r.format_short();
                                    let display = sanitize_display(&short);
                                    match result.resolved_ips.get(&short.to_ascii_lowercase()) {
                                        Some(ips) if !ips.is_empty() => {
                                            format!("{} ({})", display, ips.join(", "))
                                        }
                                        _ => display,
                                    }
                                })
                                .collect::<Vec<_>>()
                                .join(", ")
                        }
                    } else {
                        sanitize_display(server_result.error.as_deref().unwrap_or("Error"))
                    };

                    output.push(format!(
                        "      {} {} ({}) - {} [{}ms]",
                        status_colored,
                        self.value(&server_result.server.name),
                        server_result.server.ip,
                        values,
                        server_result.response_time_ms
                    ));
                }
            }
        }

        // DNSSEC disclosure (M12). The resolver does not perform DNSSEC
        // validation and UDP DNS is trivially spoofable — surface this so
        // users don't treat the results as authenticated.
        if !result.dnssec_validated {
            output.push(String::new());
            output.push(self.warning("Note: DNS responses are not DNSSEC-validated"));
        }

        output.join("\n")
    }

    fn format_lookup(&self, result: &LookupResult) -> String {
        let mut output = Vec::new();

        let domain = result
            .domain_name()
            .unwrap_or_else(|| "Unknown".to_string());
        let header_suffix = match result {
            LookupResult::Rdap { .. } => "via RDAP".to_string(),
            LookupResult::Whois { .. } => "via WHOIS".to_string(),
            LookupResult::Available { data, .. } => match data.verdict() {
                "available" => "available".to_string(),
                "likely_available" => "likely available".to_string(),
                "registered" => "registered".to_string(),
                "likely_registered" => "likely registered".to_string(),
                _ => "status unknown".to_string(),
            },
        };

        output.push(self.header(&format!(
            "Lookup: {} ({})",
            sanitize_display(&domain),
            header_suffix
        )));

        match result {
            LookupResult::Rdap {
                data,
                whois_fallback,
            } => {
                output.push(format!(
                    "  {}: {}",
                    self.label("Source"),
                    self.success("RDAP (modern protocol)")
                ));

                if let Some(registrar) = data.get_registrar() {
                    output.push(format!(
                        "  {}: {}",
                        self.label("Registrar"),
                        self.value(&sanitize_display(&registrar))
                    ));
                }

                if let Some(registrant) = data.get_registrant() {
                    output.push(format!(
                        "  {}: {}",
                        self.label("Registrant"),
                        self.value(&sanitize_display(&registrant))
                    ));
                }

                if let Some(organization) = data.get_registrant_organization() {
                    output.push(format!(
                        "  {}: {}",
                        self.label("Organization"),
                        self.value(&sanitize_display(&organization))
                    ));
                }

                // Registrant contact details
                if let Some(contact) = data.get_registrant_contact() {
                    if contact.has_info() {
                        output.push(format!("\n  {}:", self.label("Registrant Contact")));
                        if let Some(ref email) = contact.email {
                            output.push(format!(
                                "    {}: {}",
                                self.label("Email"),
                                self.value(&sanitize_display(email))
                            ));
                        }
                        if let Some(ref phone) = contact.phone {
                            output.push(format!(
                                "    {}: {}",
                                self.label("Phone"),
                                self.value(&sanitize_display(phone))
                            ));
                        }
                        if let Some(ref address) = contact.address {
                            output.push(format!(
                                "    {}: {}",
                                self.label("Address"),
                                self.value(&sanitize_display(address))
                            ));
                        }
                        if let Some(ref country) = contact.country {
                            output.push(format!(
                                "    {}: {}",
                                self.label("Country"),
                                self.value(&sanitize_display(country))
                            ));
                        }
                    }
                }

                // Admin contact
                if let Some(contact) = data.get_admin_contact() {
                    if contact.has_info() {
                        output.push(format!("\n  {}:", self.label("Admin Contact")));
                        if let Some(ref name) = contact.name {
                            output.push(format!(
                                "    {}: {}",
                                self.label("Name"),
                                self.value(&sanitize_display(name))
                            ));
                        }
                        if let Some(ref org) = contact.organization {
                            output.push(format!(
                                "    {}: {}",
                                self.label("Organization"),
                                self.value(&sanitize_display(org))
                            ));
                        }
                        if let Some(ref email) = contact.email {
                            output.push(format!(
                                "    {}: {}",
                                self.label("Email"),
                                self.value(&sanitize_display(email))
                            ));
                        }
                        if let Some(ref phone) = contact.phone {
                            output.push(format!(
                                "    {}: {}",
                                self.label("Phone"),
                                self.value(&sanitize_display(phone))
                            ));
                        }
                    }
                }

                // Tech contact
                if let Some(contact) = data.get_tech_contact() {
                    if contact.has_info() {
                        output.push(format!("\n  {}:", self.label("Tech Contact")));
                        if let Some(ref name) = contact.name {
                            output.push(format!(
                                "    {}: {}",
                                self.label("Name"),
                                self.value(&sanitize_display(name))
                            ));
                        }
                        if let Some(ref org) = contact.organization {
                            output.push(format!(
                                "    {}: {}",
                                self.label("Organization"),
                                self.value(&sanitize_display(org))
                            ));
                        }
                        if let Some(ref email) = contact.email {
                            output.push(format!(
                                "    {}: {}",
                                self.label("Email"),
                                self.value(&sanitize_display(email))
                            ));
                        }
                        if let Some(ref phone) = contact.phone {
                            output.push(format!(
                                "    {}: {}",
                                self.label("Phone"),
                                self.value(&sanitize_display(phone))
                            ));
                        }
                    }
                }

                if let Some(created) = data.creation_date() {
                    output.push(format!(
                        "  {}: {}",
                        self.label("Created"),
                        self.value(&created.format("%Y-%m-%d").to_string())
                    ));
                }

                if let Some(expires) = data.expiration_date() {
                    let days_until = (expires - chrono::Utc::now()).num_days();
                    let expiry_str = expires.format("%Y-%m-%d").to_string();
                    let status = self.format_expiry_status(&expiry_str, days_until);
                    output.push(format!("  {}: {}", self.label("Expires"), status));
                }

                if !data.status.is_empty() {
                    output.push(format!("  {}:", self.label("Status")));
                    for status in &data.status {
                        output.push(format!("    - {}", self.value(&sanitize_display(status))));
                    }
                }

                let nameservers = data.nameserver_names();
                if !nameservers.is_empty() {
                    output.push(format!("  {}:", self.label("Nameservers")));
                    for ns in &nameservers {
                        output.push(format!("    - {}", self.value(&sanitize_display(ns))));
                    }
                }

                if data.is_dnssec_signed() {
                    output.push(format!(
                        "  {}: {}",
                        self.label("DNSSEC"),
                        self.success("signed")
                    ));
                }

                if let Some(whois) = whois_fallback {
                    let mut extra = Vec::new();

                    // Registrant (if RDAP didn't have it)
                    if data.get_registrant().is_none() {
                        if let Some(ref registrant) = whois.registrant {
                            extra.push(format!(
                                "    {}: {}",
                                self.label("Registrant"),
                                self.value(&sanitize_display(registrant))
                            ));
                        }
                    }

                    // Organization (if RDAP didn't have it)
                    if data.get_registrant_organization().is_none() {
                        if let Some(ref org) = whois.organization {
                            extra.push(format!(
                                "    {}: {}",
                                self.label("Organization"),
                                self.value(&sanitize_display(org))
                            ));
                        }
                    }

                    // Registrant contact details (if RDAP didn't have them)
                    let rdap_registrant = data.get_registrant_contact();
                    let rdap_has_registrant =
                        rdap_registrant.as_ref().is_some_and(|c| c.has_info());
                    if !rdap_has_registrant {
                        let has_whois_contact = whois.registrant_email.is_some()
                            || whois.registrant_phone.is_some()
                            || whois.registrant_address.is_some()
                            || whois.registrant_country.is_some();
                        if has_whois_contact {
                            extra.push(format!("\n    {}:", self.label("Registrant Contact")));
                            if let Some(ref email) = whois.registrant_email {
                                extra.push(format!(
                                    "      {}: {}",
                                    self.label("Email"),
                                    self.value(&sanitize_display(email))
                                ));
                            }
                            if let Some(ref phone) = whois.registrant_phone {
                                extra.push(format!(
                                    "      {}: {}",
                                    self.label("Phone"),
                                    self.value(&sanitize_display(phone))
                                ));
                            }
                            if let Some(ref address) = whois.registrant_address {
                                extra.push(format!(
                                    "      {}: {}",
                                    self.label("Address"),
                                    self.value(&sanitize_display(address))
                                ));
                            }
                            if let Some(ref country) = whois.registrant_country {
                                extra.push(format!(
                                    "      {}: {}",
                                    self.label("Country"),
                                    self.value(&sanitize_display(country))
                                ));
                            }
                        }
                    }

                    // Admin contact (if RDAP didn't have it)
                    let rdap_has_admin = data.get_admin_contact().is_some_and(|c| c.has_info());
                    if !rdap_has_admin {
                        let has_whois_admin = whois.admin_name.is_some()
                            || whois.admin_email.is_some()
                            || whois.admin_phone.is_some();
                        if has_whois_admin {
                            extra.push(format!("\n    {}:", self.label("Admin Contact")));
                            if let Some(ref name) = whois.admin_name {
                                extra.push(format!(
                                    "      {}: {}",
                                    self.label("Name"),
                                    self.value(&sanitize_display(name))
                                ));
                            }
                            if let Some(ref org) = whois.admin_organization {
                                extra.push(format!(
                                    "      {}: {}",
                                    self.label("Organization"),
                                    self.value(&sanitize_display(org))
                                ));
                            }
                            if let Some(ref email) = whois.admin_email {
                                extra.push(format!(
                                    "      {}: {}",
                                    self.label("Email"),
                                    self.value(&sanitize_display(email))
                                ));
                            }
                            if let Some(ref phone) = whois.admin_phone {
                                extra.push(format!(
                                    "      {}: {}",
                                    self.label("Phone"),
                                    self.value(&sanitize_display(phone))
                                ));
                            }
                        }
                    }

                    // Tech contact (if RDAP didn't have it)
                    let rdap_has_tech = data.get_tech_contact().is_some_and(|c| c.has_info());
                    if !rdap_has_tech {
                        let has_whois_tech = whois.tech_name.is_some()
                            || whois.tech_email.is_some()
                            || whois.tech_phone.is_some();
                        if has_whois_tech {
                            extra.push(format!("\n    {}:", self.label("Tech Contact")));
                            if let Some(ref name) = whois.tech_name {
                                extra.push(format!(
                                    "      {}: {}",
                                    self.label("Name"),
                                    self.value(&sanitize_display(name))
                                ));
                            }
                            if let Some(ref org) = whois.tech_organization {
                                extra.push(format!(
                                    "      {}: {}",
                                    self.label("Organization"),
                                    self.value(&sanitize_display(org))
                                ));
                            }
                            if let Some(ref email) = whois.tech_email {
                                extra.push(format!(
                                    "      {}: {}",
                                    self.label("Email"),
                                    self.value(&sanitize_display(email))
                                ));
                            }
                            if let Some(ref phone) = whois.tech_phone {
                                extra.push(format!(
                                    "      {}: {}",
                                    self.label("Phone"),
                                    self.value(&sanitize_display(phone))
                                ));
                            }
                        }
                    }

                    // Updated date (RDAP doesn't typically expose this)
                    if let Some(updated) = whois.updated_date {
                        extra.push(format!(
                            "    {}: {}",
                            self.label("Updated"),
                            self.value(&updated.format("%Y-%m-%d").to_string())
                        ));
                    }

                    // DNSSEC (if RDAP didn't show it)
                    if !data.is_dnssec_signed() {
                        if let Some(ref dnssec) = whois.dnssec {
                            extra.push(format!(
                                "    {}: {}",
                                self.label("DNSSEC"),
                                self.value(&sanitize_display(dnssec))
                            ));
                        }
                    }

                    // WHOIS server
                    if !whois.whois_server.is_empty() {
                        extra.push(format!(
                            "    {}: {}",
                            self.label("WHOIS Server"),
                            self.value(&sanitize_display(&whois.whois_server))
                        ));
                    }

                    if !extra.is_empty() {
                        output.push(format!("\n  {}", self.label("Additional WHOIS data:")));
                        output.extend(extra);
                    }
                }
            }
            LookupResult::Whois {
                data, rdap_error, ..
            } => {
                let source_note = if rdap_error.is_some() {
                    "WHOIS (RDAP unavailable)"
                } else {
                    "WHOIS"
                };
                output.push(format!(
                    "  {}: {}",
                    self.label("Source"),
                    self.warning(source_note)
                ));

                if let Some(ref error) = rdap_error {
                    output.push(format!(
                        "  {}: {}",
                        self.label("RDAP Error"),
                        self.error(error)
                    ));
                }

                if let Some(ref registrar) = data.registrar {
                    output.push(format!(
                        "  {}: {}",
                        self.label("Registrar"),
                        self.value(&sanitize_display(registrar))
                    ));
                }

                if let Some(ref registrant) = data.registrant {
                    output.push(format!(
                        "  {}: {}",
                        self.label("Registrant"),
                        self.value(&sanitize_display(registrant))
                    ));
                }

                if let Some(ref organization) = data.organization {
                    output.push(format!(
                        "  {}: {}",
                        self.label("Organization"),
                        self.value(&sanitize_display(organization))
                    ));
                }

                // Registrant contact details
                let has_registrant_details = data.registrant_email.is_some()
                    || data.registrant_phone.is_some()
                    || data.registrant_address.is_some()
                    || data.registrant_country.is_some();

                if has_registrant_details {
                    output.push(format!("\n  {}:", self.label("Registrant Contact")));
                    if let Some(ref email) = data.registrant_email {
                        output.push(format!(
                            "    {}: {}",
                            self.label("Email"),
                            self.value(&sanitize_display(email))
                        ));
                    }
                    if let Some(ref phone) = data.registrant_phone {
                        output.push(format!(
                            "    {}: {}",
                            self.label("Phone"),
                            self.value(&sanitize_display(phone))
                        ));
                    }
                    if let Some(ref address) = data.registrant_address {
                        output.push(format!(
                            "    {}: {}",
                            self.label("Address"),
                            self.value(&sanitize_display(address))
                        ));
                    }
                    if let Some(ref country) = data.registrant_country {
                        output.push(format!(
                            "    {}: {}",
                            self.label("Country"),
                            self.value(&sanitize_display(country))
                        ));
                    }
                }

                // Admin contact
                let has_admin_contact = data.admin_name.is_some()
                    || data.admin_organization.is_some()
                    || data.admin_email.is_some()
                    || data.admin_phone.is_some();

                if has_admin_contact {
                    output.push(format!("\n  {}:", self.label("Admin Contact")));
                    if let Some(ref name) = data.admin_name {
                        output.push(format!(
                            "    {}: {}",
                            self.label("Name"),
                            self.value(&sanitize_display(name))
                        ));
                    }
                    if let Some(ref org) = data.admin_organization {
                        output.push(format!(
                            "    {}: {}",
                            self.label("Organization"),
                            self.value(&sanitize_display(org))
                        ));
                    }
                    if let Some(ref email) = data.admin_email {
                        output.push(format!(
                            "    {}: {}",
                            self.label("Email"),
                            self.value(&sanitize_display(email))
                        ));
                    }
                    if let Some(ref phone) = data.admin_phone {
                        output.push(format!(
                            "    {}: {}",
                            self.label("Phone"),
                            self.value(&sanitize_display(phone))
                        ));
                    }
                }

                // Tech contact
                let has_tech_contact = data.tech_name.is_some()
                    || data.tech_organization.is_some()
                    || data.tech_email.is_some()
                    || data.tech_phone.is_some();

                if has_tech_contact {
                    output.push(format!("\n  {}:", self.label("Tech Contact")));
                    if let Some(ref name) = data.tech_name {
                        output.push(format!(
                            "    {}: {}",
                            self.label("Name"),
                            self.value(&sanitize_display(name))
                        ));
                    }
                    if let Some(ref org) = data.tech_organization {
                        output.push(format!(
                            "    {}: {}",
                            self.label("Organization"),
                            self.value(&sanitize_display(org))
                        ));
                    }
                    if let Some(ref email) = data.tech_email {
                        output.push(format!(
                            "    {}: {}",
                            self.label("Email"),
                            self.value(&sanitize_display(email))
                        ));
                    }
                    if let Some(ref phone) = data.tech_phone {
                        output.push(format!(
                            "    {}: {}",
                            self.label("Phone"),
                            self.value(&sanitize_display(phone))
                        ));
                    }
                }

                if let Some(created) = data.creation_date {
                    output.push(format!(
                        "  {}: {}",
                        self.label("Created"),
                        self.value(&created.format("%Y-%m-%d").to_string())
                    ));
                }

                if let Some(expires) = data.expiration_date {
                    let days_until = (expires - chrono::Utc::now()).num_days();
                    let expiry_str = expires.format("%Y-%m-%d").to_string();
                    let status = self.format_expiry_status(&expiry_str, days_until);
                    output.push(format!("  {}: {}", self.label("Expires"), status));
                }

                if !data.status.is_empty() {
                    output.push(format!("  {}:", self.label("Status")));
                    for status in &data.status {
                        output.push(format!("    - {}", self.value(&sanitize_display(status))));
                    }
                }

                if !data.nameservers.is_empty() {
                    output.push(format!("  {}:", self.label("Nameservers")));
                    for ns in &data.nameservers {
                        output.push(format!("    - {}", self.value(&sanitize_display(ns))));
                    }
                }

                if let Some(ref dnssec) = data.dnssec {
                    output.push(format!(
                        "  {}: {}",
                        self.label("DNSSEC"),
                        self.value(&sanitize_display(dnssec))
                    ));
                }
            }
            LookupResult::Available {
                data,
                rdap_error,
                whois_error,
                whois_data,
            } => {
                let source_note = if whois_data.is_some() {
                    "WHOIS (RDAP unavailable)"
                } else {
                    "availability check (RDAP and WHOIS failed)"
                };
                output.push(format!(
                    "  {}: {}",
                    self.label("Source"),
                    self.warning(source_note)
                ));

                let verdict_colored = match data.verdict() {
                    "available" => self.success("AVAILABLE"),
                    "likely_available" => self.warning("MAY BE AVAILABLE"),
                    "registered" => self.value("REGISTERED"),
                    "likely_registered" => self.warning("LIKELY REGISTERED"),
                    _ => self.error("UNKNOWN"),
                };
                output.push(format!("  {}: {}", self.label("Verdict"), verdict_colored));

                // Confidence colouring is purely about certainty, independent of
                // the registered/available answer.
                let confidence_colored = match data.confidence.as_str() {
                    "high" => self.success(&data.confidence),
                    "medium" => self.warning(&data.confidence),
                    _ => self.error(&data.confidence),
                };
                output.push(format!(
                    "  {}: {}",
                    self.label("Confidence"),
                    confidence_colored
                ));

                output.push(format!(
                    "  {}: {}",
                    self.label("Method"),
                    self.value(&sanitize_display(&data.method))
                ));

                if let Some(details) = &data.details {
                    output.push(format!(
                        "  {}: {}",
                        self.label("Details"),
                        self.value(&sanitize_display(details))
                    ));
                }

                if !rdap_error.is_empty() {
                    output.push(format!(
                        "  {}: {}",
                        self.label("RDAP Error"),
                        self.error(rdap_error)
                    ));
                }
                if !whois_error.is_empty() {
                    output.push(format!(
                        "  {}: {}",
                        self.label("WHOIS Error"),
                        self.error(whois_error)
                    ));
                }

                if let Some(w) = whois_data {
                    let mut extra = Vec::new();
                    if !w.nameservers.is_empty() {
                        extra.push(format!(
                            "    {}: {}",
                            self.label("Nameservers"),
                            self.value(&sanitize_display(&w.nameservers.join(", ")))
                        ));
                    }
                    if !w.status.is_empty() {
                        extra.push(format!(
                            "    {}: {}",
                            self.label("Status"),
                            self.value(&sanitize_display(&w.status.join(", ")))
                        ));
                    }
                    if let Some(ref dnssec) = w.dnssec {
                        extra.push(format!(
                            "    {}: {}",
                            self.label("DNSSEC"),
                            self.value(&sanitize_display(dnssec))
                        ));
                    }
                    if !w.whois_server.is_empty() {
                        extra.push(format!(
                            "    {}: {}",
                            self.label("WHOIS Server"),
                            self.value(&sanitize_display(&w.whois_server))
                        ));
                    }
                    if !extra.is_empty() {
                        output.push(format!("  {}", self.label("Additional WHOIS data:")));
                        output.extend(extra);
                    }
                }
            }
        }

        output.join("\n")
    }

    fn format_status(&self, response: &StatusResponse) -> String {
        let mut output = Vec::new();

        output.push(self.header(&format!("Status: {}", sanitize_display(&response.domain))));

        // HTTP Status
        if let Some(status) = response.http_status {
            let status_text =
                sanitize_display(response.http_status_text.as_deref().unwrap_or("Unknown"));
            let status_display = if (200..300).contains(&status) {
                self.success(&format!("{} ({})", status, status_text))
            } else if (300..400).contains(&status) {
                self.warning(&format!("{} ({})", status, status_text))
            } else {
                self.error(&format!("{} ({})", status, status_text))
            };
            output.push(format!(
                "  {}: {}",
                self.label("HTTP Status"),
                status_display
            ));
        }

        // Site Title
        if let Some(ref title) = response.title {
            output.push(format!(
                "  {}: {}",
                self.label("Site Title"),
                self.value(&sanitize_display(title))
            ));
        }

        // SSL Certificate
        if let Some(ref cert) = response.certificate {
            output.push(format!("\n  {}:", self.label("SSL Certificate")));
            output.push(format!(
                "    {}: {}",
                self.label("Subject"),
                self.value(&sanitize_display(&cert.subject))
            ));
            output.push(format!(
                "    {}: {}",
                self.label("Issuer"),
                self.value(&sanitize_display(&cert.issuer))
            ));

            let valid_status = if cert.is_valid {
                self.success("Valid")
            } else {
                self.error("Invalid")
            };
            output.push(format!("    {}: {}", self.label("Status"), valid_status));

            if !cert.hostname_verified {
                output.push(format!(
                    "    {}",
                    self.error("WARNING: certificate hostname not verified")
                ));
            }

            output.push(format!(
                "    {}: {}",
                self.label("Valid From"),
                self.value(&cert.valid_from.format("%Y-%m-%d").to_string())
            ));

            let expiry_str = cert.valid_until.format("%Y-%m-%d").to_string();
            let expiry_display = if cert.days_until_expiry < 30 {
                self.error(&format!(
                    "{} ({} days!)",
                    expiry_str, cert.days_until_expiry
                ))
            } else if cert.days_until_expiry < 90 {
                self.warning(&format!("{} ({} days)", expiry_str, cert.days_until_expiry))
            } else {
                self.value(&format!("{} ({} days)", expiry_str, cert.days_until_expiry))
            };
            output.push(format!("    {}: {}", self.label("Expires"), expiry_display));
        } else {
            output.push(format!(
                "\n  {}: {}",
                self.label("SSL Certificate"),
                self.warning("Not available (HTTPS may not be configured)")
            ));
        }

        // CAA policy (issuance-time authorization for certificate authorities)
        if let Some(ref caa) = response.caa {
            output.extend(self.render_caa_block(caa, "  "));
        }

        // Domain Expiration
        if let Some(ref expiry) = response.domain_expiration {
            output.push(format!("\n  {}:", self.label("Domain Registration")));

            if let Some(ref registrar) = expiry.registrar {
                output.push(format!(
                    "    {}: {}",
                    self.label("Registrar"),
                    self.value(&sanitize_display(registrar))
                ));
            }

            let expiry_str = expiry.expiration_date.format("%Y-%m-%d").to_string();
            let expiry_display = if expiry.days_until_expiry < 30 {
                self.error(&format!(
                    "{} ({} days!)",
                    expiry_str, expiry.days_until_expiry
                ))
            } else if expiry.days_until_expiry < 90 {
                self.warning(&format!(
                    "{} ({} days)",
                    expiry_str, expiry.days_until_expiry
                ))
            } else {
                self.value(&format!(
                    "{} ({} days)",
                    expiry_str, expiry.days_until_expiry
                ))
            };
            output.push(format!("    {}: {}", self.label("Expires"), expiry_display));
        }

        // DNS Resolution
        if let Some(ref dns) = response.dns_resolution {
            output.push(format!("\n  {}:", self.label("DNS Resolution")));

            // Status line
            if dns.resolves {
                output.push(format!("    {}", self.success("✓ Resolving")));
            } else {
                output.push(format!("    {}", self.error("✗ Domain does not resolve")));
            }

            // CNAME if present
            if let Some(ref cname) = dns.cname_target {
                output.push(format!(
                    "    {}: Aliases to {}",
                    self.label("CNAME"),
                    self.success(&sanitize_display(cname))
                ));
            }

            // IPv4 addresses (A records)
            if !dns.a_records.is_empty() {
                output.push(format!("    {}:", self.label("IPv4 (A)")));
                for ip in &dns.a_records {
                    output.push(format!("      • {}", self.value(&sanitize_display(ip))));
                }
            }

            // IPv6 addresses (AAAA records)
            if !dns.aaaa_records.is_empty() {
                output.push(format!("    {}:", self.label("IPv6 (AAAA)")));
                for ip in &dns.aaaa_records {
                    output.push(format!("      • {}", self.value(&sanitize_display(ip))));
                }
            }

            // Nameservers
            if !dns.nameservers.is_empty() {
                output.push(format!("    {}:", self.label("Nameservers")));
                for ns in &dns.nameservers {
                    output.push(format!("      • {}", self.value(&sanitize_display(ns))));
                }
            }
        } else {
            output.push(format!(
                "\n  {}: {}",
                self.label("DNS Resolution"),
                self.warning("Check failed")
            ));
        }

        // CAA note sits at the very bottom of the whole status output,
        // un-indented, with a blank separator line.
        if let Some(ref caa) = response.caa {
            self.push_caa_note_footer(&mut output, caa);
        }

        output.join("\n")
    }

    fn format_follow_iteration(&self, iteration: &FollowIteration) -> String {
        let mut output = Vec::new();

        let time_str = iteration.timestamp.format("%H:%M:%S").to_string();
        let iter_str = format!(
            "Iteration {}/{}",
            iteration.iteration, iteration.total_iterations
        );

        if let Some(ref error) = iteration.error {
            output.push(format!(
                "[{}] {}: {}",
                self.label(&time_str),
                iter_str,
                self.error(error)
            ));
            return output.join("\n");
        }

        let record_count = iteration.record_count();
        let status = if iteration.iteration == 1 {
            "".to_string()
        } else if iteration.changed {
            format!(" ({})", self.warning("CHANGED"))
        } else {
            format!(" ({})", self.success("unchanged"))
        };

        // Collect record values, trimming trailing dots
        let values: Vec<String> = iteration
            .records
            .iter()
            .map(|r| r.data.to_string().trim_end_matches('.').to_string())
            .collect();

        output.push(format!(
            "[{}] {}: {} record(s){}",
            self.label(&time_str),
            iter_str,
            record_count,
            status
        ));

        // Show records comma-separated on a single indented line
        if !values.is_empty() {
            output.push(format!("  {}", self.value(&values.join(", "))));
        }

        // Show changes if any
        if !iteration.added.is_empty() {
            for added in &iteration.added {
                let value = added.trim_end_matches('.');
                output.push(format!("  {} {}", self.success("+"), self.success(value)));
            }
        }
        if !iteration.removed.is_empty() {
            for removed in &iteration.removed {
                let value = removed.trim_end_matches('.');
                output.push(format!("  {} {}", self.error("-"), self.error(value)));
            }
        }

        output.join("\n")
    }

    fn format_follow(&self, result: &FollowResult) -> String {
        let mut output = Vec::new();

        output.push(self.header(&format!(
            "DNS Follow Complete: {} {}",
            result.domain, result.record_type
        )));

        // Summary
        output.push(format!(
            "  {}: {}/{}",
            self.label("Iterations completed"),
            result.completed_iterations(),
            result.iterations_requested
        ));

        if result.interrupted {
            output.push(format!(
                "  {}: {}",
                self.label("Status"),
                self.warning("Interrupted")
            ));
        }

        output.push(format!(
            "  {}: {}",
            self.label("Total changes detected"),
            if result.total_changes > 0 {
                self.warning(&result.total_changes.to_string())
            } else {
                self.success(&result.total_changes.to_string())
            }
        ));

        let duration = result.ended_at - result.started_at;
        output.push(format!(
            "  {}: {}",
            self.label("Duration"),
            self.value(&format_duration(duration))
        ));

        // Show iteration details
        if !result.iterations.is_empty() {
            output.push(format!("\n  {}:", self.label("Iteration Details")));
            for iteration in &result.iterations {
                let time_str = iteration.timestamp.format("%H:%M:%S").to_string();
                let status = if iteration.error.is_some() {
                    self.error("ERROR")
                } else if iteration.changed {
                    self.warning("CHANGED")
                } else if iteration.iteration == 1 {
                    self.value("initial")
                } else {
                    self.success("stable")
                };

                output.push(format!(
                    "    [{}] #{}: {} record(s) - {}",
                    time_str,
                    iteration.iteration,
                    iteration.record_count(),
                    status
                ));
            }
        }

        output.join("\n")
    }

    fn format_availability(&self, result: &crate::availability::AvailabilityResult) -> String {
        let mut output = Vec::new();

        let status = if result.available {
            self.success("AVAILABLE")
        } else {
            self.error("TAKEN")
        };
        output.push(format!("{}: {}", sanitize_display(&result.domain), status));
        let confidence_colored = match result.confidence.as_str() {
            "high" => self.success(&result.confidence),
            "medium" => self.warning(&result.confidence),
            _ => self.error(&result.confidence),
        };
        output.push(format!(
            "  {}: {}",
            self.label("Confidence"),
            confidence_colored
        ));
        output.push(format!(
            "  {}: {}",
            self.label("Method"),
            self.value(&sanitize_display(&result.method))
        ));
        if let Some(ref details) = result.details {
            // `details` in `decide_fallback` can interpolate raw `rdap_err`
            // / `whois_err` strings — those originate from third-party
            // servers and may contain ANSI escapes. Strip before display
            // matching every other value-rendering site in this formatter.
            output.push(format!(
                "  {}: {}",
                self.label("Details"),
                self.value(&sanitize_display(details))
            ));
        }

        output.join("\n")
    }

    fn format_dnssec(&self, report: &crate::dns::DnssecReport) -> String {
        let mut output = Vec::new();

        output.push(format!(
            "DNSSEC Report for {}",
            self.success(&sanitize_display(&report.domain))
        ));
        output.push(String::new());

        let status_colored = match report.status.as_str() {
            "secure" => self.success(&report.status),
            "insecure" | "partial" => self.warning(&report.status),
            _ => self.error(&report.status),
        };
        output.push(format!("  {}: {}", self.label("Status"), status_colored));
        let chain_colored = if report.chain_valid {
            self.success("valid")
        } else if report.has_ds_records && report.has_dnskey_records {
            self.error("invalid")
        } else {
            self.warning("n/a")
        };
        output.push(format!(
            "  {}: {}",
            self.label("Chain Valid"),
            chain_colored
        ));
        output.push(format!(
            "  {}: {}",
            self.label("Enabled"),
            self.value(&report.enabled.to_string())
        ));
        output.push(format!(
            "  {}: {}",
            self.label("DS Records"),
            self.value(&report.ds_records.len().to_string())
        ));
        output.push(format!(
            "  {}: {}",
            self.label("DNSKEY Records"),
            self.value(&report.dnskey_records.len().to_string())
        ));

        if !report.ds_records.is_empty() {
            output.push(String::new());
            output.push(format!("  {}:", self.label("DS Records")));
            for ds in &report.ds_records {
                let match_indicator = if ds.matched_key && ds.digest_verified {
                    self.success("\u{2713} verified")
                } else if ds.matched_key {
                    self.error("\u{2717} digest mismatch")
                } else {
                    self.error("\u{2717} no matching key")
                };
                output.push(format!(
                    "    Key Tag: {}, Algorithm: {} ({}), Digest: {} ({}) [{}]",
                    ds.key_tag,
                    ds.algorithm,
                    sanitize_display(&ds.algorithm_name),
                    ds.digest_type,
                    sanitize_display(&ds.digest_type_name),
                    match_indicator,
                ));
            }
        }

        if !report.dnskey_records.is_empty() {
            output.push(String::new());
            output.push(format!("  {}:", self.label("DNSKEY Records")));
            for key in &report.dnskey_records {
                let role = if key.is_ksk {
                    "KSK"
                } else if key.is_zsk {
                    "ZSK"
                } else {
                    "Other"
                };
                output.push(format!(
                    "    Key Tag: {}, Flags: {}, Role: {}, Algorithm: {} ({})",
                    key.key_tag,
                    key.flags,
                    role,
                    key.algorithm,
                    sanitize_display(&key.algorithm_name)
                ));
            }
        }

        if !report.issues.is_empty() {
            output.push(String::new());
            output.push(format!("  {}:", self.label("Issues")));
            for issue in &report.issues {
                output.push(format!("    - {}", sanitize_display(issue)));
            }
        }

        output.join("\n")
    }

    fn format_tld(&self, info: &crate::tld::TldInfo) -> String {
        let mut output = Vec::new();

        output.push(self.header(&format!("TLD Info: .{}", info.tld)));

        output.push(format!(
            "  {}: {}",
            self.label("Type"),
            self.value(&info.tld_type)
        ));

        if let Some(ref server) = info.whois_server {
            output.push(format!(
                "  {}: {}",
                self.label("WHOIS Server"),
                self.value(server)
            ));
        } else {
            output.push(format!(
                "  {}: {}",
                self.label("WHOIS Server"),
                self.warning("not available")
            ));
        }

        if let Some(ref url) = info.rdap_url {
            output.push(format!("  {}: {}", self.label("RDAP URL"), self.value(url)));
        } else {
            output.push(format!(
                "  {}: {}",
                self.label("RDAP URL"),
                self.warning("not available")
            ));
        }

        if let Some(ref url) = info.registry_url {
            output.push(format!("  {}: {}", self.label("Registry"), self.value(url)));
        } else {
            output.push(format!(
                "  {}: {}",
                self.label("Registry"),
                self.warning("not available")
            ));
        }

        output.join("\n")
    }

    fn format_dns_comparison(&self, comparison: &crate::dns::DnsComparison) -> String {
        let mut output = Vec::new();

        output.push(self.header(&format!(
            "DNS Comparison: {} {}",
            comparison.domain, comparison.record_type
        )));

        // Match status
        if comparison.matches {
            output.push(format!("  {} Records match", self.success("✓")));
        } else {
            output.push(format!("  {} Records differ", self.error("✗")));
        }
        output.push(String::new());

        // Server A
        if let Some(ref err) = comparison.server_a.error {
            output.push(format!(
                "  {} ({}): {}",
                self.label("Server A"),
                self.value(&sanitize_display(&comparison.server_a.nameserver)),
                self.error(&sanitize_display(err))
            ));
        } else {
            output.push(format!(
                "  {} ({}): {} records",
                self.label("Server A"),
                self.value(&sanitize_display(&comparison.server_a.nameserver)),
                self.value(&comparison.server_a.records.len().to_string())
            ));
            for record in &comparison.server_a.records {
                output.push(format!(
                    "    - {}",
                    self.value(&sanitize_display(&record.format_short()))
                ));
            }
        }
        output.push(String::new());

        // Server B
        if let Some(ref err) = comparison.server_b.error {
            output.push(format!(
                "  {} ({}): {}",
                self.label("Server B"),
                self.value(&sanitize_display(&comparison.server_b.nameserver)),
                self.error(&sanitize_display(err))
            ));
        } else {
            output.push(format!(
                "  {} ({}): {} records",
                self.label("Server B"),
                self.value(&sanitize_display(&comparison.server_b.nameserver)),
                self.value(&comparison.server_b.records.len().to_string())
            ));
            for record in &comparison.server_b.records {
                output.push(format!(
                    "    - {}",
                    self.value(&sanitize_display(&record.format_short()))
                ));
            }
        }
        output.push(String::new());

        // Common records
        output.push(format!(
            "  {}: {}",
            self.label("Common"),
            if comparison.common.is_empty() {
                self.warning("(none)")
            } else {
                self.value(&sanitize_display(&comparison.common.join(", ")))
            }
        ));

        // Only in A
        output.push(format!(
            "  {}: {}",
            self.label(&format!(
                "Only in {}",
                sanitize_display(&comparison.server_a.nameserver)
            )),
            if comparison.only_in_a.is_empty() {
                self.warning("(none)")
            } else {
                self.error(&sanitize_display(&comparison.only_in_a.join(", ")))
            }
        ));

        // Only in B
        output.push(format!(
            "  {}: {}",
            self.label(&format!(
                "Only in {}",
                sanitize_display(&comparison.server_b.nameserver)
            )),
            if comparison.only_in_b.is_empty() {
                self.warning("(none)")
            } else {
                self.error(&sanitize_display(&comparison.only_in_b.join(", ")))
            }
        ));

        output.join("\n")
    }

    fn format_subdomains(&self, result: &crate::subdomains::SubdomainResult) -> String {
        let mut output = Vec::new();

        output.push(self.header(&format!("Subdomains: {}", sanitize_display(&result.domain))));

        output.push(format!(
            "  {}: {}",
            self.label("Source"),
            self.value(&sanitize_display(&result.source))
        ));
        output.push(format!(
            "  {}: {}",
            self.label("Count"),
            self.value(&result.count.to_string())
        ));

        if result.subdomains.is_empty() {
            output.push(format!("  {}", self.warning("No subdomains found")));
        } else {
            output.push(String::new());
            for subdomain in &result.subdomains {
                output.push(format!(
                    "    - {}",
                    self.value(&sanitize_display(subdomain))
                ));
            }
        }

        output.join("\n")
    }

    fn format_diff(&self, diff: &crate::diff::DomainDiff) -> String {
        let mut output = Vec::new();

        output.push(self.header(&format!(
            "Diff: {} vs {}",
            sanitize_display(&diff.domain_a),
            sanitize_display(&diff.domain_b)
        )));

        let domain_a = sanitize_display(&diff.domain_a);
        let domain_b = sanitize_display(&diff.domain_b);
        let sections = build_diff_sections(diff);
        let col_width = compute_column_width(&sections, &domain_a, &domain_b);

        // Label gutter width: max of all field labels (not section titles).
        let label_width = sections
            .iter()
            .flat_map(|s| s.rows.iter().map(|r| r.label.chars().count()))
            .max()
            .unwrap_or(0);

        // Indents and gutters
        let label_indent = "    "; // 4 spaces inside section
        let section_indent = "  "; // 2 spaces before section title
        let marker_gutter_width = 2; // "= " or "≠ "
                                     // Between label cell and marker: 2 spaces (inter-column gap).
                                     // Marker cell: "= " or "≠ " = 2 chars.
                                     // Total left pad before value column A = label_indent + label_width + 2 + 2.
        let header_left_pad = label_indent.chars().count() + label_width + 2 + marker_gutter_width;

        // Column header block
        let header_line = format!(
            "{}{}   {}",
            " ".repeat(header_left_pad),
            self.label(&pad_right(&domain_a, col_width)),
            self.label(&domain_b)
        );
        let rule_a: String = "─".repeat(domain_a.chars().count());
        let rule_b: String = "─".repeat(domain_b.chars().count());
        let rule_line = format!(
            "{}{}   {}",
            " ".repeat(header_left_pad),
            self.label(&pad_right(&rule_a, col_width)),
            self.label(&rule_b)
        );
        output.push(String::new());
        output.push(header_line);
        output.push(rule_line);

        for section in &sections {
            output.push(String::new());
            output.push(format!("{}{}", section_indent, self.label(section.title)));

            for row in &section.rows {
                // Wrap each value column independently.
                let mut a_lines: Vec<String> = row
                    .a_values
                    .iter()
                    .flat_map(|v| wrap_cell(&sanitize_display(v), col_width))
                    .collect();
                let mut b_lines: Vec<String> = row
                    .b_values
                    .iter()
                    .flat_map(|v| wrap_cell(&sanitize_display(v), col_width))
                    .collect();

                // Pad the shorter list with blank lines so rows align.
                let rows_needed = a_lines.len().max(b_lines.len()).max(1);
                while a_lines.len() < rows_needed {
                    a_lines.push(String::new());
                }
                while b_lines.len() < rows_needed {
                    b_lines.push(String::new());
                }

                let marker_glyph = if row.matches { "=" } else { "≠" };
                let color = |s: &str| -> String {
                    if row.matches {
                        self.success(s)
                    } else {
                        self.error(s)
                    }
                };

                for (i, (a, b)) in a_lines.iter().zip(b_lines.iter()).enumerate() {
                    let label_cell = if i == 0 {
                        format!("{}{}", label_indent, pad_right(row.label, label_width))
                    } else {
                        format!("{}{}", label_indent, " ".repeat(label_width))
                    };
                    let marker_cell = if i == 0 {
                        format!("{} ", color(marker_glyph))
                    } else {
                        "  ".to_string()
                    };
                    let color_value = |s: &str, raw: &str| -> String {
                        if raw.trim() == EMPTY_PLACEHOLDER {
                            self.dim(s)
                        } else {
                            color(s)
                        }
                    };
                    let a_cell = color_value(&pad_right(a, col_width), a);
                    let b_cell = color_value(b, b);
                    output.push(format!(
                        "{}  {}{}   {}",
                        self.label(&label_cell),
                        marker_cell,
                        a_cell,
                        b_cell
                    ));
                }
            }
        }

        output.join("\n")
    }

    fn format_ssl(&self, report: &crate::ssl::SslReport) -> String {
        let mut output = Vec::new();

        output.push(self.header(&format!("SSL Report: {}", sanitize_display(&report.domain))));

        output.push(format!(
            "  {}: {}",
            self.label("Valid"),
            if report.is_valid {
                self.success("yes")
            } else {
                self.error("no")
            }
        ));
        output.push(format!(
            "  {}: {}",
            self.label("Days Until Expiry"),
            self.value(&report.days_until_expiry.to_string())
        ));

        if let Some(ref proto) = report.protocol_version {
            output.push(format!(
                "  {}: {}",
                self.label("Protocol"),
                self.value(&sanitize_display(proto))
            ));
        }

        if !report.san_names.is_empty() {
            let sanitized_sans: Vec<String> = report
                .san_names
                .iter()
                .map(|s| sanitize_display(s))
                .collect();
            output.push(format!(
                "  {}: {}",
                self.label("SANs"),
                self.value(&sanitized_sans.join(", "))
            ));
        }

        if !report.chain.is_empty() {
            output.push(String::new());
            output.push(format!("  {}:", self.label("Certificate Chain")));
            for (i, cert) in report.chain.iter().enumerate() {
                output.push(format!(
                    "    [{}] {}",
                    i,
                    self.value(&sanitize_display(&cert.subject))
                ));
                output.push(format!(
                    "        {}: {}",
                    self.label("Issuer"),
                    self.value(&sanitize_display(&cert.issuer))
                ));
                if let Some(ref alg) = cert.signature_algorithm {
                    output.push(format!(
                        "        {}: {}",
                        self.label("Algorithm"),
                        self.value(&sanitize_display(alg))
                    ));
                }
                if let Some(ref key_type) = cert.key_type {
                    let key_info = if let Some(bits) = cert.key_bits {
                        format!("{} ({} bits)", sanitize_display(key_type), bits)
                    } else {
                        sanitize_display(key_type)
                    };
                    output.push(format!(
                        "        {}: {}",
                        self.label("Key"),
                        self.value(&key_info)
                    ));
                }
                output.push(format!(
                    "        {}: {} to {}",
                    self.label("Validity"),
                    self.value(&cert.valid_from.format("%Y-%m-%d").to_string()),
                    self.value(&cert.valid_until.format("%Y-%m-%d").to_string())
                ));
            }
        }

        if let Some(ref caa) = report.caa {
            output.extend(self.render_caa_block(caa, "  "));
            self.push_caa_note_footer(&mut output, caa);
        }

        output.join("\n")
    }

    fn format_watch(&self, report: &crate::watchlist::WatchReport) -> String {
        let mut output = Vec::new();

        output.push(self.header("Domain Watch Report"));

        output.push(format!(
            "  {}: {}",
            self.label("Checked"),
            self.value(
                &report
                    .checked_at
                    .format("%Y-%m-%d %H:%M:%S UTC")
                    .to_string()
            )
        ));
        output.push(format!(
            "  {}: {} domains, {} warnings",
            self.label("Total"),
            self.value(&report.total.to_string()),
            if report.warnings > 0 {
                self.warning(&report.warnings.to_string())
            } else {
                self.value(&report.warnings.to_string())
            }
        ));

        for r in &report.results {
            output.push(String::new());

            let icon = if r.issues.is_empty() {
                self.success("v")
            } else {
                self.warning("!")
            };
            output.push(format!(
                "  {} {}",
                icon,
                self.value(&sanitize_display(&r.domain))
            ));

            // Condensed status line: SSL | Domain | HTTP
            let ssl_str = r
                .ssl_days_remaining
                .map(|d| format!("{} days", d))
                .unwrap_or_else(|| "N/A".to_string());
            let dom_str = r
                .domain_days_remaining
                .map(|d| format!("{} days", d))
                .unwrap_or_else(|| "N/A".to_string());
            let http_str = r
                .http_status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "N/A".to_string());

            output.push(format!(
                "      {}: {} | {}: {} | {}: {}",
                self.label("SSL"),
                self.value(&ssl_str),
                self.label("Domain"),
                self.value(&dom_str),
                self.label("HTTP"),
                self.value(&http_str)
            ));

            if !r.issues.is_empty() {
                output.push(format!("      {}:", self.label("Issues")));
                for issue in &r.issues {
                    output.push(format!(
                        "        - {}",
                        self.warning(&sanitize_display(issue))
                    ));
                }
            }
        }

        output.join("\n")
    }

    fn format_domain_info(&self, info: &crate::domain_info::DomainInfo) -> String {
        let mut output = Vec::new();

        let source_str = match info.source {
            crate::domain_info::DomainInfoSource::Both => "both",
            crate::domain_info::DomainInfoSource::Rdap => "rdap",
            crate::domain_info::DomainInfoSource::Whois => "whois",
            crate::domain_info::DomainInfoSource::Available => "available",
        };

        output.push(self.header(&format!(
            "Domain Info: {} (source: {})",
            sanitize_display(&info.domain),
            source_str
        )));

        if let Some(verdict) = &info.availability_verdict {
            let colored = match verdict.as_str() {
                "available" => self.success("AVAILABLE"),
                "likely_available" => self.warning("MAY BE AVAILABLE"),
                "registered" => self.value("REGISTERED"),
                "likely_registered" => self.warning("LIKELY REGISTERED"),
                _ => self.error("UNKNOWN"),
            };
            output.push(format!("  {}: {}", self.label("Status"), colored));
        }

        // Registration
        if let Some(ref registrar) = info.registrar {
            output.push(format!(
                "  {}: {}",
                self.label("Registrar"),
                self.value(&sanitize_display(registrar))
            ));
        }
        if let Some(ref registrant) = info.registrant {
            output.push(format!(
                "  {}: {}",
                self.label("Registrant"),
                self.value(&sanitize_display(registrant))
            ));
        }
        if let Some(ref organization) = info.organization {
            output.push(format!(
                "  {}: {}",
                self.label("Organization"),
                self.value(&sanitize_display(organization))
            ));
        }

        // Dates
        if let Some(ref created) = info.creation_date {
            output.push(format!(
                "  {}: {}",
                self.label("Created"),
                self.value(&created.format("%Y-%m-%d").to_string())
            ));
        }
        if let Some(ref expires) = info.expiration_date {
            output.push(format!(
                "  {}: {}",
                self.label("Expires"),
                self.value(&expires.format("%Y-%m-%d").to_string())
            ));
        }
        if let Some(ref updated) = info.updated_date {
            output.push(format!(
                "  {}: {}",
                self.label("Updated"),
                self.value(&updated.format("%Y-%m-%d").to_string())
            ));
        }

        // DNS
        if !info.nameservers.is_empty() {
            output.push(format!(
                "  {}: {}",
                self.label("Nameservers"),
                self.value(&info.nameservers.join(", "))
            ));
        }
        if !info.status.is_empty() {
            output.push(format!(
                "  {}: {}",
                self.label("Status"),
                self.value(&info.status.join(", "))
            ));
        }
        if let Some(ref dnssec) = info.dnssec {
            output.push(format!(
                "  {}: {}",
                self.label("DNSSEC"),
                self.value(&sanitize_display(dnssec))
            ));
        }

        // Registrant Contact
        let has_registrant_contact = info.registrant_email.is_some()
            || info.registrant_phone.is_some()
            || info.registrant_address.is_some()
            || info.registrant_country.is_some();
        if has_registrant_contact {
            output.push(format!("\n  {}:", self.label("Registrant Contact")));
            if let Some(ref email) = info.registrant_email {
                output.push(format!(
                    "    {}: {}",
                    self.label("Email"),
                    self.value(&sanitize_display(email))
                ));
            }
            if let Some(ref phone) = info.registrant_phone {
                output.push(format!(
                    "    {}: {}",
                    self.label("Phone"),
                    self.value(&sanitize_display(phone))
                ));
            }
            if let Some(ref address) = info.registrant_address {
                output.push(format!(
                    "    {}: {}",
                    self.label("Address"),
                    self.value(&sanitize_display(address))
                ));
            }
            if let Some(ref country) = info.registrant_country {
                output.push(format!(
                    "    {}: {}",
                    self.label("Country"),
                    self.value(&sanitize_display(country))
                ));
            }
        }

        // Admin Contact
        let has_admin_contact = info.admin_name.is_some()
            || info.admin_organization.is_some()
            || info.admin_email.is_some()
            || info.admin_phone.is_some();
        if has_admin_contact {
            output.push(format!("\n  {}:", self.label("Admin Contact")));
            if let Some(ref name) = info.admin_name {
                output.push(format!(
                    "    {}: {}",
                    self.label("Name"),
                    self.value(&sanitize_display(name))
                ));
            }
            if let Some(ref org) = info.admin_organization {
                output.push(format!(
                    "    {}: {}",
                    self.label("Organization"),
                    self.value(&sanitize_display(org))
                ));
            }
            if let Some(ref email) = info.admin_email {
                output.push(format!(
                    "    {}: {}",
                    self.label("Email"),
                    self.value(&sanitize_display(email))
                ));
            }
            if let Some(ref phone) = info.admin_phone {
                output.push(format!(
                    "    {}: {}",
                    self.label("Phone"),
                    self.value(&sanitize_display(phone))
                ));
            }
        }

        // Tech Contact
        let has_tech_contact = info.tech_name.is_some()
            || info.tech_organization.is_some()
            || info.tech_email.is_some()
            || info.tech_phone.is_some();
        if has_tech_contact {
            output.push(format!("\n  {}:", self.label("Tech Contact")));
            if let Some(ref name) = info.tech_name {
                output.push(format!(
                    "    {}: {}",
                    self.label("Name"),
                    self.value(&sanitize_display(name))
                ));
            }
            if let Some(ref org) = info.tech_organization {
                output.push(format!(
                    "    {}: {}",
                    self.label("Organization"),
                    self.value(&sanitize_display(org))
                ));
            }
            if let Some(ref email) = info.tech_email {
                output.push(format!(
                    "    {}: {}",
                    self.label("Email"),
                    self.value(&sanitize_display(email))
                ));
            }
            if let Some(ref phone) = info.tech_phone {
                output.push(format!(
                    "    {}: {}",
                    self.label("Phone"),
                    self.value(&sanitize_display(phone))
                ));
            }
        }

        // Protocol Metadata
        let has_metadata = info.whois_server.is_some() || info.rdap_url.is_some();
        if has_metadata {
            output.push(format!("\n  {}:", self.label("Protocol Metadata")));
            if let Some(ref whois_server) = info.whois_server {
                output.push(format!(
                    "    {}: {}",
                    self.label("WHOIS Server"),
                    self.value(&sanitize_display(whois_server))
                ));
            }
            if let Some(ref rdap_url) = info.rdap_url {
                output.push(format!(
                    "    {}: {}",
                    self.label("RDAP URL"),
                    self.value(&sanitize_display(rdap_url))
                ));
            }
        }

        output.join("\n")
    }
}

/// Compares two `Option<String>` values for equality after trimming whitespace.
/// Empty-after-trim is treated as `None`.
fn eq_opt_str_trimmed(a: &Option<String>, b: &Option<String>) -> bool {
    let norm = |o: &Option<String>| -> Option<String> {
        o.as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    norm(a) == norm(b)
}

/// Compares two string lists as sets: trims each item, drops empty items,
/// then checks that the sorted multisets are equal.
fn eq_as_set(a: &[String], b: &[String]) -> bool {
    let mut an: Vec<String> = a
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let mut bn: Vec<String> = b
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    an.sort();
    bn.sort();
    an == bn
}

/// Wraps `text` into lines no wider than `max_width` display chars.
/// Breaks at the last ASCII whitespace within the window when possible;
/// otherwise hard-breaks at the cap. Widths are measured in `chars().count()`
/// which is correct for ASCII and a reasonable fallback for other inputs.
fn wrap_cell(text: &str, max_width: usize) -> Vec<String> {
    let width = max_width.max(1);
    if text.is_empty() {
        return vec![String::new()];
    }

    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= width {
        return vec![text.to_string()];
    }

    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let remaining = chars.len() - i;
        if remaining <= width {
            out.push(chars[i..].iter().collect());
            break;
        }
        // Search for last whitespace in chars[i .. i+width]
        let window_end = i + width;
        let break_at = (i..window_end).rev().find(|&k| chars[k].is_whitespace());
        match break_at {
            Some(k) if k > i => {
                out.push(chars[i..k].iter().collect());
                i = k + 1; // skip the whitespace itself
            }
            _ => {
                // No whitespace in window (or whitespace at index i): hard break.
                out.push(chars[i..window_end].iter().collect());
                i = window_end;
            }
        }
    }

    out
}

/// One labeled row in the rendered diff table. `a_values` / `b_values` each
/// hold one item per rendered line — scalars are single-element; multi-value
/// fields (A records, nameservers) hold one entry per item.
struct DiffRow {
    label: &'static str,
    a_values: Vec<String>,
    b_values: Vec<String>,
    matches: bool,
}

struct DiffSection {
    title: &'static str,
    rows: Vec<DiffRow>,
}

/// The placeholder rendered for `None` or empty values.
const EMPTY_PLACEHOLDER: &str = "—";

fn opt_or_placeholder(o: &Option<String>) -> String {
    o.as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| EMPTY_PLACEHOLDER.to_string())
}

fn opt_i64_or_placeholder(o: &Option<i64>) -> String {
    o.map(|n| n.to_string())
        .unwrap_or_else(|| EMPTY_PLACEHOLDER.to_string())
}

fn opt_bool_or_placeholder(o: &Option<bool>) -> String {
    match o {
        Some(true) => "yes".to_string(),
        Some(false) => "no".to_string(),
        None => EMPTY_PLACEHOLDER.to_string(),
    }
}

fn bool_as_str(b: bool) -> String {
    if b {
        "yes".to_string()
    } else {
        "no".to_string()
    }
}

fn list_or_placeholder(list: &[String]) -> Vec<String> {
    let cleaned: Vec<String> = list
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if cleaned.is_empty() {
        vec![EMPTY_PLACEHOLDER.to_string()]
    } else {
        cleaned
    }
}

fn build_diff_sections(diff: &crate::diff::DomainDiff) -> Vec<DiffSection> {
    let reg = &diff.registration;
    let dns = &diff.dns;
    let ssl = &diff.ssl;

    let registration = DiffSection {
        title: "Registration",
        rows: vec![
            DiffRow {
                label: "Registrar",
                a_values: vec![opt_or_placeholder(&reg.registrar.0)],
                b_values: vec![opt_or_placeholder(&reg.registrar.1)],
                matches: eq_opt_str_trimmed(&reg.registrar.0, &reg.registrar.1),
            },
            DiffRow {
                label: "Organization",
                a_values: vec![opt_or_placeholder(&reg.organization.0)],
                b_values: vec![opt_or_placeholder(&reg.organization.1)],
                matches: eq_opt_str_trimmed(&reg.organization.0, &reg.organization.1),
            },
            DiffRow {
                label: "Created",
                a_values: vec![opt_or_placeholder(&reg.created.0)],
                b_values: vec![opt_or_placeholder(&reg.created.1)],
                matches: eq_opt_str_trimmed(&reg.created.0, &reg.created.1),
            },
            DiffRow {
                label: "Expires",
                a_values: vec![opt_or_placeholder(&reg.expires.0)],
                b_values: vec![opt_or_placeholder(&reg.expires.1)],
                matches: eq_opt_str_trimmed(&reg.expires.0, &reg.expires.1),
            },
        ],
    };

    let dns_section = DiffSection {
        title: "DNS",
        rows: vec![
            DiffRow {
                label: "Resolves",
                a_values: vec![bool_as_str(dns.resolves.0)],
                b_values: vec![bool_as_str(dns.resolves.1)],
                matches: dns.resolves.0 == dns.resolves.1,
            },
            DiffRow {
                label: "A Records",
                a_values: list_or_placeholder(&dns.a_records.0),
                b_values: list_or_placeholder(&dns.a_records.1),
                matches: eq_as_set(&dns.a_records.0, &dns.a_records.1),
            },
            DiffRow {
                label: "Nameservers",
                a_values: list_or_placeholder(&dns.nameservers.0),
                b_values: list_or_placeholder(&dns.nameservers.1),
                matches: eq_as_set(&dns.nameservers.0, &dns.nameservers.1),
            },
        ],
    };

    let ssl_section = DiffSection {
        title: "SSL",
        rows: vec![
            DiffRow {
                label: "Issuer",
                a_values: vec![opt_or_placeholder(&ssl.issuer.0)],
                b_values: vec![opt_or_placeholder(&ssl.issuer.1)],
                matches: eq_opt_str_trimmed(&ssl.issuer.0, &ssl.issuer.1),
            },
            DiffRow {
                label: "Valid Until",
                a_values: vec![opt_or_placeholder(&ssl.valid_until.0)],
                b_values: vec![opt_or_placeholder(&ssl.valid_until.1)],
                matches: eq_opt_str_trimmed(&ssl.valid_until.0, &ssl.valid_until.1),
            },
            DiffRow {
                label: "Days Remaining",
                a_values: vec![opt_i64_or_placeholder(&ssl.days_remaining.0)],
                b_values: vec![opt_i64_or_placeholder(&ssl.days_remaining.1)],
                matches: ssl.days_remaining.0 == ssl.days_remaining.1,
            },
            DiffRow {
                label: "Valid",
                a_values: vec![opt_bool_or_placeholder(&ssl.is_valid.0)],
                b_values: vec![opt_bool_or_placeholder(&ssl.is_valid.1)],
                matches: ssl.is_valid.0 == ssl.is_valid.1,
            },
        ],
    };

    vec![registration, dns_section, ssl_section]
}

/// Hard cap on a single value column (applies before wrapping).
const DIFF_COLUMN_CAP: usize = 40;

/// Computes the shared width for both value columns: the widest item across
/// every row of every section plus the two domain-header lengths, capped at
/// `DIFF_COLUMN_CAP`.
fn compute_column_width(sections: &[DiffSection], domain_a: &str, domain_b: &str) -> usize {
    let mut widest = domain_a.chars().count().max(domain_b.chars().count());
    for section in sections {
        for row in &section.rows {
            for v in row.a_values.iter().chain(row.b_values.iter()) {
                widest = widest.max(v.chars().count());
            }
        }
    }
    widest.clamp(1, DIFF_COLUMN_CAP)
}

/// Right-pads `text` with spaces to `width` display chars. Never truncates.
fn pad_right(text: &str, width: usize) -> String {
    let have = text.chars().count();
    if have >= width {
        text.to_string()
    } else {
        format!("{}{}", text, " ".repeat(width - have))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::{DnsDiff, DomainDiff, RegistrationDiff, SslDiff};

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

    #[test]
    fn eq_opt_str_trims_whitespace() {
        assert!(eq_opt_str_trimmed(
            &Some("  foo  ".to_string()),
            &Some("foo".to_string())
        ));
        assert!(!eq_opt_str_trimmed(
            &Some("foo".to_string()),
            &Some("bar".to_string())
        ));
    }

    #[test]
    fn eq_opt_str_both_none_matches() {
        assert!(eq_opt_str_trimmed(&None, &None));
    }

    #[test]
    fn eq_opt_str_empty_string_is_none() {
        assert!(eq_opt_str_trimmed(&None, &Some("".to_string())));
        assert!(eq_opt_str_trimmed(&Some("   ".to_string()), &None));
    }

    #[test]
    fn eq_opt_str_some_vs_none_differs() {
        assert!(!eq_opt_str_trimmed(&Some("foo".to_string()), &None));
    }

    #[test]
    fn eq_as_set_order_independent() {
        let a = vec!["ns1".to_string(), "ns2".to_string()];
        let b = vec!["ns2".to_string(), "ns1".to_string()];
        assert!(eq_as_set(&a, &b));
    }

    #[test]
    fn eq_as_set_trims_and_drops_empty() {
        let a = vec!["ns1".to_string(), "  ".to_string(), " ns2 ".to_string()];
        let b = vec!["ns2".to_string(), "ns1".to_string()];
        assert!(eq_as_set(&a, &b));
    }

    #[test]
    fn eq_as_set_different_contents() {
        let a = vec!["1.2.3.4".to_string()];
        let b = vec!["1.2.3.5".to_string()];
        assert!(!eq_as_set(&a, &b));
    }

    #[test]
    fn eq_as_set_both_empty_matches() {
        let a: Vec<String> = vec![];
        let b: Vec<String> = vec![];
        assert!(eq_as_set(&a, &b));
    }

    #[test]
    fn wrap_cell_short_returns_single_line() {
        assert_eq!(wrap_cell("hello", 10), vec!["hello".to_string()]);
    }

    #[test]
    fn wrap_cell_wraps_at_word_boundary() {
        let out = wrap_cell("the quick brown fox", 10);
        assert_eq!(out, vec!["the quick".to_string(), "brown fox".to_string()]);
    }

    #[test]
    fn wrap_cell_hard_breaks_when_no_whitespace() {
        // A long nameserver with no break points must hard-break at the cap.
        let out = wrap_cell("a.very.long.nameserver.example", 10);
        assert_eq!(
            out,
            vec![
                "a.very.lon".to_string(),
                "g.nameserv".to_string(),
                "er.example".to_string(),
            ]
        );
    }

    #[test]
    fn wrap_cell_exact_width_no_wrap() {
        assert_eq!(wrap_cell("1234567890", 10), vec!["1234567890".to_string()]);
    }

    #[test]
    fn wrap_cell_empty_input_returns_one_empty_line() {
        assert_eq!(wrap_cell("", 10), vec!["".to_string()]);
    }

    #[test]
    fn wrap_cell_zero_width_treated_as_one() {
        // Defensive: never loop forever on width 0. Caller must not pass 0, but
        // we clamp to 1 to be safe.
        let out = wrap_cell("abc", 0);
        assert_eq!(out, vec!["a".to_string(), "b".to_string(), "c".to_string()]);
    }

    fn make_sample_diff() -> DomainDiff {
        DomainDiff {
            domain_a: "example.com".to_string(),
            domain_b: "google.com".to_string(),
            registration: RegistrationDiff {
                registrar: (Some("IANA".to_string()), Some("MarkMonitor".to_string())),
                organization: (None, Some("Google LLC".to_string())),
                created: (
                    Some("1995-08-14".to_string()),
                    Some("1997-09-15".to_string()),
                ),
                expires: (
                    Some("2026-08-13".to_string()),
                    Some("2028-09-14".to_string()),
                ),
            },
            dns: DnsDiff {
                a_records: (
                    vec!["93.184.216.34".to_string()],
                    vec!["142.250.185.46".to_string()],
                ),
                nameservers: (
                    vec!["ns1.example".to_string(), "ns2.example".to_string()],
                    vec!["ns2.example".to_string(), "ns1.example".to_string()],
                ),
                resolves: (true, true),
            },
            ssl: SslDiff {
                issuer: (
                    Some("DigiCert".to_string()),
                    Some("Google Trust".to_string()),
                ),
                valid_until: (
                    Some("2025-03-01".to_string()),
                    Some("2025-02-15".to_string()),
                ),
                days_remaining: (Some(89), Some(75)),
                is_valid: (Some(true), Some(true)),
            },
        }
    }

    #[test]
    fn build_diff_sections_produces_three_sections() {
        let diff = make_sample_diff();
        let sections = build_diff_sections(&diff);
        assert_eq!(sections.len(), 3);
        assert_eq!(sections[0].title, "Registration");
        assert_eq!(sections[1].title, "DNS");
        assert_eq!(sections[2].title, "SSL");
    }

    #[test]
    fn build_diff_sections_marks_nameservers_as_match_when_sets_equal() {
        let diff = make_sample_diff();
        let sections = build_diff_sections(&diff);
        let dns = &sections[1];
        let ns_row = dns.rows.iter().find(|r| r.label == "Nameservers").unwrap();
        assert!(ns_row.matches, "reversed-order nameservers should match");
    }

    #[test]
    fn build_diff_sections_marks_registrar_differ() {
        let diff = make_sample_diff();
        let sections = build_diff_sections(&diff);
        let reg = &sections[0];
        let row = reg.rows.iter().find(|r| r.label == "Registrar").unwrap();
        assert!(!row.matches);
    }

    #[test]
    fn build_diff_sections_marks_resolves_match_when_both_true() {
        let diff = make_sample_diff();
        let sections = build_diff_sections(&diff);
        let dns = &sections[1];
        let row = dns.rows.iter().find(|r| r.label == "Resolves").unwrap();
        assert!(row.matches);
        assert_eq!(row.a_values, vec!["yes".to_string()]);
        assert_eq!(row.b_values, vec!["yes".to_string()]);
    }

    #[test]
    fn build_diff_sections_renders_none_as_em_dash() {
        let diff = make_sample_diff();
        let sections = build_diff_sections(&diff);
        let reg = &sections[0];
        let row = reg.rows.iter().find(|r| r.label == "Organization").unwrap();
        assert_eq!(row.a_values, vec!["—".to_string()]);
    }

    #[test]
    fn build_diff_sections_a_records_one_item_per_row() {
        let mut diff = make_sample_diff();
        diff.dns.a_records = (
            vec!["1.1.1.1".to_string(), "2.2.2.2".to_string()],
            vec!["3.3.3.3".to_string()],
        );
        let sections = build_diff_sections(&diff);
        let dns = &sections[1];
        let row = dns.rows.iter().find(|r| r.label == "A Records").unwrap();
        assert_eq!(row.a_values.len(), 2);
        assert_eq!(row.b_values.len(), 1);
    }

    #[test]
    fn build_diff_sections_preserves_field_order() {
        let diff = make_sample_diff();
        let sections = build_diff_sections(&diff);
        let labels: Vec<&str> = sections[0].rows.iter().map(|r| r.label).collect();
        assert_eq!(
            labels,
            vec!["Registrar", "Organization", "Created", "Expires"]
        );
        let dns_labels: Vec<&str> = sections[1].rows.iter().map(|r| r.label).collect();
        assert_eq!(dns_labels, vec!["Resolves", "A Records", "Nameservers"]);
        let ssl_labels: Vec<&str> = sections[2].rows.iter().map(|r| r.label).collect();
        assert_eq!(
            ssl_labels,
            vec!["Issuer", "Valid Until", "Days Remaining", "Valid"]
        );
    }

    #[test]
    fn compute_column_width_uses_widest_value_across_sections() {
        let sections = vec![DiffSection {
            title: "Registration",
            rows: vec![
                DiffRow {
                    label: "Registrar",
                    a_values: vec!["IANA".to_string()],
                    b_values: vec!["MarkMonitor".to_string()],
                    matches: false,
                },
                DiffRow {
                    label: "Organization",
                    a_values: vec!["—".to_string()],
                    b_values: vec!["Google LLC".to_string()],
                    matches: false,
                },
            ],
        }];
        // Widest item is "MarkMonitor" (11).
        assert_eq!(compute_column_width(&sections, "a.com", "b.com"), 11);
    }

    #[test]
    fn compute_column_width_respects_domain_width() {
        let sections = vec![DiffSection {
            title: "Registration",
            rows: vec![DiffRow {
                label: "Registrar",
                a_values: vec!["x".to_string()],
                b_values: vec!["y".to_string()],
                matches: false,
            }],
        }];
        // Domain "very-long-domain.example" is wider than any value.
        let w = compute_column_width(&sections, "very-long-domain.example", "b.com");
        assert_eq!(w, "very-long-domain.example".chars().count());
    }

    #[test]
    fn compute_column_width_caps_at_40() {
        let long_value = "x".repeat(100);
        let sections = vec![DiffSection {
            title: "Registration",
            rows: vec![DiffRow {
                label: "Registrar",
                a_values: vec![long_value],
                b_values: vec!["y".to_string()],
                matches: false,
            }],
        }];
        assert_eq!(compute_column_width(&sections, "a.com", "b.com"), 40);
    }

    #[test]
    fn compute_column_width_minimum_sensible_default() {
        // Even with tiny inputs, width should not be zero.
        let sections = vec![DiffSection {
            title: "Registration",
            rows: vec![DiffRow {
                label: "X",
                a_values: vec!["a".to_string()],
                b_values: vec!["b".to_string()],
                matches: true,
            }],
        }];
        let w = compute_column_width(&sections, "a", "b");
        assert!(w >= 1);
    }

    fn diff_formatter() -> HumanFormatter {
        HumanFormatter::new().without_colors()
    }

    #[test]
    fn format_diff_shows_column_headers_with_domain_names() {
        let f = diff_formatter();
        let out = f.format_diff(&make_sample_diff());
        assert!(
            out.contains("example.com"),
            "missing domain_a in output:\n{}",
            out
        );
        assert!(
            out.contains("google.com"),
            "missing domain_b in output:\n{}",
            out
        );
        // A row indicating the header underline (Unicode box-drawing dash).
        assert!(out.contains("──"), "missing header underline:\n{}", out);
    }

    #[test]
    fn format_diff_marks_differing_rows_with_neq() {
        let f = diff_formatter();
        let out = f.format_diff(&make_sample_diff());
        // Registrar differs: IANA vs MarkMonitor.
        let registrar_line = out
            .lines()
            .find(|l| l.contains("Registrar"))
            .expect("registrar line missing");
        assert!(
            registrar_line.contains("≠"),
            "registrar row should be marked differ: {}",
            registrar_line
        );
    }

    #[test]
    fn format_diff_marks_matching_rows_with_eq() {
        let f = diff_formatter();
        let out = f.format_diff(&make_sample_diff());
        // Resolves matches (both true).
        let resolves_line = out
            .lines()
            .find(|l| l.contains("Resolves"))
            .expect("resolves line missing");
        assert!(
            resolves_line.contains('='),
            "resolves row should be marked match: {}",
            resolves_line
        );
        assert!(!resolves_line.contains('≠'));
    }

    #[test]
    fn format_diff_nameservers_reversed_order_is_match() {
        // make_sample_diff has reversed nameservers.
        let f = diff_formatter();
        let out = f.format_diff(&make_sample_diff());
        let ns_line = out
            .lines()
            .find(|l| l.contains("Nameservers"))
            .expect("nameservers line missing");
        assert!(
            ns_line.contains('=') && !ns_line.contains('≠'),
            "nameservers row should match (set equality): {}",
            ns_line
        );
    }

    #[test]
    fn format_diff_organization_none_renders_em_dash() {
        let f = diff_formatter();
        let out = f.format_diff(&make_sample_diff());
        let org_line = out
            .lines()
            .find(|l| l.contains("Organization"))
            .expect("organization line missing");
        assert!(org_line.contains("—"), "expected em dash: {}", org_line);
    }

    #[test]
    fn format_diff_multi_value_a_records_one_per_line() {
        let mut diff = make_sample_diff();
        diff.dns.a_records = (
            vec!["1.1.1.1".to_string(), "2.2.2.2".to_string()],
            vec!["3.3.3.3".to_string(), "4.4.4.4".to_string()],
        );
        let f = diff_formatter();
        let out = f.format_diff(&diff);
        assert!(out.contains("1.1.1.1"), "missing 1.1.1.1:\n{}", out);
        assert!(out.contains("2.2.2.2"), "missing 2.2.2.2:\n{}", out);
        assert!(out.contains("3.3.3.3"), "missing 3.3.3.3:\n{}", out);
        assert!(out.contains("4.4.4.4"), "missing 4.4.4.4:\n{}", out);
        // The label only appears on the first row of the field.
        let a_records_label_count = out.matches("A Records").count();
        assert_eq!(
            a_records_label_count, 1,
            "A Records label should appear exactly once:\n{}",
            out
        );
    }

    #[test]
    fn format_diff_wraps_long_scalar_values() {
        let mut diff = make_sample_diff();
        let long = "a".repeat(60);
        diff.ssl.issuer = (Some(long.clone()), Some("short".to_string()));
        let f = diff_formatter();
        let out = f.format_diff(&diff);
        // The 60-char value should not appear on any single line in full.
        for line in out.lines() {
            assert!(
                !line.contains(&long),
                "unwrapped 60-char value on one line: {}",
                line
            );
        }
        // But the characters as a whole should still be present.
        let chars_present = out.matches('a').count();
        assert!(
            chars_present >= 60,
            "wrapped value should preserve all chars, got {}",
            chars_present
        );
    }

    #[test]
    fn format_diff_plain_mode_contains_marker_glyphs() {
        let out = diff_formatter().format_diff(&make_sample_diff());
        assert!(out.contains('='), "plain mode missing =");
        assert!(out.contains('≠'), "plain mode missing ≠");
        assert!(out.contains('─'), "plain mode missing header rule ─");
    }

    #[test]
    fn format_diff_all_matching_has_no_neq() {
        let diff = DomainDiff {
            domain_a: "a.com".to_string(),
            domain_b: "a.com".to_string(),
            registration: RegistrationDiff {
                registrar: (Some("X".to_string()), Some("X".to_string())),
                organization: (Some("Org".to_string()), Some("Org".to_string())),
                created: (Some("2020".to_string()), Some("2020".to_string())),
                expires: (Some("2030".to_string()), Some("2030".to_string())),
            },
            dns: DnsDiff {
                a_records: (vec!["1.1.1.1".to_string()], vec!["1.1.1.1".to_string()]),
                nameservers: (vec!["ns".to_string()], vec!["ns".to_string()]),
                resolves: (true, true),
            },
            ssl: SslDiff {
                issuer: (Some("I".to_string()), Some("I".to_string())),
                valid_until: (Some("2030".to_string()), Some("2030".to_string())),
                days_remaining: (Some(10), Some(10)),
                is_valid: (Some(true), Some(true)),
            },
        };
        let out = diff_formatter().format_diff(&diff);
        assert!(
            !out.contains('≠'),
            "all-match diff should have no ≠:\n{}",
            out
        );
    }

    #[test]
    fn format_diff_all_differing_has_no_eq() {
        let diff = DomainDiff {
            domain_a: "a.com".to_string(),
            domain_b: "b.com".to_string(),
            registration: RegistrationDiff {
                registrar: (Some("X".to_string()), Some("Y".to_string())),
                organization: (Some("OrgX".to_string()), Some("OrgY".to_string())),
                created: (Some("2020".to_string()), Some("2021".to_string())),
                expires: (Some("2030".to_string()), Some("2031".to_string())),
            },
            dns: DnsDiff {
                a_records: (vec!["1.1.1.1".to_string()], vec!["2.2.2.2".to_string()]),
                nameservers: (vec!["nsa".to_string()], vec!["nsb".to_string()]),
                resolves: (true, false),
            },
            ssl: SslDiff {
                issuer: (Some("IA".to_string()), Some("IB".to_string())),
                valid_until: (Some("2030".to_string()), Some("2031".to_string())),
                days_remaining: (Some(10), Some(20)),
                is_valid: (Some(true), Some(false)),
            },
        };
        let out = diff_formatter().format_diff(&diff);
        // Every field differs. Match marker must not appear on any row.
        // We exclude the rule-line `─` and any spaces; only search within
        // lines that contain a field label (start with four spaces).
        for line in out.lines() {
            if line.starts_with("    ") && line.len() > 10 {
                assert!(
                    !line.contains('='),
                    "all-differing diff should have no = on field rows: {}",
                    line
                );
            }
        }
    }

    #[test]
    fn format_diff_uneven_list_lengths_pad_shorter_side() {
        let mut diff = make_sample_diff();
        diff.dns.nameservers = (
            vec!["ns1".to_string(), "ns2".to_string(), "ns3".to_string()],
            vec!["only".to_string()],
        );
        let out = diff_formatter().format_diff(&diff);
        // All three left-side nameservers render.
        assert!(out.contains("ns1"), "ns1 missing:\n{}", out);
        assert!(out.contains("ns2"), "ns2 missing:\n{}", out);
        assert!(out.contains("ns3"), "ns3 missing:\n{}", out);
        // Right side only has one value, "only".
        assert!(out.contains("only"), "right-side 'only' missing:\n{}", out);
        // The "only" string must appear exactly once — it should not be
        // mistakenly duplicated onto padding rows.
        assert_eq!(
            out.matches("only").count(),
            1,
            "right-side value must appear exactly once:\n{}",
            out
        );
    }

    fn availability_lookup(available: bool, confidence: &str) -> LookupResult {
        LookupResult::Available {
            data: Box::new(crate::availability::AvailabilityResult {
                domain: "myroyalcanin.lv".to_string(),
                available,
                confidence: confidence.to_string(),
                method: "whois".to_string(),
                details: None,
            }),
            rdap_error: "bootstrap failed".to_string(),
            whois_error: String::new(),
            whois_data: None,
        }
    }

    #[test]
    fn format_lookup_registered_high_confidence_does_not_say_available() {
        // Regression: a `LookupResult::Available` with `available: false` was
        // previously rendered as "AVAILABLE" because the formatter branched on
        // `confidence` alone. See myroyalcanin.lv investigation.
        let f = formatter();
        let out = f.format_lookup(&availability_lookup(false, "high"));
        assert!(
            !out.contains("AVAILABLE"),
            "must not claim available:\n{}",
            out
        );
        assert!(
            out.contains("REGISTERED"),
            "must render REGISTERED:\n{}",
            out
        );
        assert!(
            out.contains("(registered)"),
            "header suffix must say registered:\n{}",
            out
        );
    }

    #[test]
    fn format_lookup_available_high_confidence_still_says_available() {
        let f = formatter();
        let out = f.format_lookup(&availability_lookup(true, "high"));
        assert!(
            out.contains("AVAILABLE"),
            "high-confidence available:\n{}",
            out
        );
        assert!(out.contains("(available)"), "header suffix:\n{}", out);
    }

    #[test]
    fn format_lookup_likely_registered_medium_confidence() {
        let f = formatter();
        let out = f.format_lookup(&availability_lookup(false, "medium"));
        assert!(out.contains("LIKELY REGISTERED"), "medium reg:\n{}", out);
        assert!(
            !out.contains("MAY BE AVAILABLE"),
            "must not say MAY BE AVAILABLE:\n{}",
            out
        );
    }

    #[test]
    fn domain_info_verdict_registered_for_high_confidence_unavailable() {
        // Regression: DomainInfo::availability_verdict ignored data.available.
        let lookup = availability_lookup(false, "high");
        let info = crate::domain_info::DomainInfo::from_lookup_result(&lookup);
        assert_eq!(info.availability_verdict.as_deref(), Some("registered"));
    }

    #[test]
    fn format_diff_em_dash_is_dim_not_row_color() {
        // Colored formatter — we need to see the ANSI escape codes.
        // Force color output even in non-TTY test environments.
        colored::control::set_override(true);
        let f = HumanFormatter::new();
        let out = f.format_diff(&make_sample_diff());
        colored::control::unset_override();

        // In make_sample_diff, Organization is (None, Some("Google LLC")) →
        // differ row. The row-level red color for differ rows is the bright-red
        // ANSI code `\x1b[91m`. The dim em-dash cell should NOT appear inside
        // that code.
        //
        // We look for the Organization line and assert that the em-dash in it
        // is NOT wrapped in bright-red — i.e. the substring "\x1b[91m—" should
        // not appear. The em-dash should instead appear wrapped in the dim
        // (bright-black, `\x1b[90m`) code.
        let org_line = out
            .lines()
            .find(|l| l.contains("Organization"))
            .expect("organization line missing");
        assert!(
            !org_line.contains("\x1b[91m—"),
            "em-dash should not be red on a differ row: {:?}",
            org_line
        );
        assert!(
            org_line.contains("\x1b[90m"),
            "em-dash should be dim (bright-black ANSI): {:?}",
            org_line
        );
    }
}
