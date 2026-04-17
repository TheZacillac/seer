use chrono::TimeDelta;
use colored::Colorize;
use once_cell::sync::Lazy;
use regex::Regex;

use super::OutputFormatter;
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
                                .map(|r| sanitize_display(&r.format_short()))
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
        let source = match result {
            LookupResult::Rdap { .. } => "RDAP",
            LookupResult::Whois { .. } => "WHOIS",
            LookupResult::Available { .. } => "availability",
        };

        output.push(self.header(&format!(
            "Lookup: {} (via {})",
            sanitize_display(&domain),
            source
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
                ..
            } => {
                output.push(format!(
                    "  {}: {}",
                    self.label("Source"),
                    self.warning("availability check (RDAP and WHOIS failed)")
                ));

                let avail_str = if data.available {
                    self.success("AVAILABLE")
                } else {
                    self.error("TAKEN")
                };
                output.push(format!("  {}: {}", self.label("Availability"), avail_str));

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
                    self.value(&data.method)
                ));
                if let Some(ref details) = data.details {
                    output.push(format!(
                        "  {}: {}",
                        self.label("Details"),
                        self.value(details)
                    ));
                }
                output.push(format!(
                    "  {}: {}",
                    self.label("RDAP Error"),
                    self.error(rdap_error)
                ));
                output.push(format!(
                    "  {}: {}",
                    self.label("WHOIS Error"),
                    self.error(whois_error)
                ));
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
            self.value(&result.method)
        ));
        if let Some(ref details) = result.details {
            output.push(format!(
                "  {}: {}",
                self.label("Details"),
                self.value(details)
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

        // Registration
        output.push(format!("\n  {}:", self.label("Registration")));
        let reg = &diff.registration;
        output.push(format!(
            "    {}: {} | {}",
            self.label("Registrar"),
            self.value(&sanitize_display(
                reg.registrar.0.as_deref().unwrap_or("N/A")
            )),
            self.value(&sanitize_display(
                reg.registrar.1.as_deref().unwrap_or("N/A")
            ))
        ));
        output.push(format!(
            "    {}: {} | {}",
            self.label("Organization"),
            self.value(&sanitize_display(
                reg.organization.0.as_deref().unwrap_or("N/A")
            )),
            self.value(&sanitize_display(
                reg.organization.1.as_deref().unwrap_or("N/A")
            ))
        ));
        output.push(format!(
            "    {}: {} | {}",
            self.label("Created"),
            self.value(reg.created.0.as_deref().unwrap_or("N/A")),
            self.value(reg.created.1.as_deref().unwrap_or("N/A"))
        ));
        output.push(format!(
            "    {}: {} | {}",
            self.label("Expires"),
            self.value(reg.expires.0.as_deref().unwrap_or("N/A")),
            self.value(reg.expires.1.as_deref().unwrap_or("N/A"))
        ));

        // DNS
        output.push(format!("\n  {}:", self.label("DNS")));
        let dns = &diff.dns;
        {
            let (res_a, res_b) = dns.resolves;
            output.push(format!(
                "    {}: {} | {}",
                self.label("Resolves"),
                if res_a {
                    self.success("yes")
                } else {
                    self.error("no")
                },
                if res_b {
                    self.success("yes")
                } else {
                    self.error("no")
                }
            ));
        }
        output.push(format!(
            "    {}: {} | {}",
            self.label("A Records"),
            self.value(&sanitize_display(&dns.a_records.0.join(", "))),
            self.value(&sanitize_display(&dns.a_records.1.join(", ")))
        ));
        output.push(format!(
            "    {}: {} | {}",
            self.label("Nameservers"),
            self.value(&sanitize_display(&dns.nameservers.0.join(", "))),
            self.value(&sanitize_display(&dns.nameservers.1.join(", ")))
        ));

        // SSL
        output.push(format!("\n  {}:", self.label("SSL")));
        let ssl = &diff.ssl;
        output.push(format!(
            "    {}: {} | {}",
            self.label("Issuer"),
            self.value(&sanitize_display(ssl.issuer.0.as_deref().unwrap_or("N/A"))),
            self.value(&sanitize_display(ssl.issuer.1.as_deref().unwrap_or("N/A")))
        ));
        output.push(format!(
            "    {}: {} | {}",
            self.label("Valid Until"),
            self.value(ssl.valid_until.0.as_deref().unwrap_or("N/A")),
            self.value(ssl.valid_until.1.as_deref().unwrap_or("N/A"))
        ));
        {
            let a_str = ssl.days_remaining.0.map(|d| d.to_string());
            let b_str = ssl.days_remaining.1.map(|d| d.to_string());
            output.push(format!(
                "    {}: {} | {}",
                self.label("Days Remaining"),
                self.value(a_str.as_deref().unwrap_or("N/A")),
                self.value(b_str.as_deref().unwrap_or("N/A"))
            ));
        }
        {
            let a_str = ssl.is_valid.0.map(|v| if v { "yes" } else { "no" });
            let b_str = ssl.is_valid.1.map(|v| if v { "yes" } else { "no" });
            output.push(format!(
                "    {}: {} | {}",
                self.label("Valid"),
                self.value(a_str.unwrap_or("N/A")),
                self.value(b_str.unwrap_or("N/A"))
            ));
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
