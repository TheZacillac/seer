use chrono::TimeDelta;
use colored::Colorize;

use super::OutputFormatter;
use crate::colors::CatppuccinExt;
use crate::dns::{DnsRecord, FollowIteration, FollowResult, PropagationResult};
use crate::lookup::LookupResult;
use crate::rdap::RdapResponse;
use crate::status::StatusResponse;
use crate::whois::WhoisResponse;

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
            format!("\n{}\n{}", text.lavender().bold(), "─".repeat(text.len()).subtext0())
        } else {
            format!("\n{}\n{}", text, "-".repeat(text.len()))
        }
    }
}

impl OutputFormatter for HumanFormatter {
    fn format_whois(&self, response: &WhoisResponse) -> String {
        let mut output = Vec::new();

        output.push(self.header(&format!("WHOIS: {}", response.domain)));

        if response.is_available() {
            output.push(format!("  {} Domain is available", self.success("✓")));
            return output.join("\n");
        }

        if let Some(ref registrar) = response.registrar {
            output.push(format!(
                "  {}: {}",
                self.label("Registrar"),
                self.value(registrar)
            ));
        }

        if let Some(ref registrant) = response.registrant {
            output.push(format!(
                "  {}: {}",
                self.label("Registrant"),
                self.value(registrant)
            ));
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
            let status = if days_until < 30 {
                self.error(&format!("{} (expires in {} days!)", expiry_str, days_until))
            } else if days_until < 90 {
                self.warning(&format!("{} ({} days)", expiry_str, days_until))
            } else {
                self.value(&format!("{} ({} days)", expiry_str, days_until))
            };
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
                output.push(format!("    - {}", self.value(ns)));
            }
        }

        if !response.status.is_empty() {
            output.push(format!("  {}:", self.label("Status")));
            for status in &response.status {
                output.push(format!("    - {}", self.value(status)));
            }
        }

        if let Some(ref dnssec) = response.dnssec {
            output.push(format!(
                "  {}: {}",
                self.label("DNSSEC"),
                self.value(dnssec)
            ));
        }

        output.push(format!(
            "  {}: {}",
            self.label("WHOIS Server"),
            self.value(&response.whois_server)
        ));

        output.join("\n")
    }

    fn format_rdap(&self, response: &RdapResponse) -> String {
        let mut output = Vec::new();

        let name = response
            .domain_name()
            .or(response.name.as_deref())
            .unwrap_or("Unknown");
        output.push(self.header(&format!("RDAP: {}", name)));

        if let Some(handle) = &response.handle {
            output.push(format!(
                "  {}: {}",
                self.label("Handle"),
                self.value(handle)
            ));
        }

        if let Some(registrar) = response.get_registrar() {
            output.push(format!(
                "  {}: {}",
                self.label("Registrar"),
                self.value(&registrar)
            ));
        }

        if let Some(registrant) = response.get_registrant() {
            output.push(format!(
                "  {}: {}",
                self.label("Registrant"),
                self.value(&registrant)
            ));
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
            let status = if days_until < 30 {
                self.error(&format!("{} (expires in {} days!)", expiry_str, days_until))
            } else if days_until < 90 {
                self.warning(&format!("{} ({} days)", expiry_str, days_until))
            } else {
                self.value(&format!("{} ({} days)", expiry_str, days_until))
            };
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
                output.push(format!("    - {}", self.value(status)));
            }
        }

        let nameservers = response.nameserver_names();
        if !nameservers.is_empty() {
            output.push(format!("  {}:", self.label("Nameservers")));
            for ns in &nameservers {
                output.push(format!("    - {}", self.value(ns)));
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
                self.value(start)
            ));
        }

        if let Some(ref end) = response.end_address {
            output.push(format!(
                "  {}: {}",
                self.label("End Address"),
                self.value(end)
            ));
        }

        if let Some(ref country) = response.country {
            output.push(format!(
                "  {}: {}",
                self.label("Country"),
                self.value(country)
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
            return output.join("\n");
        }

        let domain = &records[0].name;
        let record_type = &records[0].record_type;
        output.push(self.header(&format!("DNS {} Records: {}", record_type, domain)));

        for record in records {
            output.push(format!(
                "  {} {} {} {}",
                self.value(&record.name),
                self.label(&format!("{}", record.ttl)),
                self.label(&format!("{}", record.record_type)),
                self.success(&record.data.to_string())
            ));
        }

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
                output.push(format!("    - {}", self.success(value)));
            }
        }

        // Inconsistencies
        if !result.inconsistencies.is_empty() {
            output.push(format!("  {}:", self.label("Inconsistencies")));
            for inconsistency in &result.inconsistencies {
                output.push(format!("    - {}", self.warning(inconsistency)));
            }
        }

        // Group results by region
        let mut by_region: std::collections::HashMap<&str, Vec<_>> = std::collections::HashMap::new();
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
                            .map(|r| r.format_short())
                            .collect::<Vec<_>>()
                            .join(", ")
                    }
                } else {
                    server_result
                        .error
                        .as_deref()
                        .unwrap_or("Error")
                        .to_string()
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

        output.join("\n")
    }

    fn format_lookup(&self, result: &LookupResult) -> String {
        let mut output = Vec::new();

        let domain = result.domain_name().unwrap_or_else(|| "Unknown".to_string());
        let source = if result.is_rdap() { "RDAP" } else { "WHOIS" };

        output.push(self.header(&format!("Lookup: {} (via {})", domain, source)));

        match result {
            LookupResult::Rdap { data, whois_fallback } => {
                output.push(format!(
                    "  {}: {}",
                    self.label("Source"),
                    self.success("RDAP (modern protocol)")
                ));

                if let Some(registrar) = data.get_registrar() {
                    output.push(format!(
                        "  {}: {}",
                        self.label("Registrar"),
                        self.value(&registrar)
                    ));
                }

                if let Some(registrant) = data.get_registrant() {
                    output.push(format!(
                        "  {}: {}",
                        self.label("Registrant"),
                        self.value(&registrant)
                    ));
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
                    let status = if days_until < 30 {
                        self.error(&format!("{} (expires in {} days!)", expiry_str, days_until))
                    } else if days_until < 90 {
                        self.warning(&format!("{} ({} days)", expiry_str, days_until))
                    } else {
                        self.value(&format!("{} ({} days)", expiry_str, days_until))
                    };
                    output.push(format!("  {}: {}", self.label("Expires"), status));
                }

                if !data.status.is_empty() {
                    output.push(format!("  {}:", self.label("Status")));
                    for status in &data.status {
                        output.push(format!("    - {}", self.value(status)));
                    }
                }

                let nameservers = data.nameserver_names();
                if !nameservers.is_empty() {
                    output.push(format!("  {}:", self.label("Nameservers")));
                    for ns in &nameservers {
                        output.push(format!("    - {}", self.value(ns)));
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
                    output.push(format!("\n  {}", self.label("Additional WHOIS data:")));
                    if let Some(ref raw) = whois.dnssec {
                        output.push(format!("    DNSSEC: {}", self.value(raw)));
                    }
                }
            }
            LookupResult::Whois { data, rdap_error } => {
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
                        self.value(registrar)
                    ));
                }

                if let Some(ref registrant) = data.registrant {
                    output.push(format!(
                        "  {}: {}",
                        self.label("Registrant"),
                        self.value(registrant)
                    ));
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
                    let status = if days_until < 30 {
                        self.error(&format!("{} (expires in {} days!)", expiry_str, days_until))
                    } else if days_until < 90 {
                        self.warning(&format!("{} ({} days)", expiry_str, days_until))
                    } else {
                        self.value(&format!("{} ({} days)", expiry_str, days_until))
                    };
                    output.push(format!("  {}: {}", self.label("Expires"), status));
                }

                if !data.status.is_empty() {
                    output.push(format!("  {}:", self.label("Status")));
                    for status in &data.status {
                        output.push(format!("    - {}", self.value(status)));
                    }
                }

                if !data.nameservers.is_empty() {
                    output.push(format!("  {}:", self.label("Nameservers")));
                    for ns in &data.nameservers {
                        output.push(format!("    - {}", self.value(ns)));
                    }
                }

                if let Some(ref dnssec) = data.dnssec {
                    output.push(format!(
                        "  {}: {}",
                        self.label("DNSSEC"),
                        self.value(dnssec)
                    ));
                }
            }
        }

        output.join("\n")
    }

    fn format_status(&self, response: &StatusResponse) -> String {
        let mut output = Vec::new();

        output.push(self.header(&format!("Status: {}", response.domain)));

        // HTTP Status
        if let Some(status) = response.http_status {
            let status_text = response
                .http_status_text
                .as_deref()
                .unwrap_or("Unknown");
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
                self.value(title)
            ));
        }

        // SSL Certificate
        if let Some(ref cert) = response.certificate {
            output.push(format!("\n  {}:", self.label("SSL Certificate")));
            output.push(format!(
                "    {}: {}",
                self.label("Subject"),
                self.value(&cert.subject)
            ));
            output.push(format!(
                "    {}: {}",
                self.label("Issuer"),
                self.value(&cert.issuer)
            ));

            let valid_status = if cert.is_valid {
                self.success("Valid")
            } else {
                self.error("Invalid")
            };
            output.push(format!(
                "    {}: {}",
                self.label("Status"),
                valid_status
            ));

            output.push(format!(
                "    {}: {}",
                self.label("Valid From"),
                self.value(&cert.valid_from.format("%Y-%m-%d").to_string())
            ));

            let expiry_str = cert.valid_until.format("%Y-%m-%d").to_string();
            let expiry_display = if cert.days_until_expiry < 30 {
                self.error(&format!("{} ({} days!)", expiry_str, cert.days_until_expiry))
            } else if cert.days_until_expiry < 90 {
                self.warning(&format!("{} ({} days)", expiry_str, cert.days_until_expiry))
            } else {
                self.value(&format!("{} ({} days)", expiry_str, cert.days_until_expiry))
            };
            output.push(format!(
                "    {}: {}",
                self.label("Expires"),
                expiry_display
            ));
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
                    self.value(registrar)
                ));
            }

            let expiry_str = expiry.expiration_date.format("%Y-%m-%d").to_string();
            let expiry_display = if expiry.days_until_expiry < 30 {
                self.error(&format!("{} ({} days!)", expiry_str, expiry.days_until_expiry))
            } else if expiry.days_until_expiry < 90 {
                self.warning(&format!("{} ({} days)", expiry_str, expiry.days_until_expiry))
            } else {
                self.value(&format!("{} ({} days)", expiry_str, expiry.days_until_expiry))
            };
            output.push(format!(
                "    {}: {}",
                self.label("Expires"),
                expiry_display
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

        output.push(format!(
            "[{}] {}: {} record(s){}",
            self.label(&time_str),
            iter_str,
            record_count,
            status
        ));

        // Show records (each on its own line, trailing dots removed)
        for record in &iteration.records {
            let value = record.data.to_string().trim_end_matches('.').to_string();
            output.push(format!("    {}", self.value(&value)));
        }

        // Show changes if any
        if !iteration.added.is_empty() {
            for added in &iteration.added {
                let value = added.trim_end_matches('.');
                output.push(format!("    {} {}", self.success("+"), self.success(value)));
            }
        }
        if !iteration.removed.is_empty() {
            for removed in &iteration.removed {
                let value = removed.trim_end_matches('.');
                output.push(format!("    {} {}", self.error("-"), self.error(value)));
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
}
