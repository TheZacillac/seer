use super::grouping::render_grouped;
use super::OutputFormatter;
use crate::caa::{CaaPolicy, IssuerCaaMatch};
use crate::dns::{DnsRecord, FollowIteration, FollowResult, PropagationResult};
use crate::lookup::LookupResult;
use crate::rdap::RdapResponse;
use crate::status::StatusResponse;
use crate::whois::WhoisResponse;
use std::fmt::{self, Write as _};

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

impl OutputFormatter for MarkdownFormatter {
    fn format_whois(&self, response: &WhoisResponse) -> String {
        let mut output = Vec::new();

        output.push(format!("## WHOIS: {}", MdSafe(&response.domain)));
        output.push(String::new());

        if response.is_available() {
            output.push("Domain is **available** for registration.".to_string());
            return output.join("\n");
        }

        if let Some(ref registrar) = response.registrar {
            output.push(format!("- **Registrar**: {}", MdSafe(registrar)));
        }
        if let Some(ref registrant) = response.registrant {
            output.push(format!("- **Registrant**: {}", MdSafe(registrant)));
        }
        if let Some(ref organization) = response.organization {
            output.push(format!("- **Organization**: {}", MdSafe(organization)));
        }

        // Registrant contact details
        let has_registrant_details = response.registrant_email.is_some()
            || response.registrant_phone.is_some()
            || response.registrant_address.is_some()
            || response.registrant_country.is_some();

        if has_registrant_details {
            output.push(String::new());
            output.push("### Registrant Contact".to_string());
            output.push(String::new());
            if let Some(ref email) = response.registrant_email {
                output.push(format!("- **Email**: `{}`", MdSafe(email)));
            }
            if let Some(ref phone) = response.registrant_phone {
                output.push(format!("- **Phone**: {}", MdSafe(phone)));
            }
            if let Some(ref address) = response.registrant_address {
                output.push(format!("- **Address**: {}", MdSafe(address)));
            }
            if let Some(ref country) = response.registrant_country {
                output.push(format!("- **Country**: {}", MdSafe(country)));
            }
        }

        // Admin contact
        self.format_whois_contact(
            &mut output,
            "Admin Contact",
            &response.admin_name,
            &response.admin_organization,
            &response.admin_email,
            &response.admin_phone,
        );

        // Tech contact
        self.format_whois_contact(
            &mut output,
            "Tech Contact",
            &response.tech_name,
            &response.tech_organization,
            &response.tech_email,
            &response.tech_phone,
        );

        if let Some(created) = response.creation_date {
            output.push(format!("- **Created**: `{}`", created.format("%Y-%m-%d")));
        }
        if let Some(expires) = response.expiration_date {
            let days_until = (expires - chrono::Utc::now()).num_days();
            output.push(format!(
                "- **Expires**: `{}` ({} days)",
                expires.format("%Y-%m-%d"),
                days_until
            ));
        }
        if let Some(updated) = response.updated_date {
            output.push(format!("- **Updated**: `{}`", updated.format("%Y-%m-%d")));
        }

        if !response.nameservers.is_empty() {
            output.push(format!(
                "- **Nameservers**: {}",
                response
                    .nameservers
                    .iter()
                    .map(|ns| format!("`{}`", MdSafe(ns)))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        if !response.status.is_empty() {
            output.push(format!(
                "- **Status**: {}",
                response
                    .status
                    .iter()
                    .map(|s| format!("`{}`", MdSafe(s)))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        if let Some(ref dnssec) = response.dnssec {
            output.push(format!("- **DNSSEC**: {}", MdSafe(dnssec)));
        }

        output.push(format!(
            "- **WHOIS Server**: `{}`",
            MdSafe(&response.whois_server)
        ));

        output.join("\n")
    }

    fn format_rdap(&self, response: &RdapResponse) -> String {
        let mut output = Vec::new();

        let name = response
            .domain_name()
            .or(response.name.as_deref())
            .unwrap_or("Unknown");
        output.push(format!("## RDAP: {}", MdSafe(name)));
        output.push(String::new());

        if let Some(ref handle) = response.handle {
            output.push(format!("- **Handle**: `{}`", MdSafe(handle)));
        }
        if let Some(registrar) = response.get_registrar() {
            output.push(format!("- **Registrar**: {}", MdSafe(&registrar)));
        }
        if let Some(registrant) = response.get_registrant() {
            output.push(format!("- **Registrant**: {}", MdSafe(&registrant)));
        }
        if let Some(organization) = response.get_registrant_organization() {
            output.push(format!("- **Organization**: {}", MdSafe(&organization)));
        }

        // Contact sections
        if let Some(contact) = response.get_registrant_contact() {
            self.format_rdap_contact(&mut output, "Registrant Contact", &contact);
        }
        if let Some(contact) = response.get_admin_contact() {
            self.format_rdap_contact(&mut output, "Admin Contact", &contact);
        }
        if let Some(contact) = response.get_tech_contact() {
            self.format_rdap_contact(&mut output, "Tech Contact", &contact);
        }
        if let Some(contact) = response.get_billing_contact() {
            self.format_rdap_contact(&mut output, "Billing Contact", &contact);
        }

        if let Some(created) = response.creation_date() {
            output.push(format!("- **Created**: `{}`", created.format("%Y-%m-%d")));
        }
        if let Some(expires) = response.expiration_date() {
            let days_until = (expires - chrono::Utc::now()).num_days();
            output.push(format!(
                "- **Expires**: `{}` ({} days)",
                expires.format("%Y-%m-%d"),
                days_until
            ));
        }
        if let Some(updated) = response.last_updated() {
            output.push(format!("- **Updated**: `{}`", updated.format("%Y-%m-%d")));
        }

        if !response.status.is_empty() {
            output.push(format!(
                "- **Status**: {}",
                response
                    .status
                    .iter()
                    .map(|s| format!("`{}`", MdSafe(s)))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        let nameservers = response.nameserver_names();
        if !nameservers.is_empty() {
            output.push(format!(
                "- **Nameservers**: {}",
                nameservers
                    .iter()
                    .map(|ns| format!("`{}`", MdSafe(ns)))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        if response.is_dnssec_signed() {
            output.push("- **DNSSEC**: signed".to_string());
        }

        // IP-specific fields
        if let Some(ref start) = response.start_address {
            output.push(format!("- **Start Address**: `{}`", MdSafe(start)));
        }
        if let Some(ref end) = response.end_address {
            output.push(format!("- **End Address**: `{}`", MdSafe(end)));
        }
        if let Some(ref country) = response.country {
            output.push(format!("- **Country**: {}", MdSafe(country)));
        }

        // ASN-specific fields
        if let Some(start) = response.start_autnum {
            output.push(format!(
                "- **AS Number**: `AS{}` - `AS{}`",
                start,
                response.end_autnum.unwrap_or(start)
            ));
        }

        output.join("\n")
    }

    fn format_dns(&self, records: &[DnsRecord]) -> String {
        let mut output = Vec::new();

        if records.is_empty() {
            output.push("*No records found*".to_string());
            output.push(String::new());
            output.push("> Note: DNS responses are not DNSSEC-validated.".to_string());
            return output.join("\n");
        }

        let domain = &records[0].name;
        let record_type = &records[0].record_type;
        output.push(format!(
            "## DNS {} Records: {}",
            record_type,
            MdSafe(domain)
        ));
        output.push(String::new());
        output.push("| Name | TTL | Type | Data |".to_string());
        output.push("| --- | --- | --- | --- |".to_string());

        for record in records {
            let data_str = record.data.to_string();
            output.push(format!(
                "| `{}` | {} | {} | `{}` |",
                MdSafe(&record.name),
                record.ttl,
                record.record_type,
                MdSafe(&data_str)
            ));
        }

        output.push(String::new());
        output.push("> Note: DNS responses are not DNSSEC-validated.".to_string());

        output.join("\n")
    }

    fn format_propagation(&self, result: &PropagationResult) -> String {
        let mut output = Vec::new();

        output.push(format!(
            "## Propagation: {} {}",
            MdSafe(&result.domain),
            result.record_type
        ));
        output.push(String::new());

        // Summary
        let percentage = result.propagation_percentage;
        let status = if percentage >= 100.0 {
            "Fully propagated"
        } else if percentage >= 80.0 {
            "Mostly propagated"
        } else if percentage >= 50.0 {
            "Partially propagated"
        } else {
            "Not propagated"
        };
        output.push(format!("**{:.1}%** - {}", percentage, status));
        output.push(String::new());
        output.push(format!(
            "- **Servers responding**: {}/{}",
            result.servers_responding, result.servers_checked
        ));

        // Consensus values, grouped by record type. Single-type results
        // collapse to one inline line; multi-type results get a header line
        // plus one rendered line per type. Unlike the inconsistency blocks
        // below, the per-group items are joined into a single line — so this
        // block doesn't share the `render_grouped` helper they use.
        if !result.consensus_values.is_empty() {
            let mut grouped: std::collections::BTreeMap<String, Vec<&str>> =
                std::collections::BTreeMap::new();
            for v in &result.consensus_values {
                grouped
                    .entry(v.record_type.to_string())
                    .or_default()
                    .push(v.value.as_str());
            }

            let render_values = |values: &[&str]| -> String {
                values
                    .iter()
                    .map(|v| format!("`{}`", MdSafe(v)))
                    .collect::<Vec<_>>()
                    .join(", ")
            };

            if grouped.len() == 1 {
                let (_, values) = grouped.iter().next().expect("non-empty by check above");
                output.push(format!("- **Consensus values**: {}", render_values(values)));
            } else {
                output.push("- **Consensus values**:".to_string());
                for (record_type, values) in &grouped {
                    output.push(format!(
                        "    - **{}**: {}",
                        MdSafe(record_type),
                        render_values(values)
                    ));
                }
            }
        }

        // Inconsistencies (genuine answer conflicts), grouped by record type.
        if !result.inconsistencies.is_empty() {
            output.push(String::new());
            output.push("### Inconsistencies".to_string());
            output.push(String::new());
            render_grouped(
                &mut output,
                &result.inconsistencies,
                |inc| inc.record_type.to_string(),
                |out, hdr| {
                    out.push(format!("**{}**", MdSafe(hdr)));
                    out.push(String::new());
                },
                |out, inc, _nested| out.push(format!("- {}", MdSafe(&inc.to_string()))),
            );
        }

        // Per-vantage nameserver-IP disagreements (glue-update lag), grouped
        // by NS hostname. Only present for NS-record lookups.
        let ns_details = result.nameserver_details.as_ref();
        if let Some(details) = ns_details {
            if !details.inconsistencies.is_empty() {
                output.push(String::new());
                output.push("### Nameserver IP inconsistencies".to_string());
                output.push(String::new());
                render_grouped(
                    &mut output,
                    &details.inconsistencies,
                    |inc| inc.nameserver.clone(),
                    |out, hdr| {
                        out.push(format!("**{}**", MdSafe(hdr)));
                        out.push(String::new());
                    },
                    |out, inc, _nested| out.push(format!("- {}", MdSafe(&inc.to_string()))),
                );
            }
        }

        // Unreachable servers (distinct from answer conflicts)
        if !result.unreachable_servers.is_empty() {
            output.push(String::new());
            output.push("### Unreachable servers".to_string());
            output.push(String::new());
            for unreachable in &result.unreachable_servers {
                let error_msg = unreachable.error.as_deref().unwrap_or("no response");
                output.push(format!(
                    "- **{}** (`{}`): {}",
                    unreachable.name,
                    unreachable.ip,
                    MdSafe(error_msg)
                ));
            }
        }

        // Results table
        output.push(String::new());
        output.push("### Results".to_string());
        output.push(String::new());
        output.push("| Server | Location | IP | Result | Time |".to_string());
        output.push("| --- | --- | --- | --- | --- |".to_string());

        for sr in &result.results {
            let result_str = if sr.success {
                if sr.records.is_empty() {
                    "NXDOMAIN".to_string()
                } else {
                    sr.records
                        .iter()
                        .map(|r| {
                            let short = r.format_short();
                            let key = short.to_ascii_lowercase();
                            // Per-vantage view first, then cross-server
                            // consensus as a fallback.
                            let ips = ns_details.and_then(|d| {
                                d.per_vantage
                                    .get(&sr.server.ip)
                                    .and_then(|m| m.get(&key))
                                    .filter(|v| !v.is_empty())
                                    .or_else(|| d.consensus.get(&key).filter(|v| !v.is_empty()))
                            });
                            match ips {
                                Some(ips) => format!("{} ({})", short, ips.join(", ")),
                                None => short,
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            } else {
                sr.error.as_deref().unwrap_or("Error").to_string()
            };

            output.push(format!(
                "| {} | {} | `{}` | `{}` | {}ms |",
                sr.server.name,
                sr.server.location,
                sr.server.ip,
                MdSafe(&result_str),
                sr.response_time_ms
            ));
        }

        if !result.dnssec_validated {
            output.push(String::new());
            output.push("> Note: DNS responses are not DNSSEC-validated.".to_string());
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

        output.push(format!("## Lookup: {}", MdSafe(&domain)));
        output.push(String::new());
        output.push(format!("- **Source**: {}", source));

        match result {
            LookupResult::Rdap {
                data,
                whois_fallback,
            } => {
                if let Some(registrar) = data.get_registrar() {
                    output.push(format!("- **Registrar**: {}", MdSafe(&registrar)));
                }
                if let Some(registrant) = data.get_registrant() {
                    output.push(format!("- **Registrant**: {}", MdSafe(&registrant)));
                }
                if let Some(organization) = data.get_registrant_organization() {
                    output.push(format!("- **Organization**: {}", MdSafe(&organization)));
                }

                // Contact sections from RDAP
                if let Some(contact) = data.get_registrant_contact() {
                    self.format_rdap_contact(&mut output, "Registrant Contact", &contact);
                }
                if let Some(contact) = data.get_admin_contact() {
                    self.format_rdap_contact(&mut output, "Admin Contact", &contact);
                }
                if let Some(contact) = data.get_tech_contact() {
                    self.format_rdap_contact(&mut output, "Tech Contact", &contact);
                }

                if let Some(created) = data.creation_date() {
                    output.push(format!("- **Created**: `{}`", created.format("%Y-%m-%d")));
                }
                if let Some(expires) = data.expiration_date() {
                    let days_until = (expires - chrono::Utc::now()).num_days();
                    output.push(format!(
                        "- **Expires**: `{}` ({} days)",
                        expires.format("%Y-%m-%d"),
                        days_until
                    ));
                }

                if !data.status.is_empty() {
                    output.push(format!(
                        "- **Status**: {}",
                        data.status
                            .iter()
                            .map(|s| format!("`{}`", MdSafe(s)))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }

                let nameservers = data.nameserver_names();
                if !nameservers.is_empty() {
                    output.push(format!(
                        "- **Nameservers**: {}",
                        nameservers
                            .iter()
                            .map(|ns| format!("`{}`", MdSafe(ns)))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }

                if data.is_dnssec_signed() {
                    output.push("- **DNSSEC**: signed".to_string());
                }

                // WHOIS fallback data
                if let Some(whois) = whois_fallback {
                    let mut extra = Vec::new();

                    if data.get_registrant().is_none() {
                        if let Some(ref registrant) = whois.registrant {
                            extra.push(format!("- **Registrant**: {}", MdSafe(registrant)));
                        }
                    }
                    if data.get_registrant_organization().is_none() {
                        if let Some(ref org) = whois.organization {
                            extra.push(format!("- **Organization**: {}", MdSafe(org)));
                        }
                    }

                    // Registrant contact from WHOIS fallback
                    let rdap_has_registrant = data
                        .get_registrant_contact()
                        .as_ref()
                        .is_some_and(|c| c.has_info());
                    if !rdap_has_registrant {
                        let has_whois_contact = whois.registrant_email.is_some()
                            || whois.registrant_phone.is_some()
                            || whois.registrant_address.is_some()
                            || whois.registrant_country.is_some();
                        if has_whois_contact {
                            extra.push(String::new());
                            extra.push("### Registrant Contact".to_string());
                            extra.push(String::new());
                            if let Some(ref email) = whois.registrant_email {
                                extra.push(format!("- **Email**: `{}`", MdSafe(email)));
                            }
                            if let Some(ref phone) = whois.registrant_phone {
                                extra.push(format!("- **Phone**: {}", MdSafe(phone)));
                            }
                            if let Some(ref address) = whois.registrant_address {
                                extra.push(format!("- **Address**: {}", MdSafe(address)));
                            }
                            if let Some(ref country) = whois.registrant_country {
                                extra.push(format!("- **Country**: {}", MdSafe(country)));
                            }
                        }
                    }

                    // Admin contact from WHOIS fallback
                    let rdap_has_admin = data.get_admin_contact().is_some_and(|c| c.has_info());
                    if !rdap_has_admin {
                        let has_whois_admin = whois.admin_name.is_some()
                            || whois.admin_email.is_some()
                            || whois.admin_phone.is_some();
                        if has_whois_admin {
                            extra.push(String::new());
                            extra.push("### Admin Contact".to_string());
                            extra.push(String::new());
                            if let Some(ref name) = whois.admin_name {
                                extra.push(format!("- **Name**: {}", MdSafe(name)));
                            }
                            if let Some(ref org) = whois.admin_organization {
                                extra.push(format!("- **Organization**: {}", MdSafe(org)));
                            }
                            if let Some(ref email) = whois.admin_email {
                                extra.push(format!("- **Email**: `{}`", MdSafe(email)));
                            }
                            if let Some(ref phone) = whois.admin_phone {
                                extra.push(format!("- **Phone**: {}", MdSafe(phone)));
                            }
                        }
                    }

                    // Tech contact from WHOIS fallback
                    let rdap_has_tech = data.get_tech_contact().is_some_and(|c| c.has_info());
                    if !rdap_has_tech {
                        let has_whois_tech = whois.tech_name.is_some()
                            || whois.tech_email.is_some()
                            || whois.tech_phone.is_some();
                        if has_whois_tech {
                            extra.push(String::new());
                            extra.push("### Tech Contact".to_string());
                            extra.push(String::new());
                            if let Some(ref name) = whois.tech_name {
                                extra.push(format!("- **Name**: {}", MdSafe(name)));
                            }
                            if let Some(ref org) = whois.tech_organization {
                                extra.push(format!("- **Organization**: {}", MdSafe(org)));
                            }
                            if let Some(ref email) = whois.tech_email {
                                extra.push(format!("- **Email**: `{}`", MdSafe(email)));
                            }
                            if let Some(ref phone) = whois.tech_phone {
                                extra.push(format!("- **Phone**: {}", MdSafe(phone)));
                            }
                        }
                    }

                    if let Some(updated) = whois.updated_date {
                        extra.push(format!("- **Updated**: `{}`", updated.format("%Y-%m-%d")));
                    }

                    if !data.is_dnssec_signed() {
                        if let Some(ref dnssec) = whois.dnssec {
                            extra.push(format!("- **DNSSEC**: {}", MdSafe(dnssec)));
                        }
                    }

                    if !whois.whois_server.is_empty() {
                        extra.push(format!(
                            "- **WHOIS Server**: `{}`",
                            MdSafe(&whois.whois_server)
                        ));
                    }

                    if !extra.is_empty() {
                        output.push(String::new());
                        output.push("### Additional WHOIS Data".to_string());
                        output.push(String::new());
                        output.extend(extra);
                    }
                }
            }
            LookupResult::Whois {
                data, rdap_error, ..
            } => {
                if let Some(ref error) = rdap_error {
                    output.push(format!("- **RDAP Error**: {}", MdSafe(error)));
                }

                if let Some(ref registrar) = data.registrar {
                    output.push(format!("- **Registrar**: {}", MdSafe(registrar)));
                }
                if let Some(ref registrant) = data.registrant {
                    output.push(format!("- **Registrant**: {}", MdSafe(registrant)));
                }
                if let Some(ref organization) = data.organization {
                    output.push(format!("- **Organization**: {}", MdSafe(organization)));
                }

                // Registrant contact details
                let has_registrant_details = data.registrant_email.is_some()
                    || data.registrant_phone.is_some()
                    || data.registrant_address.is_some()
                    || data.registrant_country.is_some();

                if has_registrant_details {
                    output.push(String::new());
                    output.push("### Registrant Contact".to_string());
                    output.push(String::new());
                    if let Some(ref email) = data.registrant_email {
                        output.push(format!("- **Email**: `{}`", MdSafe(email)));
                    }
                    if let Some(ref phone) = data.registrant_phone {
                        output.push(format!("- **Phone**: {}", MdSafe(phone)));
                    }
                    if let Some(ref address) = data.registrant_address {
                        output.push(format!("- **Address**: {}", MdSafe(address)));
                    }
                    if let Some(ref country) = data.registrant_country {
                        output.push(format!("- **Country**: {}", MdSafe(country)));
                    }
                }

                // Admin contact
                self.format_whois_contact(
                    &mut output,
                    "Admin Contact",
                    &data.admin_name,
                    &data.admin_organization,
                    &data.admin_email,
                    &data.admin_phone,
                );

                // Tech contact
                self.format_whois_contact(
                    &mut output,
                    "Tech Contact",
                    &data.tech_name,
                    &data.tech_organization,
                    &data.tech_email,
                    &data.tech_phone,
                );

                if let Some(created) = data.creation_date {
                    output.push(format!("- **Created**: `{}`", created.format("%Y-%m-%d")));
                }
                if let Some(expires) = data.expiration_date {
                    let days_until = (expires - chrono::Utc::now()).num_days();
                    output.push(format!(
                        "- **Expires**: `{}` ({} days)",
                        expires.format("%Y-%m-%d"),
                        days_until
                    ));
                }

                if !data.status.is_empty() {
                    output.push(format!(
                        "- **Status**: {}",
                        data.status
                            .iter()
                            .map(|s| format!("`{}`", MdSafe(s)))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }

                if !data.nameservers.is_empty() {
                    output.push(format!(
                        "- **Nameservers**: {}",
                        data.nameservers
                            .iter()
                            .map(|ns| format!("`{}`", MdSafe(ns)))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }

                if let Some(ref dnssec) = data.dnssec {
                    output.push(format!("- **DNSSEC**: {}", MdSafe(dnssec)));
                }
            }
            LookupResult::Available {
                data,
                rdap_error,
                whois_error,
                whois_data,
            } => {
                let verdict = match data.confidence.as_str() {
                    "high" => "AVAILABLE",
                    "medium" => "MAY BE AVAILABLE",
                    _ => "UNKNOWN",
                };
                output.push(format!("- **Verdict**: {}", verdict));
                output.push(format!("- **Confidence**: {}", data.confidence));
                output.push(format!("- **Method**: {}", data.method));
                if let Some(ref details) = data.details {
                    output.push(format!("- **Details**: {}", MdSafe(details)));
                }
                if !rdap_error.is_empty() {
                    output.push(format!("- **RDAP Error**: {}", MdSafe(rdap_error)));
                }
                if !whois_error.is_empty() {
                    output.push(format!("- **WHOIS Error**: {}", MdSafe(whois_error)));
                }

                if let Some(w) = whois_data {
                    let mut bullets = Vec::new();
                    if !w.nameservers.is_empty() {
                        bullets.push(format!(
                            "- **Nameservers**: {}",
                            w.nameservers
                                .iter()
                                .map(|ns| format!("`{}`", MdSafe(ns)))
                                .collect::<Vec<_>>()
                                .join(", ")
                        ));
                    }
                    if !w.status.is_empty() {
                        bullets.push(format!(
                            "- **Status**: {}",
                            w.status
                                .iter()
                                .map(|s| format!("`{}`", MdSafe(s)))
                                .collect::<Vec<_>>()
                                .join(", ")
                        ));
                    }
                    if let Some(ref dnssec) = w.dnssec {
                        bullets.push(format!("- **DNSSEC**: {}", MdSafe(dnssec)));
                    }
                    if !w.whois_server.is_empty() {
                        bullets.push(format!("- **WHOIS Server**: `{}`", MdSafe(&w.whois_server)));
                    }
                    if !bullets.is_empty() {
                        output.push(String::new());
                        output.push("### Additional WHOIS data".to_string());
                        output.push(String::new());
                        output.extend(bullets);
                    }
                }
            }
        }

        output.join("\n")
    }

    fn format_status(&self, response: &StatusResponse) -> String {
        let mut output = Vec::new();

        output.push(format!("## Status: {}", MdSafe(&response.domain)));
        output.push(String::new());

        // HTTP Status
        if let Some(status) = response.http_status {
            let status_text = response.http_status_text.as_deref().unwrap_or("Unknown");
            output.push(format!(
                "- **HTTP Status**: `{}` ({})",
                status,
                MdSafe(status_text)
            ));
        }

        // Site Title
        if let Some(ref title) = response.title {
            output.push(format!("- **Site Title**: {}", MdSafe(title)));
        }

        // SSL Certificate
        output.push(String::new());
        if let Some(ref cert) = response.certificate {
            output.push("### SSL Certificate".to_string());
            output.push(String::new());
            output.push(format!("- **Subject**: `{}`", MdSafe(&cert.subject)));
            output.push(format!("- **Issuer**: {}", MdSafe(&cert.issuer)));
            output.push(format!(
                "- **Status**: {}",
                if cert.is_valid { "Valid" } else { "Invalid" }
            ));
            output.push(format!(
                "- **Valid From**: `{}`",
                cert.valid_from.format("%Y-%m-%d")
            ));
            output.push(format!(
                "- **Expires**: `{}` ({} days)",
                cert.valid_until.format("%Y-%m-%d"),
                cert.days_until_expiry
            ));
        } else {
            output.push("### SSL Certificate".to_string());
            output.push(String::new());
            output.push("*Not available (HTTPS may not be configured)*".to_string());
        }

        if let Some(ref caa) = response.caa {
            output.extend(self.render_caa_section(caa));
        }

        // Domain Expiration
        if let Some(ref expiry) = response.domain_expiration {
            output.push(String::new());
            output.push("### Domain Registration".to_string());
            output.push(String::new());
            if let Some(ref registrar) = expiry.registrar {
                output.push(format!("- **Registrar**: {}", MdSafe(registrar)));
            }
            output.push(format!(
                "- **Expires**: `{}` ({} days)",
                expiry.expiration_date.format("%Y-%m-%d"),
                expiry.days_until_expiry
            ));
        }

        // DNS Resolution
        output.push(String::new());
        if let Some(ref dns) = response.dns_resolution {
            output.push("### DNS Resolution".to_string());
            output.push(String::new());
            output.push(format!(
                "- **Resolves**: {}",
                if dns.resolves { "Yes" } else { "No" }
            ));

            if let Some(ref cname) = dns.cname_target {
                output.push(format!("- **CNAME**: `{}`", MdSafe(cname)));
            }
            if !dns.a_records.is_empty() {
                output.push(format!(
                    "- **IPv4 (A)**: {}",
                    dns.a_records
                        .iter()
                        .map(|ip| format!("`{}`", MdSafe(ip)))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            if !dns.aaaa_records.is_empty() {
                output.push(format!(
                    "- **IPv6 (AAAA)**: {}",
                    dns.aaaa_records
                        .iter()
                        .map(|ip| format!("`{}`", MdSafe(ip)))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            if !dns.nameservers.is_empty() {
                output.push(format!(
                    "- **Nameservers**: {}",
                    dns.nameservers
                        .iter()
                        .map(|ns| format!("`{}`", MdSafe(ns)))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        } else {
            output.push("### DNS Resolution".to_string());
            output.push(String::new());
            output.push("*Check failed*".to_string());
        }

        output.join("\n")
    }

    fn format_follow_iteration(&self, iteration: &FollowIteration) -> String {
        let time_str = iteration.timestamp.format("%H:%M:%S").to_string();

        if let Some(ref error) = iteration.error {
            return format!(
                "[{}] Iteration {}/{}: **ERROR** - {}",
                time_str,
                iteration.iteration,
                iteration.total_iterations,
                MdSafe(error)
            );
        }

        let record_count = iteration.record_count();
        let status = if iteration.iteration == 1 {
            String::new()
        } else if iteration.changed {
            " (**CHANGED**)".to_string()
        } else {
            " (unchanged)".to_string()
        };

        let values: Vec<String> = iteration
            .records
            .iter()
            .map(|r| r.data.to_string().trim_end_matches('.').to_string())
            .collect();

        let values_str = if values.is_empty() {
            String::new()
        } else {
            let joined = values.join(", ");
            format!(" `{}`", MdSafe(&joined))
        };

        format!(
            "[{}] Iteration {}/{}: {} record(s){}{}",
            time_str,
            iteration.iteration,
            iteration.total_iterations,
            record_count,
            status,
            values_str
        )
    }

    fn format_follow(&self, result: &FollowResult) -> String {
        let mut output = Vec::new();

        output.push(format!(
            "## DNS Follow: {} {}",
            MdSafe(&result.domain),
            result.record_type
        ));
        output.push(String::new());

        // Summary
        output.push(format!(
            "- **Iterations**: {}/{}",
            result.completed_iterations(),
            result.iterations_requested
        ));

        if result.interrupted {
            output.push("- **Status**: Interrupted".to_string());
        }

        output.push(format!("- **Total changes**: {}", result.total_changes));

        let duration = result.ended_at - result.started_at;
        let total_secs = duration.num_seconds();
        let duration_str = if total_secs < 60 {
            format!("{}s", total_secs)
        } else if total_secs < 3600 {
            format!("{}m {}s", total_secs / 60, total_secs % 60)
        } else {
            format!("{}h {}m", total_secs / 3600, (total_secs % 3600) / 60)
        };
        output.push(format!("- **Duration**: {}", duration_str));

        // Iteration details table
        if !result.iterations.is_empty() {
            output.push(String::new());
            output.push("### Iteration Details".to_string());
            output.push(String::new());
            output.push("| # | Time | Records | Status |".to_string());
            output.push("| --- | --- | --- | --- |".to_string());

            for iteration in &result.iterations {
                let time_str = iteration.timestamp.format("%H:%M:%S").to_string();
                let status = if iteration.error.is_some() {
                    "ERROR"
                } else if iteration.changed {
                    "CHANGED"
                } else if iteration.iteration == 1 {
                    "initial"
                } else {
                    "stable"
                };

                output.push(format!(
                    "| {} | {} | {} | {} |",
                    iteration.iteration,
                    time_str,
                    iteration.record_count(),
                    status
                ));
            }
        }

        output.join("\n")
    }

    fn format_availability(&self, result: &crate::availability::AvailabilityResult) -> String {
        let mut output = Vec::new();

        output.push(format!("## Availability: {}", MdSafe(&result.domain)));
        output.push(String::new());

        let avail_str = if result.available {
            "**AVAILABLE**"
        } else {
            "**TAKEN**"
        };
        output.push(format!("- **Result**: {}", avail_str));
        output.push(format!("- **Confidence**: {}", result.confidence));
        output.push(format!("- **Method**: {}", result.method));
        if let Some(ref details) = result.details {
            output.push(format!("- **Details**: {}", MdSafe(details)));
        }

        output.join("\n")
    }

    fn format_tld(&self, info: &crate::tld::TldInfo) -> String {
        let mut output = Vec::new();

        output.push(format!("## TLD Info: .{}", MdSafe(&info.tld)));
        output.push(String::new());

        output.push(format!("- **Type**: {}", MdSafe(&info.tld_type)));

        match info.whois_server {
            Some(ref server) => {
                output.push(format!("- **WHOIS Server**: `{}`", MdSafe(server)));
            }
            None => output.push("- **WHOIS Server**: *not available*".to_string()),
        }

        match info.rdap_url {
            Some(ref url) => output.push(format!("- **RDAP URL**: `{}`", MdSafe(url))),
            None => output.push("- **RDAP URL**: *not available*".to_string()),
        }

        match info.registry_url {
            Some(ref url) => output.push(format!("- **Registry URL**: {}", MdSafe(url))),
            None => output.push("- **Registry URL**: *not available*".to_string()),
        }

        output.join("\n")
    }

    fn format_dnssec(&self, report: &crate::dns::DnssecReport) -> String {
        let mut output = Vec::new();

        output.push(format!("## DNSSEC: {}", MdSafe(&report.domain)));
        output.push(String::new());

        output.push(format!("- **Status**: `{}`", MdSafe(&report.status)));
        output.push(format!(
            "- **Chain Valid**: {}",
            if report.chain_valid { "yes" } else { "no" }
        ));
        output.push(format!("- **Enabled**: {}", report.enabled));
        output.push(format!("- **DS Records**: {}", report.ds_records.len()));
        output.push(format!(
            "- **DNSKEY Records**: {}",
            report.dnskey_records.len()
        ));

        if !report.ds_records.is_empty() {
            output.push(String::new());
            output.push("### DS Records".to_string());
            output.push(String::new());
            output.push("| Key Tag | Algorithm | Digest Type | Matched | Verified |".to_string());
            output.push("| --- | --- | --- | --- | --- |".to_string());
            for ds in &report.ds_records {
                // `algorithm_name` / `digest_type_name` come from a small
                // internal lookup table today, but wrapping in MdSafe is
                // cheap and prevents a future contributor adding a parser
                // path that pulls these from the wire from producing a
                // Markdown injection.
                output.push(format!(
                    "| {} | {} ({}) | {} ({}) | {} | {} |",
                    ds.key_tag,
                    ds.algorithm,
                    MdSafe(&ds.algorithm_name),
                    ds.digest_type,
                    MdSafe(&ds.digest_type_name),
                    if ds.matched_key { "yes" } else { "no" },
                    if ds.digest_verified { "yes" } else { "no" },
                ));
            }
        }

        if !report.dnskey_records.is_empty() {
            output.push(String::new());
            output.push("### DNSKEY Records".to_string());
            output.push(String::new());
            output.push("| Key Tag | Flags | Role | Algorithm |".to_string());
            output.push("| --- | --- | --- | --- |".to_string());
            for key in &report.dnskey_records {
                let role = if key.is_ksk {
                    "KSK"
                } else if key.is_zsk {
                    "ZSK"
                } else {
                    "Other"
                };
                output.push(format!(
                    "| {} | {} | {} | {} ({}) |",
                    key.key_tag,
                    key.flags,
                    role,
                    key.algorithm,
                    MdSafe(&key.algorithm_name)
                ));
            }
        }

        if !report.issues.is_empty() {
            output.push(String::new());
            output.push("### Issues".to_string());
            output.push(String::new());
            for issue in &report.issues {
                output.push(format!("- {}", MdSafe(issue)));
            }
        }

        output.join("\n")
    }

    fn format_dns_comparison(&self, comparison: &crate::dns::DnsComparison) -> String {
        let mut output = Vec::new();

        output.push(format!(
            "## DNS Comparison: {} {}",
            MdSafe(&comparison.domain),
            comparison.record_type
        ));
        output.push(String::new());

        if comparison.matches {
            output.push("**Result**: Records match".to_string());
        } else {
            output.push("**Result**: Records differ".to_string());
        }
        output.push(String::new());

        // Server A
        output.push(format!(
            "### Server A ({})",
            MdSafe(&comparison.server_a.nameserver)
        ));
        output.push(String::new());
        if let Some(ref err) = comparison.server_a.error {
            output.push(format!("**Error**: {}", MdSafe(err)));
        } else if comparison.server_a.records.is_empty() {
            output.push("*No records found*".to_string());
        } else {
            output.push("| Record |".to_string());
            output.push("| --- |".to_string());
            for record in &comparison.server_a.records {
                let s = record.format_short();
                output.push(format!("| `{}` |", MdSafe(&s)));
            }
        }
        output.push(String::new());

        // Server B
        output.push(format!(
            "### Server B ({})",
            MdSafe(&comparison.server_b.nameserver)
        ));
        output.push(String::new());
        if let Some(ref err) = comparison.server_b.error {
            output.push(format!("**Error**: {}", MdSafe(err)));
        } else if comparison.server_b.records.is_empty() {
            output.push("*No records found*".to_string());
        } else {
            output.push("| Record |".to_string());
            output.push("| --- |".to_string());
            for record in &comparison.server_b.records {
                let s = record.format_short();
                output.push(format!("| `{}` |", MdSafe(&s)));
            }
        }
        output.push(String::new());

        // Differences
        output.push("### Comparison".to_string());
        output.push(String::new());

        if comparison.common.is_empty() {
            output.push("- **Common**: *(none)*".to_string());
        } else {
            output.push(format!(
                "- **Common**: {}",
                comparison
                    .common
                    .iter()
                    .map(|r| format!("`{}`", MdSafe(r)))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        if comparison.only_in_a.is_empty() {
            output.push(format!(
                "- **Only in {}**: *(none)*",
                MdSafe(&comparison.server_a.nameserver)
            ));
        } else {
            output.push(format!(
                "- **Only in {}**: {}",
                MdSafe(&comparison.server_a.nameserver),
                comparison
                    .only_in_a
                    .iter()
                    .map(|r| format!("`{}`", MdSafe(r)))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        if comparison.only_in_b.is_empty() {
            output.push(format!(
                "- **Only in {}**: *(none)*",
                MdSafe(&comparison.server_b.nameserver)
            ));
        } else {
            output.push(format!(
                "- **Only in {}**: {}",
                MdSafe(&comparison.server_b.nameserver),
                comparison
                    .only_in_b
                    .iter()
                    .map(|r| format!("`{}`", MdSafe(r)))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        output.join("\n")
    }

    fn format_subdomains(&self, result: &crate::subdomains::SubdomainResult) -> String {
        let mut output = Vec::new();

        output.push(format!("## Subdomains: {}", MdSafe(&result.domain)));
        output.push(String::new());
        output.push(format!("- **Source**: {}", MdSafe(&result.source)));
        output.push(format!("- **Count**: {}", result.count));
        output.push(String::new());

        if result.subdomains.is_empty() {
            output.push("*No subdomains found*".to_string());
        } else {
            for subdomain in &result.subdomains {
                output.push(format!("- `{}`", MdSafe(subdomain)));
            }
        }

        output.join("\n")
    }

    fn format_diff(&self, diff: &crate::diff::DomainDiff) -> String {
        let dash = "\u{2014}";
        let mut output = Vec::new();

        // Helper for "value or dash"; wraps attacker-controlled value in MdSafe.
        let opt_or_dash = |o: &Option<String>| -> String {
            match o {
                Some(v) => format!("{}", MdSafe(v)),
                None => dash.to_string(),
            }
        };
        let list_or_dash = |v: &Vec<String>| -> String {
            if v.is_empty() {
                dash.to_string()
            } else {
                let joined = v.join("`, `");
                format!("`{}`", MdSafe(&joined))
            }
        };

        output.push(format!(
            "## Domain Comparison: {} vs {}",
            MdSafe(&diff.domain_a),
            MdSafe(&diff.domain_b)
        ));
        output.push(String::new());

        // Registration table
        output.push("### Registration".to_string());
        output.push(String::new());
        output.push(format!(
            "| Field | {} | {} |",
            MdSafe(&diff.domain_a),
            MdSafe(&diff.domain_b)
        ));
        output.push("| --- | --- | --- |".to_string());

        let reg = &diff.registration;
        output.push(format!(
            "| Registrar | {} | {} |",
            opt_or_dash(&reg.registrar.0),
            opt_or_dash(&reg.registrar.1)
        ));
        output.push(format!(
            "| Organization | {} | {} |",
            opt_or_dash(&reg.organization.0),
            opt_or_dash(&reg.organization.1)
        ));
        output.push(format!(
            "| Created | {} | {} |",
            opt_or_dash(&reg.created.0),
            opt_or_dash(&reg.created.1)
        ));
        output.push(format!(
            "| Expires | {} | {} |",
            opt_or_dash(&reg.expires.0),
            opt_or_dash(&reg.expires.1)
        ));

        // DNS table
        output.push(String::new());
        output.push("### DNS".to_string());
        output.push(String::new());
        output.push(format!(
            "| Field | {} | {} |",
            MdSafe(&diff.domain_a),
            MdSafe(&diff.domain_b)
        ));
        output.push("| --- | --- | --- |".to_string());
        let dns = &diff.dns;
        output.push(format!(
            "| Resolves | {} | {} |",
            if dns.resolves.0 { "yes" } else { "no" },
            if dns.resolves.1 { "yes" } else { "no" }
        ));
        let a_recs_a = list_or_dash(&dns.a_records.0);
        let a_recs_b = list_or_dash(&dns.a_records.1);
        output.push(format!("| A Records | {} | {} |", a_recs_a, a_recs_b));
        let ns_a = list_or_dash(&dns.nameservers.0);
        let ns_b = list_or_dash(&dns.nameservers.1);
        output.push(format!("| Nameservers | {} | {} |", ns_a, ns_b));

        // SSL table
        output.push(String::new());
        output.push("### SSL".to_string());
        output.push(String::new());
        output.push(format!(
            "| Field | {} | {} |",
            MdSafe(&diff.domain_a),
            MdSafe(&diff.domain_b)
        ));
        output.push("| --- | --- | --- |".to_string());
        let ssl = &diff.ssl;
        output.push(format!(
            "| Issuer | {} | {} |",
            opt_or_dash(&ssl.issuer.0),
            opt_or_dash(&ssl.issuer.1)
        ));
        output.push(format!(
            "| Valid Until | {} | {} |",
            opt_or_dash(&ssl.valid_until.0),
            opt_or_dash(&ssl.valid_until.1)
        ));
        output.push(format!(
            "| Days Remaining | {} | {} |",
            ssl.days_remaining
                .0
                .map(|d| d.to_string())
                .as_deref()
                .unwrap_or(dash),
            ssl.days_remaining
                .1
                .map(|d| d.to_string())
                .as_deref()
                .unwrap_or(dash)
        ));
        output.push(format!(
            "| Valid | {} | {} |",
            ssl.is_valid
                .0
                .map(|v| if v { "yes" } else { "no" })
                .unwrap_or(dash),
            ssl.is_valid
                .1
                .map(|v| if v { "yes" } else { "no" })
                .unwrap_or(dash)
        ));

        output.join("\n")
    }

    fn format_ssl(&self, report: &crate::ssl::SslReport) -> String {
        let mut output = Vec::new();

        output.push(format!("## SSL Report: {}", MdSafe(&report.domain)));
        output.push(String::new());

        output.push(format!(
            "- **Valid**: {}",
            if report.is_valid { "yes" } else { "no" }
        ));
        output.push(format!(
            "- **Days Until Expiry**: {}",
            report.days_until_expiry
        ));

        if let Some(ref proto) = report.protocol_version {
            output.push(format!("- **Protocol**: {}", MdSafe(proto)));
        }

        if !report.san_names.is_empty() {
            output.push(format!(
                "- **SANs**: {}",
                report
                    .san_names
                    .iter()
                    .map(|s| format!("`{}`", MdSafe(s)))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        if !report.chain.is_empty() {
            output.push(String::new());
            output.push("### Certificate Chain".to_string());
            output.push(String::new());
            output.push("| # | Subject | Issuer | Valid Until | Key |".to_string());
            output.push("| --- | --- | --- | --- | --- |".to_string());
            for (i, cert) in report.chain.iter().enumerate() {
                let key_info = match (&cert.key_type, cert.key_bits) {
                    (Some(kt), Some(bits)) => format!("{} ({} bits)", MdSafe(kt), bits),
                    (Some(kt), None) => format!("{}", MdSafe(kt)),
                    _ => "N/A".to_string(),
                };
                output.push(format!(
                    "| {} | {} | {} | {} | {} |",
                    i,
                    MdSafe(&cert.subject),
                    MdSafe(&cert.issuer),
                    cert.valid_until.format("%Y-%m-%d"),
                    key_info
                ));
            }
        }

        if let Some(ref caa) = report.caa {
            output.extend(self.render_caa_section(caa));
        }

        output.join("\n")
    }

    fn format_watch(&self, report: &crate::watchlist::WatchReport) -> String {
        let mut output = Vec::new();

        output.push("## Domain Watch Report".to_string());
        output.push(String::new());
        output.push(format!(
            "- **Checked**: {}",
            report.checked_at.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        output.push(format!(
            "- **Total**: {} domains, {} warnings, {} critical",
            report.total, report.warnings, report.critical
        ));
        output.push(String::new());

        if report.results.is_empty() {
            output.push("No domains in watchlist.".to_string());
            return output.join("\n");
        }

        output.push("| Status | Domain | SSL Days | Domain Days | HTTP | Issues |".to_string());
        output.push("| --- | --- | --- | --- | --- | --- |".to_string());

        for r in &report.results {
            let icon = if r.issues.is_empty() { "ok" } else { "warn" };
            let ssl = r
                .ssl_days_remaining
                .map(|d| d.to_string())
                .unwrap_or_else(|| "N/A".to_string());
            let dom = r
                .domain_days_remaining
                .map(|d| d.to_string())
                .unwrap_or_else(|| "N/A".to_string());
            let http = r
                .http_status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "N/A".to_string());
            let issues = if r.issues.is_empty() {
                "-".to_string()
            } else {
                r.issues.join("; ")
            };
            output.push(format!(
                "| {} | {} | {} | {} | {} | {} |",
                icon,
                MdSafe(&r.domain),
                ssl,
                dom,
                http,
                MdSafe(&issues)
            ));
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

        // Helper: render Option<String> via MdSafe or fall back to "-".
        let opt_md = |o: &Option<String>| -> String {
            match o {
                Some(v) => format!("{}", MdSafe(v)),
                None => "-".to_string(),
            }
        };

        output.push(format!("## Domain Info: {}", MdSafe(&info.domain)));
        output.push(String::new());
        output.push(format!("**Source:** {}", source_str));
        output.push(String::new());

        // Registration table
        output.push("### Registration".to_string());
        output.push(String::new());
        output.push("| Field | Value |".to_string());
        output.push("| --- | --- |".to_string());
        output.push(format!("| Registrar | {} |", opt_md(&info.registrar)));
        output.push(format!("| Registrant | {} |", opt_md(&info.registrant)));
        output.push(format!("| Organization | {} |", opt_md(&info.organization)));
        output.push(format!(
            "| Created | {} |",
            info.creation_date
                .map(|d| d.format("%Y-%m-%d").to_string())
                .as_deref()
                .unwrap_or("-")
        ));
        output.push(format!(
            "| Expires | {} |",
            info.expiration_date
                .map(|d| d.format("%Y-%m-%d").to_string())
                .as_deref()
                .unwrap_or("-")
        ));
        output.push(format!(
            "| Updated | {} |",
            info.updated_date
                .map(|d| d.format("%Y-%m-%d").to_string())
                .as_deref()
                .unwrap_or("-")
        ));
        output.push(format!(
            "| Nameservers | {} |",
            if info.nameservers.is_empty() {
                "-".to_string()
            } else {
                info.nameservers
                    .iter()
                    .map(|ns| format!("`{}`", MdSafe(ns)))
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        ));
        output.push(format!(
            "| Status | {} |",
            if info.status.is_empty() {
                "-".to_string()
            } else {
                info.status
                    .iter()
                    .map(|s| format!("`{}`", MdSafe(s)))
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        ));
        output.push(format!("| DNSSEC | {} |", opt_md(&info.dnssec)));

        // Contacts table
        let has_any_contact = info.registrant_email.is_some()
            || info.registrant_phone.is_some()
            || info.registrant_address.is_some()
            || info.registrant_country.is_some()
            || info.admin_name.is_some()
            || info.admin_organization.is_some()
            || info.admin_email.is_some()
            || info.admin_phone.is_some()
            || info.tech_name.is_some()
            || info.tech_organization.is_some()
            || info.tech_email.is_some()
            || info.tech_phone.is_some();

        if has_any_contact {
            output.push(String::new());
            output.push("### Contacts".to_string());
            output.push(String::new());
            output.push("| Role | Name | Organization | Email | Phone |".to_string());
            output.push("| --- | --- | --- | --- | --- |".to_string());

            let has_registrant = info.registrant_email.is_some()
                || info.registrant_phone.is_some()
                || info.registrant_address.is_some()
                || info.registrant_country.is_some();
            if has_registrant {
                output.push(format!(
                    "| Registrant | - | - | {} | {} |",
                    opt_md(&info.registrant_email),
                    opt_md(&info.registrant_phone),
                ));
            }

            let has_admin = info.admin_name.is_some()
                || info.admin_organization.is_some()
                || info.admin_email.is_some()
                || info.admin_phone.is_some();
            if has_admin {
                output.push(format!(
                    "| Admin | {} | {} | {} | {} |",
                    opt_md(&info.admin_name),
                    opt_md(&info.admin_organization),
                    opt_md(&info.admin_email),
                    opt_md(&info.admin_phone),
                ));
            }

            let has_tech = info.tech_name.is_some()
                || info.tech_organization.is_some()
                || info.tech_email.is_some()
                || info.tech_phone.is_some();
            if has_tech {
                output.push(format!(
                    "| Tech | {} | {} | {} | {} |",
                    opt_md(&info.tech_name),
                    opt_md(&info.tech_organization),
                    opt_md(&info.tech_email),
                    opt_md(&info.tech_phone),
                ));
            }
        }

        // Protocol Metadata
        let has_metadata = info.whois_server.is_some() || info.rdap_url.is_some();
        if has_metadata {
            output.push(String::new());
            output.push("### Protocol Metadata".to_string());
            output.push(String::new());
            if let Some(ref whois_server) = info.whois_server {
                output.push(format!("- **WHOIS Server**: `{}`", MdSafe(whois_server)));
            }
            if let Some(ref rdap_url) = info.rdap_url {
                output.push(format!("- **RDAP URL**: `{}`", MdSafe(rdap_url)));
            }
        }

        output.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::RecordType;
    use crate::status::StatusResponse;

    #[test]
    fn test_markdown_format_status() {
        let response = StatusResponse::new("example.com".to_string());
        let formatter = MarkdownFormatter::new();
        let output = formatter.format_status(&response);
        assert!(output.contains("## Status: example.com"));
        assert!(output.contains("### SSL Certificate"));
        assert!(output.contains("### DNS Resolution"));
    }

    #[test]
    fn test_markdown_format_dns_records() {
        let records = vec![DnsRecord {
            name: "example.com".to_string(),
            record_type: RecordType::A,
            ttl: 300,
            data: crate::dns::RecordData::A {
                address: "93.184.216.34".to_string(),
            },
        }];
        let formatter = MarkdownFormatter::new();
        let output = formatter.format_dns(&records);
        assert!(output.contains("## DNS A Records: example.com"));
        assert!(output.contains("| Name | TTL | Type | Data |"));
        assert!(output.contains("93.184.216.34"));
        assert!(
            output.contains("DNSSEC-validated"),
            "DNS output must disclose DNSSEC is not validated"
        );
    }

    #[test]
    fn test_markdown_format_dns_empty() {
        let formatter = MarkdownFormatter::new();
        let output = formatter.format_dns(&[]);
        assert!(output.contains("No records found"));
        assert!(output.contains("DNSSEC-validated"));
    }

    #[test]
    fn test_markdown_format_availability() {
        let result = crate::availability::AvailabilityResult {
            domain: "test.com".to_string(),
            available: true,
            confidence: "high".to_string(),
            method: "RDAP+WHOIS".to_string(),
            details: Some("Domain not found".to_string()),
        };
        let formatter = MarkdownFormatter::new();
        let output = formatter.format_availability(&result);
        assert!(output.contains("## Availability: test.com"));
        assert!(output.contains("**AVAILABLE**"));
        assert!(output.contains("high"));
    }

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

    fn empty_whois(domain: &str) -> WhoisResponse {
        WhoisResponse {
            domain: domain.to_string(),
            registrar: None,
            registrant: None,
            organization: None,
            registrant_email: None,
            registrant_phone: None,
            registrant_address: None,
            registrant_country: None,
            admin_name: None,
            admin_organization: None,
            admin_email: None,
            admin_phone: None,
            tech_name: None,
            tech_organization: None,
            tech_email: None,
            tech_phone: None,
            creation_date: None,
            expiration_date: None,
            updated_date: None,
            nameservers: vec![],
            status: vec!["clientTransferProhibited".to_string()],
            dnssec: None,
            whois_server: "whois.example.invalid".to_string(),
            raw_response: String::new(),
        }
    }

    #[test]
    fn test_markdown_whois_registrar_newline_neutralized() {
        let mut w = empty_whois("example.com");
        w.registrar = Some("Foo\nIgnore previous".to_string());
        let output = MarkdownFormatter::new().format_whois(&w);
        // Newline must be collapsed to a single space so attacker text can't
        // start a new Markdown line / heading.
        assert!(
            output.contains("- **Registrar**: Foo Ignore previous"),
            "expected sanitized registrar in output:\n{}",
            output
        );
        // Make sure the literal newline did not survive inside the registrar
        // value: split on lines and check no line starts with "Ignore".
        for line in output.lines() {
            assert!(
                !line.trim_start().starts_with("Ignore previous"),
                "attacker payload broke onto its own line:\n{}",
                output
            );
        }
    }

    #[test]
    fn test_markdown_rdap_entity_name_backtick_neutralized() {
        use crate::rdap::RdapResponse;

        // Construct via serde JSON to avoid needing to import the private
        // `RdapEntity` type. `get_registrar()` falls back to `handle` when
        // there is no vCard `fn` property.
        let json = serde_json::json!({
            "ldhName": "example.com",
            "entities": [
                {
                    "objectClassName": "entity",
                    "handle": "Evil`Registrar`Co",
                    "roles": ["registrar"],
                }
            ]
        });
        let response: RdapResponse = serde_json::from_value(json).unwrap();

        let output = MarkdownFormatter::new().format_rdap(&response);
        // Backtick must be rendered as a single quote, not as a literal
        // backtick (which could close the surrounding code span and let an
        // attacker inject Markdown).
        assert!(
            output.contains("- **Registrar**: Evil'Registrar'Co"),
            "expected backticks neutralized in RDAP output:\n{}",
            output
        );
        assert!(
            !output.contains("Evil`Registrar`Co"),
            "raw backticks survived into output:\n{}",
            output
        );
    }
}
