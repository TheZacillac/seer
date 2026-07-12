use super::*;

impl HumanFormatter {
    pub(super) fn format_tld(&self, info: &crate::tld::TldInfo) -> String {
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

    pub(super) fn format_subdomains(&self, result: &crate::subdomains::SubdomainResult) -> String {
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

    pub(super) fn format_watch(&self, report: &crate::watchlist::WatchReport) -> String {
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

    pub(super) fn format_domain_info(&self, info: &crate::domain_info::DomainInfo) -> String {
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

        // Derived lifecycle (computed at construction from the dates above).
        if let Some(days) = info.days_until_expiration {
            let rendered = format!("{} days", days);
            output.push(format!(
                "  {}: {}",
                self.label("Days Until Expiry"),
                if days <= 30 {
                    self.warning(&rendered)
                } else {
                    self.value(&rendered)
                }
            ));
        }
        if let Some(age) = info.domain_age_days {
            output.push(format!(
                "  {}: {}",
                self.label("Domain Age"),
                self.value(&format!("{} days", age))
            ));
        }
        if let Some(expiry_status) = info.expiry_status {
            let rendered = expiry_status.to_string();
            let colored = match expiry_status {
                crate::domain_info::ExpiryStatus::Active => self.value(&rendered),
                crate::domain_info::ExpiryStatus::ExpiringSoon => self.warning(&rendered),
                _ => self.error(&rendered),
            };
            output.push(format!("  {}: {}", self.label("Expiry Status"), colored));
        }

        // DNS. Nameservers/status originate from attacker-controlled WHOIS/RDAP
        // parsing, so sanitize them like the adjacent DNSSEC field (issue #53).
        if !info.nameservers.is_empty() {
            output.push(format!(
                "  {}: {}",
                self.label("Nameservers"),
                self.value(&sanitize_display(&info.nameservers.join(", ")))
            ));
        }
        if !info.status.is_empty() {
            output.push(format!(
                "  {}: {}",
                self.label("Status"),
                self.value(&sanitize_display(&info.status.join(", ")))
            ));
        }
        if let Some(ref dnssec) = info.dnssec {
            output.push(format!(
                "  {}: {}",
                self.label("DNSSEC"),
                self.value(&sanitize_display(dnssec))
            ));
        }

        // Plain-English decodings of recognized EPP status codes.
        if !info.status_descriptions.is_empty() {
            output.push(format!("\n  {}:", self.label("Status Codes")));
            for sd in &info.status_descriptions {
                output.push(format!(
                    "    {}: {}",
                    self.label(&sanitize_display(&sd.code)),
                    self.value(&sanitize_display(&sd.description))
                ));
            }
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

        // Registrar Detail (RDAP registrar entity: abuse contact, IANA ID, URL)
        let has_registrar_detail = info.registrar_iana_id.is_some()
            || info.registrar_url.is_some()
            || info.registrar_abuse_email.is_some()
            || info.registrar_abuse_phone.is_some();
        if has_registrar_detail {
            output.push(format!("\n  {}:", self.label("Registrar Detail")));
            if let Some(ref iana_id) = info.registrar_iana_id {
                output.push(format!(
                    "    {}: {}",
                    self.label("IANA ID"),
                    self.value(&sanitize_display(iana_id))
                ));
            }
            if let Some(ref url) = info.registrar_url {
                output.push(format!(
                    "    {}: {}",
                    self.label("URL"),
                    self.value(&sanitize_display(url))
                ));
            }
            if let Some(ref email) = info.registrar_abuse_email {
                output.push(format!(
                    "    {}: {}",
                    self.label("Abuse Email"),
                    self.value(&sanitize_display(email))
                ));
            }
            if let Some(ref phone) = info.registrar_abuse_phone {
                output.push(format!(
                    "    {}: {}",
                    self.label("Abuse Phone"),
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
