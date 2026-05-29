use super::*;

impl HumanFormatter {
    pub(super) fn format_whois(&self, response: &WhoisResponse) -> String {
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
}
