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

        self.push_contacts(&mut output, "  ", response.contacts());

        if let Some(created) = response.creation_date {
            output.push(format!(
                "  {}: {}",
                self.label("Created"),
                self.value(&created.format("%Y-%m-%d").to_string())
            ));
        }

        if let Some(expires) = response.expiration_date {
            let days_until = days_until(expires);
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
