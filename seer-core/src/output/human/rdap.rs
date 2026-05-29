use super::*;

impl HumanFormatter {
    pub(super) fn format_rdap(&self, response: &RdapResponse) -> String {
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
}
