use super::*;

impl MarkdownFormatter {
    pub(super) fn format_whois(&self, response: &WhoisResponse) -> String {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::whois::WhoisResponse;

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
}
