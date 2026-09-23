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

        if let Some(created) = response.creation_date {
            output.push(format!("- **Created**: `{}`", created.format("%Y-%m-%d")));
        }
        if let Some(expires) = response.expiration_date {
            let days_until = days_until(expires);
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

        // Contact subsections last, so no domain-level field lands under a
        // contact heading.
        self.format_whois_contacts(&mut output, response);

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
            status: vec!["clientTransferProhibited".to_string()],
            whois_server: "whois.example.invalid".to_string(),
            ..Default::default()
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
    fn test_markdown_whois_domain_fields_precede_contact_sections() {
        // Contact `###` subsections were emitted before Created/Expires/
        // Nameservers/Status/DNSSEC/WHOIS Server with no heading in between,
        // so those domain-level fields rendered as part of the last contact.
        let w = WhoisResponse::parse(
            "example.com",
            "whois.test",
            "Registrar: Mock Registrar\n\
             Creation Date: 2010-03-15T04:00:00Z\n\
             Registry Expiry Date: 2099-03-15T04:00:00Z\n\
             Registrant Country: US\n\
             Admin Name: Jane Admin\n\
             Tech Email: tech@example.com\n\
             Name Server: ns1.example.com\n\
             Domain Status: ok\n\
             DNSSEC: unsigned\n",
        );
        let out = MarkdownFormatter::new().format_whois(&w);
        let first_heading = out.find("\n###").expect("contact sections rendered");
        for field in [
            "- **Registrar**",
            "- **Created**",
            "- **Expires**",
            "- **Nameservers**",
            "- **Status**",
            "- **DNSSEC**",
            "- **WHOIS Server**",
        ] {
            let at = out
                .find(field)
                .unwrap_or_else(|| panic!("{field} missing:\n{out}"));
            assert!(
                at < first_heading,
                "{field} rendered under a contact heading:\n{out}"
            );
        }
        for heading in [
            "### Registrant Contact",
            "### Admin Contact",
            "### Tech Contact",
        ] {
            assert!(out.contains(heading), "{heading} missing:\n{out}");
        }
        assert!(
            out.contains("- **Country**: US"),
            "contact field kept:\n{out}"
        );
    }
}
