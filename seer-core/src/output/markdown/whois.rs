use super::*;

impl MarkdownFormatter {
    pub(super) fn format_whois(&self, response: &WhoisResponse) -> String {
        let mut output = vec![
            format!("## WHOIS: {}", MdSafe(&response.domain)),
            String::new(),
        ];

        if response.is_available() {
            output.push("Domain is **available** for registration.".to_string());
            return output.join("\n");
        }

        let mut b = Bullets(&mut output);
        b.opt("Registrar", &response.registrar);
        b.opt("Registrant", &response.registrant);
        b.opt("Organization", &response.organization);
        b.date("Created", response.creation_date);
        b.expires(response.expiration_date);
        b.date("Updated", response.updated_date);
        b.code_list("Nameservers", &response.nameservers);
        b.code_list("Status", &response.status);
        b.opt("DNSSEC", &response.dnssec);
        b.code("WHOIS Server", &response.whois_server);
        // Contact subsections last, so no domain-level field lands under a
        // contact heading.
        b.contacts(response.contacts());

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
