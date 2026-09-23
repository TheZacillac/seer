use super::*;

impl MarkdownFormatter {
    pub(super) fn format_rdap(&self, response: &RdapResponse) -> String {
        let name = response
            .domain_name()
            .or(response.name.as_deref())
            .unwrap_or("Unknown");
        let mut output = vec![format!("## RDAP: {}", MdSafe(name)), String::new()];

        let mut b = Bullets(&mut output);
        b.code_opt("Handle", &response.handle);
        b.opt("Registrar", &response.get_registrar());
        b.opt("Registrant", &response.get_registrant());
        b.opt("Organization", &response.get_registrant_organization());
        b.date("Created", response.creation_date());
        b.expires(response.expiration_date());
        b.date("Updated", response.last_updated());
        b.code_list("Status", &response.status);
        b.code_list("Nameservers", &response.nameserver_names());
        if response.is_dnssec_signed() {
            b.raw("DNSSEC", "signed");
        }

        // IP-specific fields
        b.code_opt("Start Address", &response.start_address);
        b.code_opt("End Address", &response.end_address);
        b.opt("Country", &response.country);

        // ASN-specific fields
        if let Some(start) = response.start_autnum {
            let end = response.end_autnum.unwrap_or(start);
            b.raw("AS Number", format!("`AS{start}` - `AS{end}`"));
        }

        // Contact sections last: each `###` heading scopes everything below
        // it, so no domain-level field may follow one.
        let infos = contact::rdap_contacts(response);
        b.contacts(contact::rdap_views(&infos));
        let billing = response.get_billing_contact();
        b.contact("Billing", Contact::rdap(billing.as_ref()));

        output.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_markdown_rdap_domain_fields_precede_contact_sections() {
        // Contact `###` subsections used to precede Created/Expires/Status/
        // Nameservers, so those rendered as part of the last contact section.
        let json = serde_json::json!({
            "ldhName": "example.com",
            "status": ["active"],
            "events": [
                {"eventAction": "registration", "eventDate": "2010-03-15T04:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2099-03-15T04:00:00Z"}
            ],
            "nameservers": [{"objectClassName": "nameserver", "ldhName": "ns1.example.com"}],
            "entities": [{
                "objectClassName": "entity",
                "handle": "TECH-1",
                "roles": ["technical"],
                "vcardArray": ["vcard", [
                    ["fn", {}, "text", "Tech Person"],
                    ["email", {}, "text", "tech@example.com"]
                ]]
            }]
        });
        let response: RdapResponse = serde_json::from_value(json).unwrap();
        let out = MarkdownFormatter::new().format_rdap(&response);
        let heading = out
            .find("### Tech Contact")
            .unwrap_or_else(|| panic!("tech contact missing:\n{out}"));
        for field in [
            "- **Created**",
            "- **Expires**",
            "- **Status**",
            "- **Nameservers**",
        ] {
            let at = out
                .find(field)
                .unwrap_or_else(|| panic!("{field} missing:\n{out}"));
            assert!(at < heading, "{field} rendered under a contact:\n{out}");
        }
        assert!(out.contains("tech@example.com"), "contact kept:\n{out}");
    }
}
