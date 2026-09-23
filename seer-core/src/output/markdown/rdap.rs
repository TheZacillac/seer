use super::*;

impl MarkdownFormatter {
    pub(super) fn format_rdap(&self, response: &RdapResponse) -> String {
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

        if let Some(created) = response.creation_date() {
            output.push(format!("- **Created**: `{}`", created.format("%Y-%m-%d")));
        }
        if let Some(expires) = response.expiration_date() {
            let days_until = days_until(expires);
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

        // Contact sections last: each `###` heading scopes everything below
        // it, so no domain-level field may follow one.
        let infos = contact::rdap_contacts(response);
        push_contacts(&mut output, contact::rdap_views(&infos));
        let billing = response.get_billing_contact();
        push_contact(&mut output, "Billing", Contact::rdap(billing.as_ref()));

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
