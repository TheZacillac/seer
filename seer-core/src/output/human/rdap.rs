use super::*;

impl HumanFormatter {
    pub(super) fn format_rdap(&self, response: &RdapResponse) -> String {
        let name = response
            .domain_name()
            .or(response.name.as_deref())
            .unwrap_or("Unknown");
        let mut output = vec![self.header(&format!("RDAP: {}", sanitize_display(name)))];

        let mut rows = self.rows(&mut output, "  ");
        rows.opt("Handle", &response.handle);
        rows.opt("Registrar", &response.get_registrar());
        rows.opt("Registrant", &response.get_registrant());
        rows.opt("Organization", &response.get_registrant_organization());

        let infos = contact::rdap_contacts(response);
        rows.contacts(detail_views(&infos));
        let billing = response.get_billing_contact();
        rows.contact("Billing", Contact::rdap(billing.as_ref()));

        rows.date("Created", response.creation_date());
        rows.expires(response.expiration_date());
        rows.date("Updated", response.last_updated());
        rows.list("Status", &response.status);
        rows.list("Nameservers", &response.nameserver_names());
        if response.is_dnssec_signed() {
            rows.kv("DNSSEC", self.success("signed"));
        }

        // IP-specific fields
        rows.opt("Start Address", &response.start_address);
        rows.opt("End Address", &response.end_address);
        rows.opt("Country", &response.country);

        // ASN-specific fields
        if let Some(start) = response.start_autnum {
            let end = response.end_autnum.unwrap_or(start);
            rows.kv("AS Number", self.value(&format!("AS{start} - AS{end}")));
        }

        output.join("\n")
    }
}
