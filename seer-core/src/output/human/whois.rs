use super::*;

impl HumanFormatter {
    pub(super) fn format_whois(&self, response: &WhoisResponse) -> String {
        let mut output =
            vec![self.header(&format!("WHOIS: {}", sanitize_display(&response.domain)))];

        if response.is_available() {
            output.push(format!("  {} Domain is available", self.success("✓")));
            return output.join("\n");
        }

        let mut rows = self.rows(&mut output, "  ");
        rows.opt("Registrar", &response.registrar);
        rows.opt("Registrant", &response.registrant);
        rows.opt("Organization", &response.organization);
        rows.contacts(response.contacts());
        rows.date("Created", response.creation_date);
        rows.expires(response.expiration_date);
        rows.date("Updated", response.updated_date);
        rows.list("Nameservers", &response.nameservers);
        rows.list("Status", &response.status);
        rows.opt("DNSSEC", &response.dnssec);
        rows.text("WHOIS Server", &response.whois_server);

        output.join("\n")
    }
}
