use super::*;

impl HumanFormatter {
    pub(super) fn format_lookup(&self, result: &LookupResult) -> String {
        let mut output = Vec::new();

        let domain = result
            .domain_name()
            .unwrap_or_else(|| "Unknown".to_string());
        let header_suffix = match result {
            LookupResult::Rdap { .. } => "via RDAP".to_string(),
            LookupResult::Whois { .. } => "via WHOIS".to_string(),
            LookupResult::Available { data, .. } => match data.verdict() {
                "available" => "available".to_string(),
                "likely_available" => "likely available".to_string(),
                "registered" => "registered".to_string(),
                "likely_registered" => "likely registered".to_string(),
                _ => "status unknown".to_string(),
            },
        };

        output.push(self.header(&format!(
            "Lookup: {} ({})",
            sanitize_display(&domain),
            header_suffix
        )));

        match result {
            LookupResult::Rdap {
                data,
                whois_fallback,
            } => {
                output.push(format!(
                    "  {}: {}",
                    self.label("Source"),
                    self.success("RDAP (modern protocol)")
                ));

                if let Some(registrar) = data.get_registrar() {
                    output.push(format!(
                        "  {}: {}",
                        self.label("Registrar"),
                        self.value(&sanitize_display(&registrar))
                    ));
                }

                if let Some(registrant) = data.get_registrant() {
                    output.push(format!(
                        "  {}: {}",
                        self.label("Registrant"),
                        self.value(&sanitize_display(&registrant))
                    ));
                }

                if let Some(organization) = data.get_registrant_organization() {
                    output.push(format!(
                        "  {}: {}",
                        self.label("Organization"),
                        self.value(&sanitize_display(&organization))
                    ));
                }

                // Registrant contact details
                if let Some(contact) = data.get_registrant_contact() {
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
                if let Some(contact) = data.get_admin_contact() {
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
                    }
                }

                // Tech contact
                if let Some(contact) = data.get_tech_contact() {
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
                    }
                }

                if let Some(created) = data.creation_date() {
                    output.push(format!(
                        "  {}: {}",
                        self.label("Created"),
                        self.value(&created.format("%Y-%m-%d").to_string())
                    ));
                }

                if let Some(expires) = data.expiration_date() {
                    let days_until = (expires - chrono::Utc::now()).num_days();
                    let expiry_str = expires.format("%Y-%m-%d").to_string();
                    let status = self.format_expiry_status(&expiry_str, days_until);
                    output.push(format!("  {}: {}", self.label("Expires"), status));
                }

                if !data.status.is_empty() {
                    output.push(format!("  {}:", self.label("Status")));
                    for status in &data.status {
                        output.push(format!("    - {}", self.value(&sanitize_display(status))));
                    }
                }

                let nameservers = data.nameserver_names();
                if !nameservers.is_empty() {
                    output.push(format!("  {}:", self.label("Nameservers")));
                    for ns in &nameservers {
                        output.push(format!("    - {}", self.value(&sanitize_display(ns))));
                    }
                }

                if data.is_dnssec_signed() {
                    output.push(format!(
                        "  {}: {}",
                        self.label("DNSSEC"),
                        self.success("signed")
                    ));
                }

                if let Some(whois) = whois_fallback {
                    let mut extra = Vec::new();

                    // Registrant (if RDAP didn't have it)
                    if data.get_registrant().is_none() {
                        if let Some(ref registrant) = whois.registrant {
                            extra.push(format!(
                                "    {}: {}",
                                self.label("Registrant"),
                                self.value(&sanitize_display(registrant))
                            ));
                        }
                    }

                    // Organization (if RDAP didn't have it)
                    if data.get_registrant_organization().is_none() {
                        if let Some(ref org) = whois.organization {
                            extra.push(format!(
                                "    {}: {}",
                                self.label("Organization"),
                                self.value(&sanitize_display(org))
                            ));
                        }
                    }

                    // Registrant contact details (if RDAP didn't have them)
                    let rdap_registrant = data.get_registrant_contact();
                    let rdap_has_registrant =
                        rdap_registrant.as_ref().is_some_and(|c| c.has_info());
                    if !rdap_has_registrant {
                        let has_whois_contact = whois.registrant_email.is_some()
                            || whois.registrant_phone.is_some()
                            || whois.registrant_address.is_some()
                            || whois.registrant_country.is_some();
                        if has_whois_contact {
                            extra.push(format!("\n    {}:", self.label("Registrant Contact")));
                            if let Some(ref email) = whois.registrant_email {
                                extra.push(format!(
                                    "      {}: {}",
                                    self.label("Email"),
                                    self.value(&sanitize_display(email))
                                ));
                            }
                            if let Some(ref phone) = whois.registrant_phone {
                                extra.push(format!(
                                    "      {}: {}",
                                    self.label("Phone"),
                                    self.value(&sanitize_display(phone))
                                ));
                            }
                            if let Some(ref address) = whois.registrant_address {
                                extra.push(format!(
                                    "      {}: {}",
                                    self.label("Address"),
                                    self.value(&sanitize_display(address))
                                ));
                            }
                            if let Some(ref country) = whois.registrant_country {
                                extra.push(format!(
                                    "      {}: {}",
                                    self.label("Country"),
                                    self.value(&sanitize_display(country))
                                ));
                            }
                        }
                    }

                    // Admin contact (if RDAP didn't have it)
                    let rdap_has_admin = data.get_admin_contact().is_some_and(|c| c.has_info());
                    if !rdap_has_admin {
                        let has_whois_admin = whois.admin_name.is_some()
                            || whois.admin_email.is_some()
                            || whois.admin_phone.is_some();
                        if has_whois_admin {
                            extra.push(format!("\n    {}:", self.label("Admin Contact")));
                            if let Some(ref name) = whois.admin_name {
                                extra.push(format!(
                                    "      {}: {}",
                                    self.label("Name"),
                                    self.value(&sanitize_display(name))
                                ));
                            }
                            if let Some(ref org) = whois.admin_organization {
                                extra.push(format!(
                                    "      {}: {}",
                                    self.label("Organization"),
                                    self.value(&sanitize_display(org))
                                ));
                            }
                            if let Some(ref email) = whois.admin_email {
                                extra.push(format!(
                                    "      {}: {}",
                                    self.label("Email"),
                                    self.value(&sanitize_display(email))
                                ));
                            }
                            if let Some(ref phone) = whois.admin_phone {
                                extra.push(format!(
                                    "      {}: {}",
                                    self.label("Phone"),
                                    self.value(&sanitize_display(phone))
                                ));
                            }
                        }
                    }

                    // Tech contact (if RDAP didn't have it)
                    let rdap_has_tech = data.get_tech_contact().is_some_and(|c| c.has_info());
                    if !rdap_has_tech {
                        let has_whois_tech = whois.tech_name.is_some()
                            || whois.tech_email.is_some()
                            || whois.tech_phone.is_some();
                        if has_whois_tech {
                            extra.push(format!("\n    {}:", self.label("Tech Contact")));
                            if let Some(ref name) = whois.tech_name {
                                extra.push(format!(
                                    "      {}: {}",
                                    self.label("Name"),
                                    self.value(&sanitize_display(name))
                                ));
                            }
                            if let Some(ref org) = whois.tech_organization {
                                extra.push(format!(
                                    "      {}: {}",
                                    self.label("Organization"),
                                    self.value(&sanitize_display(org))
                                ));
                            }
                            if let Some(ref email) = whois.tech_email {
                                extra.push(format!(
                                    "      {}: {}",
                                    self.label("Email"),
                                    self.value(&sanitize_display(email))
                                ));
                            }
                            if let Some(ref phone) = whois.tech_phone {
                                extra.push(format!(
                                    "      {}: {}",
                                    self.label("Phone"),
                                    self.value(&sanitize_display(phone))
                                ));
                            }
                        }
                    }

                    // Updated date (RDAP doesn't typically expose this)
                    if let Some(updated) = whois.updated_date {
                        extra.push(format!(
                            "    {}: {}",
                            self.label("Updated"),
                            self.value(&updated.format("%Y-%m-%d").to_string())
                        ));
                    }

                    // DNSSEC (if RDAP didn't show it)
                    if !data.is_dnssec_signed() {
                        if let Some(ref dnssec) = whois.dnssec {
                            extra.push(format!(
                                "    {}: {}",
                                self.label("DNSSEC"),
                                self.value(&sanitize_display(dnssec))
                            ));
                        }
                    }

                    // WHOIS server
                    if !whois.whois_server.is_empty() {
                        extra.push(format!(
                            "    {}: {}",
                            self.label("WHOIS Server"),
                            self.value(&sanitize_display(&whois.whois_server))
                        ));
                    }

                    if !extra.is_empty() {
                        output.push(format!("\n  {}", self.label("Additional WHOIS data:")));
                        output.extend(extra);
                    }
                }
            }
            LookupResult::Whois {
                data, rdap_error, ..
            } => {
                let source_note = if rdap_error.is_some() {
                    "WHOIS (RDAP unavailable)"
                } else {
                    "WHOIS"
                };
                output.push(format!(
                    "  {}: {}",
                    self.label("Source"),
                    self.warning(source_note)
                ));

                if let Some(ref error) = rdap_error {
                    output.push(format!(
                        "  {}: {}",
                        self.label("RDAP Error"),
                        self.error(error)
                    ));
                }

                if let Some(ref registrar) = data.registrar {
                    output.push(format!(
                        "  {}: {}",
                        self.label("Registrar"),
                        self.value(&sanitize_display(registrar))
                    ));
                }

                if let Some(ref registrant) = data.registrant {
                    output.push(format!(
                        "  {}: {}",
                        self.label("Registrant"),
                        self.value(&sanitize_display(registrant))
                    ));
                }

                if let Some(ref organization) = data.organization {
                    output.push(format!(
                        "  {}: {}",
                        self.label("Organization"),
                        self.value(&sanitize_display(organization))
                    ));
                }

                // Registrant contact details
                let has_registrant_details = data.registrant_email.is_some()
                    || data.registrant_phone.is_some()
                    || data.registrant_address.is_some()
                    || data.registrant_country.is_some();

                if has_registrant_details {
                    output.push(format!("\n  {}:", self.label("Registrant Contact")));
                    if let Some(ref email) = data.registrant_email {
                        output.push(format!(
                            "    {}: {}",
                            self.label("Email"),
                            self.value(&sanitize_display(email))
                        ));
                    }
                    if let Some(ref phone) = data.registrant_phone {
                        output.push(format!(
                            "    {}: {}",
                            self.label("Phone"),
                            self.value(&sanitize_display(phone))
                        ));
                    }
                    if let Some(ref address) = data.registrant_address {
                        output.push(format!(
                            "    {}: {}",
                            self.label("Address"),
                            self.value(&sanitize_display(address))
                        ));
                    }
                    if let Some(ref country) = data.registrant_country {
                        output.push(format!(
                            "    {}: {}",
                            self.label("Country"),
                            self.value(&sanitize_display(country))
                        ));
                    }
                }

                // Admin contact
                let has_admin_contact = data.admin_name.is_some()
                    || data.admin_organization.is_some()
                    || data.admin_email.is_some()
                    || data.admin_phone.is_some();

                if has_admin_contact {
                    output.push(format!("\n  {}:", self.label("Admin Contact")));
                    if let Some(ref name) = data.admin_name {
                        output.push(format!(
                            "    {}: {}",
                            self.label("Name"),
                            self.value(&sanitize_display(name))
                        ));
                    }
                    if let Some(ref org) = data.admin_organization {
                        output.push(format!(
                            "    {}: {}",
                            self.label("Organization"),
                            self.value(&sanitize_display(org))
                        ));
                    }
                    if let Some(ref email) = data.admin_email {
                        output.push(format!(
                            "    {}: {}",
                            self.label("Email"),
                            self.value(&sanitize_display(email))
                        ));
                    }
                    if let Some(ref phone) = data.admin_phone {
                        output.push(format!(
                            "    {}: {}",
                            self.label("Phone"),
                            self.value(&sanitize_display(phone))
                        ));
                    }
                }

                // Tech contact
                let has_tech_contact = data.tech_name.is_some()
                    || data.tech_organization.is_some()
                    || data.tech_email.is_some()
                    || data.tech_phone.is_some();

                if has_tech_contact {
                    output.push(format!("\n  {}:", self.label("Tech Contact")));
                    if let Some(ref name) = data.tech_name {
                        output.push(format!(
                            "    {}: {}",
                            self.label("Name"),
                            self.value(&sanitize_display(name))
                        ));
                    }
                    if let Some(ref org) = data.tech_organization {
                        output.push(format!(
                            "    {}: {}",
                            self.label("Organization"),
                            self.value(&sanitize_display(org))
                        ));
                    }
                    if let Some(ref email) = data.tech_email {
                        output.push(format!(
                            "    {}: {}",
                            self.label("Email"),
                            self.value(&sanitize_display(email))
                        ));
                    }
                    if let Some(ref phone) = data.tech_phone {
                        output.push(format!(
                            "    {}: {}",
                            self.label("Phone"),
                            self.value(&sanitize_display(phone))
                        ));
                    }
                }

                if let Some(created) = data.creation_date {
                    output.push(format!(
                        "  {}: {}",
                        self.label("Created"),
                        self.value(&created.format("%Y-%m-%d").to_string())
                    ));
                }

                if let Some(expires) = data.expiration_date {
                    let days_until = (expires - chrono::Utc::now()).num_days();
                    let expiry_str = expires.format("%Y-%m-%d").to_string();
                    let status = self.format_expiry_status(&expiry_str, days_until);
                    output.push(format!("  {}: {}", self.label("Expires"), status));
                }

                if !data.status.is_empty() {
                    output.push(format!("  {}:", self.label("Status")));
                    for status in &data.status {
                        output.push(format!("    - {}", self.value(&sanitize_display(status))));
                    }
                }

                if !data.nameservers.is_empty() {
                    output.push(format!("  {}:", self.label("Nameservers")));
                    for ns in &data.nameservers {
                        output.push(format!("    - {}", self.value(&sanitize_display(ns))));
                    }
                }

                if let Some(ref dnssec) = data.dnssec {
                    output.push(format!(
                        "  {}: {}",
                        self.label("DNSSEC"),
                        self.value(&sanitize_display(dnssec))
                    ));
                }
            }
            LookupResult::Available {
                data,
                rdap_error,
                whois_error,
                whois_data,
            } => {
                let source_note = if whois_data.is_some() {
                    "WHOIS (RDAP unavailable)"
                } else {
                    "availability check (RDAP and WHOIS failed)"
                };
                output.push(format!(
                    "  {}: {}",
                    self.label("Source"),
                    self.warning(source_note)
                ));

                let verdict_colored = match data.verdict() {
                    "available" => self.success("AVAILABLE"),
                    "likely_available" => self.warning("MAY BE AVAILABLE"),
                    "registered" => self.value("REGISTERED"),
                    "likely_registered" => self.warning("LIKELY REGISTERED"),
                    _ => self.error("UNKNOWN"),
                };
                output.push(format!("  {}: {}", self.label("Verdict"), verdict_colored));

                // Confidence colouring is purely about certainty, independent of
                // the registered/available answer.
                let confidence_colored = match data.confidence.as_str() {
                    "high" => self.success(&data.confidence),
                    "medium" => self.warning(&data.confidence),
                    _ => self.error(&data.confidence),
                };
                output.push(format!(
                    "  {}: {}",
                    self.label("Confidence"),
                    confidence_colored
                ));

                output.push(format!(
                    "  {}: {}",
                    self.label("Method"),
                    self.value(&sanitize_display(&data.method))
                ));

                if let Some(details) = &data.details {
                    output.push(format!(
                        "  {}: {}",
                        self.label("Details"),
                        self.value(&sanitize_display(details))
                    ));
                }

                if !rdap_error.is_empty() {
                    output.push(format!(
                        "  {}: {}",
                        self.label("RDAP Error"),
                        self.error(rdap_error)
                    ));
                }
                if !whois_error.is_empty() {
                    output.push(format!(
                        "  {}: {}",
                        self.label("WHOIS Error"),
                        self.error(whois_error)
                    ));
                }

                if let Some(w) = whois_data {
                    let mut extra = Vec::new();
                    if !w.nameservers.is_empty() {
                        extra.push(format!(
                            "    {}: {}",
                            self.label("Nameservers"),
                            self.value(&sanitize_display(&w.nameservers.join(", ")))
                        ));
                    }
                    if !w.status.is_empty() {
                        extra.push(format!(
                            "    {}: {}",
                            self.label("Status"),
                            self.value(&sanitize_display(&w.status.join(", ")))
                        ));
                    }
                    if let Some(ref dnssec) = w.dnssec {
                        extra.push(format!(
                            "    {}: {}",
                            self.label("DNSSEC"),
                            self.value(&sanitize_display(dnssec))
                        ));
                    }
                    if !w.whois_server.is_empty() {
                        extra.push(format!(
                            "    {}: {}",
                            self.label("WHOIS Server"),
                            self.value(&sanitize_display(&w.whois_server))
                        ));
                    }
                    if !extra.is_empty() {
                        output.push(format!("  {}", self.label("Additional WHOIS data:")));
                        output.extend(extra);
                    }
                }
            }
        }

        output.join("\n")
    }

    pub(super) fn format_availability(
        &self,
        result: &crate::availability::AvailabilityResult,
    ) -> String {
        let mut output = Vec::new();

        let status = if result.available {
            self.success("AVAILABLE")
        } else {
            self.error("TAKEN")
        };
        output.push(format!("{}: {}", sanitize_display(&result.domain), status));
        let confidence_colored = match result.confidence.as_str() {
            "high" => self.success(&result.confidence),
            "medium" => self.warning(&result.confidence),
            _ => self.error(&result.confidence),
        };
        output.push(format!(
            "  {}: {}",
            self.label("Confidence"),
            confidence_colored
        ));
        output.push(format!(
            "  {}: {}",
            self.label("Method"),
            self.value(&sanitize_display(&result.method))
        ));
        if let Some(ref details) = result.details {
            // `details` in `decide_fallback` can interpolate raw `rdap_err`
            // / `whois_err` strings — those originate from third-party
            // servers and may contain ANSI escapes. Strip before display
            // matching every other value-rendering site in this formatter.
            output.push(format!(
                "  {}: {}",
                self.label("Details"),
                self.value(&sanitize_display(details))
            ));
        }

        output.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lookup::LookupResult;

    fn formatter() -> HumanFormatter {
        HumanFormatter::new().without_colors()
    }

    fn availability_lookup(available: bool, confidence: &str) -> LookupResult {
        LookupResult::Available {
            data: Box::new(crate::availability::AvailabilityResult {
                domain: "myroyalcanin.lv".to_string(),
                available,
                confidence: confidence.to_string(),
                method: "whois".to_string(),
                details: None,
            }),
            rdap_error: "bootstrap failed".to_string(),
            whois_error: String::new(),
            whois_data: None,
        }
    }

    #[test]
    fn format_lookup_registered_high_confidence_does_not_say_available() {
        // Regression: a `LookupResult::Available` with `available: false` was
        // previously rendered as "AVAILABLE" because the formatter branched on
        // `confidence` alone. See myroyalcanin.lv investigation.
        let f = formatter();
        let out = f.format_lookup(&availability_lookup(false, "high"));
        assert!(
            !out.contains("AVAILABLE"),
            "must not claim available:\n{}",
            out
        );
        assert!(
            out.contains("REGISTERED"),
            "must render REGISTERED:\n{}",
            out
        );
        assert!(
            out.contains("(registered)"),
            "header suffix must say registered:\n{}",
            out
        );
    }

    #[test]
    fn format_lookup_available_high_confidence_still_says_available() {
        let f = formatter();
        let out = f.format_lookup(&availability_lookup(true, "high"));
        assert!(
            out.contains("AVAILABLE"),
            "high-confidence available:\n{}",
            out
        );
        assert!(out.contains("(available)"), "header suffix:\n{}", out);
    }

    #[test]
    fn format_lookup_likely_registered_medium_confidence() {
        let f = formatter();
        let out = f.format_lookup(&availability_lookup(false, "medium"));
        assert!(out.contains("LIKELY REGISTERED"), "medium reg:\n{}", out);
        assert!(
            !out.contains("MAY BE AVAILABLE"),
            "must not say MAY BE AVAILABLE:\n{}",
            out
        );
    }

    #[test]
    fn domain_info_verdict_registered_for_high_confidence_unavailable() {
        // Regression: DomainInfo::availability_verdict ignored data.available.
        let lookup = availability_lookup(false, "high");
        let info = crate::domain_info::DomainInfo::from_lookup_result(&lookup);
        assert_eq!(info.availability_verdict.as_deref(), Some("registered"));
    }
}
