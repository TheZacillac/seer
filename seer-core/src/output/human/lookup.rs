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

                let infos = contact::rdap_contacts(data);
                let rdap_contacts = detail_views(&infos);
                self.push_contacts(&mut output, "  ", rdap_contacts);

                if let Some(created) = data.creation_date() {
                    output.push(format!(
                        "  {}: {}",
                        self.label("Created"),
                        self.value(&created.format("%Y-%m-%d").to_string())
                    ));
                }

                if let Some(expires) = data.expiration_date() {
                    let days_until = days_until(expires);
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

                    // Contact blocks RDAP didn't render.
                    let fallback = contact::ROLES
                        .into_iter()
                        .zip(rdap_contacts)
                        .zip(whois.contacts());
                    for ((role, rdap), whois_contact) in fallback {
                        if rdap.is_empty() {
                            self.push_contact(&mut extra, "    ", role, whois_contact);
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

                // Error strings can carry upstream server text (e.g. an
                // IANA-returned WHOIS server name), so sanitize like any
                // other remote-sourced value.
                if let Some(ref error) = rdap_error {
                    output.push(format!(
                        "  {}: {}",
                        self.label("RDAP Error"),
                        self.error(&sanitize_display(error))
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

                self.push_contacts(&mut output, "  ", data.contacts());

                if let Some(created) = data.creation_date {
                    output.push(format!(
                        "  {}: {}",
                        self.label("Created"),
                        self.value(&created.format("%Y-%m-%d").to_string())
                    ));
                }

                if let Some(expires) = data.expiration_date {
                    let days_until = days_until(expires);
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
                        self.error(&sanitize_display(rdap_error))
                    ));
                }
                if !whois_error.is_empty() {
                    output.push(format!(
                        "  {}: {}",
                        self.label("WHOIS Error"),
                        self.error(&sanitize_display(whois_error))
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
    fn format_lookup_sanitizes_protocol_error_strings() {
        // rdap_error / whois_error can carry upstream server text (e.g. an
        // IANA-returned WHOIS server name); they were printed raw while every
        // adjacent value went through sanitize_display.
        let evil = "connect to whois.evil\x1b]52;c;AAAA\x07\x1b[2J failed";
        let whois = WhoisResponse::parse("example.com", "whois.test", "Registrar: R\n");
        let whois_variant = LookupResult::Whois {
            data: whois,
            rdap_error: Some(evil.to_string()),
            rdap_fallback: None,
        };
        let available_variant = LookupResult::Available {
            data: Box::new(crate::availability::AvailabilityResult {
                domain: "example.com".to_string(),
                available: false,
                confidence: "low".to_string(),
                method: "none".to_string(),
                details: None,
            }),
            rdap_error: evil.to_string(),
            whois_error: evil.to_string(),
            whois_data: None,
        };
        for result in [whois_variant, available_variant] {
            let out = formatter().format_lookup(&result);
            assert!(!out.contains('\x1b'), "ESC reached terminal: {out:?}");
            assert!(!out.contains('\x07'), "BEL reached terminal: {out:?}");
            assert!(
                out.contains("connect to whois.evil failed"),
                "error text kept: {out:?}"
            );
        }
    }

    #[test]
    fn format_lookup_whois_fallback_keeps_organization_only_contacts() {
        // The WHOIS-fallback admin/tech gate ignored the organization field,
        // so a contact carrying only an organization (common once a registry
        // redacts the personal fields) vanished from `seer lookup` while
        // `seer whois` showed it.
        let mut whois = WhoisResponse::parse("example.com", "whois.test", "Registrar: R\n");
        whois.admin_organization = Some("Admin Org LLC".to_string());
        whois.tech_organization = Some("Tech Org LLC".to_string());
        let rdap: RdapResponse =
            serde_json::from_value(serde_json::json!({"ldhName": "example.com"})).unwrap();
        let result = LookupResult::Rdap {
            data: Box::new(rdap),
            whois_fallback: Some(whois),
        };
        let out = formatter().format_lookup(&result);
        for needle in [
            "Admin Contact",
            "Admin Org LLC",
            "Tech Contact",
            "Tech Org LLC",
        ] {
            assert!(out.contains(needle), "missing {needle:?}:\n{out}");
        }
    }

    /// RDAP whose registrant entity carries only a name and organization.
    fn rdap_registrant_identity_only() -> RdapResponse {
        serde_json::from_value(serde_json::json!({
            "ldhName": "example.com",
            "entities": [{
                "objectClassName": "entity",
                "roles": ["registrant"],
                "vcardArray": ["vcard", [
                    ["fn", {}, "text", "Jane Registrant"],
                    ["org", {}, "text", "Example LLC"]
                ]]
            }]
        }))
        .unwrap()
    }

    #[test]
    fn rdap_registrant_identity_only_opens_no_empty_contact_heading() {
        // has_info() counts name/organization, but the Registrant Contact
        // block renders only email/phone/address/country (name and org are
        // the top-level lines), so this printed a bare heading.
        let out = formatter().format_rdap(&rdap_registrant_identity_only());
        assert!(out.contains("Registrant: Jane Registrant"), "got:\n{out}");
        assert!(
            !out.contains("Registrant Contact"),
            "empty heading rendered:\n{out}"
        );
    }

    #[test]
    fn format_lookup_falls_back_to_whois_registrant_details() {
        // The same identity-only RDAP registrant also counted as "RDAP has
        // registrant details", suppressing the WHOIS fallback's email.
        let mut whois = WhoisResponse::parse("example.com", "whois.test", "Registrar: R\n");
        whois.registrant_email = Some("owner@example.com".to_string());
        let result = LookupResult::Rdap {
            data: Box::new(rdap_registrant_identity_only()),
            whois_fallback: Some(whois),
        };
        let out = formatter().format_lookup(&result);
        assert_eq!(out.matches("Registrant Contact").count(), 1, "got:\n{out}");
        assert!(out.contains("Email: owner@example.com"), "got:\n{out}");
    }

    #[test]
    fn format_lookup_rdap_admin_and_tech_show_postal_details() {
        // The lookup view rendered RDAP admin/tech contacts with the WHOIS
        // field set (name/org/email/phone) and dropped the address and
        // country that `seer rdap` and markdown lookup both show.
        let entities = ["administrative", "technical"].map(|role| {
            serde_json::json!({
                "objectClassName": "entity",
                "roles": [role],
                "vcardArray": ["vcard", [
                    ["fn", {}, "text", format!("{role} person")],
                    ["adr", {}, "text", ["", "", "1 Main St", "Springfield", "", "", "US"]]
                ]]
            })
        });
        let rdap: RdapResponse = serde_json::from_value(serde_json::json!({
            "ldhName": "example.com",
            "entities": entities,
        }))
        .unwrap();
        let result = LookupResult::Rdap {
            data: Box::new(rdap),
            whois_fallback: None,
        };
        let out = formatter().format_lookup(&result);
        assert_eq!(
            out.matches("Address: 1 Main St, Springfield, US").count(),
            2,
            "got:\n{out}"
        );
        assert_eq!(out.matches("Country: US").count(), 2, "got:\n{out}");
    }

    #[test]
    fn domain_info_verdict_registered_for_high_confidence_unavailable() {
        // Regression: DomainInfo::availability_verdict ignored data.available.
        let lookup = availability_lookup(false, "high");
        let info = crate::domain_info::DomainInfo::from_lookup_result(&lookup);
        assert_eq!(info.availability_verdict.as_deref(), Some("registered"));
    }
}
