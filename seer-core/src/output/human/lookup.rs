use super::*;

impl HumanFormatter {
    pub(super) fn format_lookup(&self, result: &LookupResult) -> String {
        let domain = result
            .domain_name()
            .unwrap_or_else(|| "Unknown".to_string());
        let header_suffix = match result {
            LookupResult::Rdap { .. } => "via RDAP",
            LookupResult::Whois { .. } => "via WHOIS",
            LookupResult::Available { data, .. } => match data.verdict() {
                "available" => "available",
                "likely_available" => "likely available",
                "registered" => "registered",
                "likely_registered" => "likely registered",
                _ => "status unknown",
            },
        };

        let mut output = vec![self.header(&format!(
            "Lookup: {} ({})",
            sanitize_display(&domain),
            header_suffix
        ))];
        let mut rows = self.rows(&mut output, "  ");

        match result {
            LookupResult::Rdap {
                data,
                whois_fallback,
            } => {
                rows.kv("Source", self.success("RDAP (modern protocol)"));
                rows.opt("Registrar", &data.get_registrar());
                rows.opt("Registrant", &data.get_registrant());
                rows.opt("Organization", &data.get_registrant_organization());
                let infos = contact::rdap_contacts(data);
                let rdap_contacts = detail_views(&infos);
                rows.contacts(rdap_contacts);
                rows.date("Created", data.creation_date());
                rows.expires(data.expiration_date());
                rows.list("Status", &data.status);
                rows.list("Nameservers", &data.nameserver_names());
                if data.is_dnssec_signed() {
                    rows.kv("DNSSEC", self.success("signed"));
                }

                if let Some(whois) = whois_fallback {
                    // Only what RDAP didn't already show.
                    let mut extra = Vec::new();
                    let mut fill = self.rows(&mut extra, "    ");
                    if data.get_registrant().is_none() {
                        fill.opt("Registrant", &whois.registrant);
                    }
                    if data.get_registrant_organization().is_none() {
                        fill.opt("Organization", &whois.organization);
                    }
                    let fallback = contact::ROLES
                        .into_iter()
                        .zip(rdap_contacts)
                        .zip(whois.contacts());
                    for ((role, rdap), whois_contact) in fallback {
                        if rdap.is_empty() {
                            fill.contact(role, whois_contact);
                        }
                    }
                    // RDAP doesn't typically expose an updated date.
                    fill.date("Updated", whois.updated_date);
                    if !data.is_dnssec_signed() {
                        fill.opt("DNSSEC", &whois.dnssec);
                    }
                    if !whois.whois_server.is_empty() {
                        fill.text("WHOIS Server", &whois.whois_server);
                    }

                    if !extra.is_empty() {
                        rows.push(format!("\n  {}", self.label("Additional WHOIS data:")));
                        rows.extend(extra);
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
                rows.kv("Source", self.warning(source_note));
                // Error strings can carry upstream server text (e.g. an
                // IANA-returned WHOIS server name), so sanitize like any
                // other remote-sourced value.
                if let Some(error) = rdap_error {
                    rows.kv("RDAP Error", self.error(&sanitize_display(error)));
                }
                rows.opt("Registrar", &data.registrar);
                rows.opt("Registrant", &data.registrant);
                rows.opt("Organization", &data.organization);
                rows.contacts(data.contacts());
                rows.date("Created", data.creation_date);
                rows.expires(data.expiration_date);
                rows.list("Status", &data.status);
                rows.list("Nameservers", &data.nameservers);
                rows.opt("DNSSEC", &data.dnssec);
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
                rows.kv("Source", self.warning(source_note));

                let verdict = match data.verdict() {
                    "available" => self.success("AVAILABLE"),
                    "likely_available" => self.warning("MAY BE AVAILABLE"),
                    "registered" => self.value("REGISTERED"),
                    "likely_registered" => self.warning("LIKELY REGISTERED"),
                    _ => self.error("UNKNOWN"),
                };
                rows.kv("Verdict", verdict);
                rows.kv("Confidence", self.confidence(&data.confidence));
                rows.text("Method", &data.method);
                rows.opt("Details", &data.details);
                if !rdap_error.is_empty() {
                    rows.kv("RDAP Error", self.error(&sanitize_display(rdap_error)));
                }
                if !whois_error.is_empty() {
                    rows.kv("WHOIS Error", self.error(&sanitize_display(whois_error)));
                }

                if let Some(w) = whois_data {
                    let mut extra = Vec::new();
                    let mut fill = self.rows(&mut extra, "    ");
                    if !w.nameservers.is_empty() {
                        fill.text("Nameservers", &w.nameservers.join(", "));
                    }
                    if !w.status.is_empty() {
                        fill.text("Status", &w.status.join(", "));
                    }
                    fill.opt("DNSSEC", &w.dnssec);
                    if !w.whois_server.is_empty() {
                        fill.text("WHOIS Server", &w.whois_server);
                    }
                    if !extra.is_empty() {
                        rows.push(format!("  {}", self.label("Additional WHOIS data:")));
                        rows.extend(extra);
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
        let status = if result.available {
            self.success("AVAILABLE")
        } else {
            self.error("TAKEN")
        };
        let mut output = vec![format!("{}: {}", sanitize_display(&result.domain), status)];
        let mut rows = self.rows(&mut output, "  ");
        rows.kv("Confidence", self.confidence(&result.confidence));
        rows.text("Method", &result.method);
        // `details` in `decide_fallback` can interpolate raw `rdap_err` /
        // `whois_err` strings from third-party servers, so it is sanitized
        // like every other remote value.
        rows.opt("Details", &result.details);

        output.join("\n")
    }

    /// Colors an availability confidence purely by certainty, independent of
    /// the registered/available answer.
    fn confidence(&self, confidence: &str) -> String {
        match confidence {
            "high" => self.success(confidence),
            "medium" => self.warning(confidence),
            _ => self.error(confidence),
        }
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
