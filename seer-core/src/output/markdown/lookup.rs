use super::*;

impl MarkdownFormatter {
    pub(super) fn format_lookup(&self, result: &LookupResult) -> String {
        let domain = result
            .domain_name()
            .unwrap_or_else(|| "Unknown".to_string());
        let source = match result {
            LookupResult::Rdap { .. } => "RDAP",
            LookupResult::Whois { .. } => "WHOIS",
            LookupResult::Available { .. } => "availability",
        };

        let mut output = vec![format!("## Lookup: {}", MdSafe(&domain)), String::new()];
        let mut b = Bullets(&mut output);
        b.raw("Source", source);

        match result {
            LookupResult::Rdap {
                data,
                whois_fallback,
            } => {
                b.opt("Registrar", &data.get_registrar());
                b.opt("Registrant", &data.get_registrant());
                b.opt("Organization", &data.get_registrant_organization());
                b.date("Created", data.creation_date());
                b.expires(data.expiration_date());
                b.code_list("Status", &data.status);
                b.code_list("Nameservers", &data.nameserver_names());
                if data.is_dnssec_signed() {
                    b.raw("DNSSEC", "signed");
                }

                // Contact sections from RDAP — after every domain-level
                // bullet, since a `###` heading scopes everything below it.
                let infos = contact::rdap_contacts(data);
                let rdap_contacts = contact::rdap_views(&infos);
                b.contacts(rdap_contacts);

                // WHOIS fallback data, limited to what RDAP didn't show:
                // bullets first, then any fallback contact sections (same
                // heading-scope rule as above).
                if let Some(whois) = whois_fallback {
                    let mut extra = Vec::new();
                    let mut fill = Bullets(&mut extra);
                    if data.get_registrant().is_none() {
                        fill.opt("Registrant", &whois.registrant);
                    }
                    if data.get_registrant_organization().is_none() {
                        fill.opt("Organization", &whois.organization);
                    }
                    fill.date("Updated", whois.updated_date);
                    if !data.is_dnssec_signed() {
                        fill.opt("DNSSEC", &whois.dnssec);
                    }
                    if !whois.whois_server.is_empty() {
                        fill.code("WHOIS Server", &whois.whois_server);
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

                    if !extra.is_empty() {
                        output.extend([
                            String::new(),
                            "### Additional WHOIS Data".to_string(),
                            String::new(),
                        ]);
                        output.extend(extra);
                    }
                }
            }
            LookupResult::Whois {
                data, rdap_error, ..
            } => {
                b.opt("RDAP Error", rdap_error);
                b.opt("Registrar", &data.registrar);
                b.opt("Registrant", &data.registrant);
                b.opt("Organization", &data.organization);
                b.date("Created", data.creation_date);
                b.expires(data.expiration_date);
                b.code_list("Status", &data.status);
                b.code_list("Nameservers", &data.nameservers);
                b.opt("DNSSEC", &data.dnssec);
                // Contact subsections last, after every domain-level bullet.
                b.contacts(data.contacts());
            }
            LookupResult::Available {
                data,
                rdap_error,
                whois_error,
                whois_data,
            } => {
                // Branch on the stable verdict (which considers `available`),
                // not `confidence` alone: a confidence:"high" result still
                // means "registered" when available == false. Mirrors the
                // human formatter; without this a registered domain reached
                // via the availability fallback rendered as "AVAILABLE".
                let verdict = match data.verdict() {
                    "available" => "AVAILABLE",
                    "likely_available" => "MAY BE AVAILABLE",
                    "registered" => "REGISTERED",
                    "likely_registered" => "LIKELY REGISTERED",
                    _ => "UNKNOWN",
                };
                b.raw("Verdict", verdict);
                b.raw("Confidence", &data.confidence);
                b.raw("Method", &data.method);
                b.opt("Details", &data.details);
                if !rdap_error.is_empty() {
                    b.text("RDAP Error", rdap_error);
                }
                if !whois_error.is_empty() {
                    b.text("WHOIS Error", whois_error);
                }

                if let Some(w) = whois_data {
                    let mut extra = Vec::new();
                    let mut fill = Bullets(&mut extra);
                    fill.code_list("Nameservers", &w.nameservers);
                    fill.code_list("Status", &w.status);
                    fill.opt("DNSSEC", &w.dnssec);
                    if !w.whois_server.is_empty() {
                        fill.code("WHOIS Server", &w.whois_server);
                    }
                    if !extra.is_empty() {
                        output.extend([
                            String::new(),
                            "### Additional WHOIS data".to_string(),
                            String::new(),
                        ]);
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
        let mut output = vec![
            format!("## Availability: {}", MdSafe(&result.domain)),
            String::new(),
        ];
        let mut b = Bullets(&mut output);
        let verdict = if result.available {
            "**AVAILABLE**"
        } else {
            "**TAKEN**"
        };
        b.raw("Result", verdict);
        b.raw("Confidence", &result.confidence);
        b.raw("Method", &result.method);
        b.opt("Details", &result.details);

        output.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_markdown_format_availability() {
        let result = crate::availability::AvailabilityResult {
            domain: "test.com".to_string(),
            available: true,
            confidence: "high".to_string(),
            method: "RDAP+WHOIS".to_string(),
            details: Some("Domain not found".to_string()),
        };
        let formatter = MarkdownFormatter::new();
        let output = formatter.format_availability(&result);
        assert!(output.contains("## Availability: test.com"));
        assert!(output.contains("**AVAILABLE**"));
        assert!(output.contains("high"));
    }

    #[test]
    fn format_lookup_registered_high_confidence_does_not_say_available() {
        // Regression: the Available arm branched on `confidence` alone, so a
        // confidently-*registered* domain (available:false, confidence:"high")
        // rendered as "AVAILABLE". It must say REGISTERED — the same fix the
        // human formatter already carries. This is the markdown rendering of
        // the dns_present "registered" verdict (e.g. zac.email).
        let result = LookupResult::Available {
            data: Box::new(crate::availability::AvailabilityResult {
                domain: "zac.email".to_string(),
                available: false,
                confidence: "high".to_string(),
                method: "dns_present".to_string(),
                details: Some("Domain is registered (delegated in DNS).".to_string()),
            }),
            rdap_error: String::new(),
            whois_error: String::new(),
            whois_data: None,
        };
        let out = MarkdownFormatter::new().format_lookup(&result);
        assert!(
            out.contains("REGISTERED"),
            "must render REGISTERED:\n{}",
            out
        );
        assert!(
            !out.contains("AVAILABLE"),
            "must not render AVAILABLE for a registered domain:\n{}",
            out
        );
    }

    #[test]
    fn format_lookup_whois_fallback_keeps_organization_only_contacts() {
        // Mirror of the human regression: an organization-only WHOIS
        // admin/tech contact was dropped from the RDAP-with-fallback view.
        let mut whois = WhoisResponse::parse("example.com", "whois.test", "Registrar: R\n");
        whois.admin_organization = Some("Admin Org LLC".to_string());
        whois.tech_organization = Some("Tech Org LLC".to_string());
        let rdap: RdapResponse =
            serde_json::from_value(serde_json::json!({"ldhName": "example.com"})).unwrap();
        let result = LookupResult::Rdap {
            data: Box::new(rdap),
            whois_fallback: Some(whois),
        };
        let out = MarkdownFormatter::new().format_lookup(&result);
        for needle in [
            "### Admin Contact",
            "- **Organization**: Admin Org LLC",
            "### Tech Contact",
            "- **Organization**: Tech Org LLC",
        ] {
            assert!(out.contains(needle), "missing {needle:?}:\n{out}");
        }
    }

    /// Asserts every `fields` bullet appears in `out` before `heading`.
    fn assert_fields_before(out: &str, heading: &str, fields: &[&str]) {
        let heading_at = out
            .find(heading)
            .unwrap_or_else(|| panic!("{heading:?} missing:\n{out}"));
        for field in fields {
            let at = out
                .find(field)
                .unwrap_or_else(|| panic!("{field:?} missing:\n{out}"));
            assert!(
                at < heading_at,
                "{field:?} rendered under {heading:?}:\n{out}"
            );
        }
    }

    fn whois_with_contacts() -> WhoisResponse {
        WhoisResponse::parse(
            "example.com",
            "whois.test",
            "Registrar: Mock Registrar\n\
             Creation Date: 2010-03-15T04:00:00Z\n\
             Updated Date: 2024-02-01T09:30:00Z\n\
             Registry Expiry Date: 2099-03-15T04:00:00Z\n\
             Registrant Country: US\n\
             Admin Name: Jane Admin\n\
             Name Server: ns1.example.com\n\
             Domain Status: ok\n\
             DNSSEC: unsigned\n",
        )
    }

    #[test]
    fn format_lookup_whois_domain_fields_precede_contact_sections() {
        // Contact `###` subsections were emitted before the domain-level
        // bullets, which then rendered as part of the last contact section.
        let result = LookupResult::Whois {
            data: whois_with_contacts(),
            rdap_error: None,
            rdap_fallback: None,
        };
        let out = MarkdownFormatter::new().format_lookup(&result);
        assert_fields_before(
            &out,
            "\n###",
            &[
                "- **Created**",
                "- **Expires**",
                "- **Status**",
                "- **Nameservers**",
                "- **DNSSEC**",
            ],
        );
        assert!(out.contains("### Registrant Contact"), "got:\n{out}");
        assert!(out.contains("### Admin Contact"), "got:\n{out}");
    }

    #[test]
    fn format_lookup_rdap_fallback_bullets_precede_contact_sections() {
        let rdap: RdapResponse = serde_json::from_value(serde_json::json!({
            "ldhName": "example.com",
            "status": ["active"],
            "events": [
                {"eventAction": "registration", "eventDate": "2010-03-15T04:00:00Z"}
            ],
            "entities": [{
                "objectClassName": "entity",
                "handle": "TECH-1",
                "roles": ["technical"],
                "vcardArray": ["vcard", [["email", {}, "text", "tech@example.com"]]]
            }]
        }))
        .unwrap();
        let result = LookupResult::Rdap {
            data: Box::new(rdap),
            whois_fallback: Some(whois_with_contacts()),
        };
        let out = MarkdownFormatter::new().format_lookup(&result);
        // RDAP domain bullets precede the RDAP contact section...
        assert_fields_before(&out, "### Tech Contact", &["- **Created**", "- **Status**"]);
        // ...and the WHOIS fallback bullets precede the fallback contacts.
        assert_fields_before(
            &out,
            "### Registrant Contact",
            &[
                "### Additional WHOIS Data",
                "- **Updated**",
                "- **WHOIS Server**",
            ],
        );
        assert!(out.contains("### Admin Contact"), "fallback admin:\n{out}");
    }
}
