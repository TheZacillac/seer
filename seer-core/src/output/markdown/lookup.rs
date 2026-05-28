use super::*;

impl MarkdownFormatter {
    pub(super) fn format_lookup(&self, result: &LookupResult) -> String {
        let mut output = Vec::new();

        let domain = result
            .domain_name()
            .unwrap_or_else(|| "Unknown".to_string());
        let source = match result {
            LookupResult::Rdap { .. } => "RDAP",
            LookupResult::Whois { .. } => "WHOIS",
            LookupResult::Available { .. } => "availability",
        };

        output.push(format!("## Lookup: {}", MdSafe(&domain)));
        output.push(String::new());
        output.push(format!("- **Source**: {}", source));

        match result {
            LookupResult::Rdap {
                data,
                whois_fallback,
            } => {
                if let Some(registrar) = data.get_registrar() {
                    output.push(format!("- **Registrar**: {}", MdSafe(&registrar)));
                }
                if let Some(registrant) = data.get_registrant() {
                    output.push(format!("- **Registrant**: {}", MdSafe(&registrant)));
                }
                if let Some(organization) = data.get_registrant_organization() {
                    output.push(format!("- **Organization**: {}", MdSafe(&organization)));
                }

                // Contact sections from RDAP
                if let Some(contact) = data.get_registrant_contact() {
                    self.format_rdap_contact(&mut output, "Registrant Contact", &contact);
                }
                if let Some(contact) = data.get_admin_contact() {
                    self.format_rdap_contact(&mut output, "Admin Contact", &contact);
                }
                if let Some(contact) = data.get_tech_contact() {
                    self.format_rdap_contact(&mut output, "Tech Contact", &contact);
                }

                if let Some(created) = data.creation_date() {
                    output.push(format!("- **Created**: `{}`", created.format("%Y-%m-%d")));
                }
                if let Some(expires) = data.expiration_date() {
                    let days_until = (expires - chrono::Utc::now()).num_days();
                    output.push(format!(
                        "- **Expires**: `{}` ({} days)",
                        expires.format("%Y-%m-%d"),
                        days_until
                    ));
                }

                if !data.status.is_empty() {
                    output.push(format!(
                        "- **Status**: {}",
                        data.status
                            .iter()
                            .map(|s| format!("`{}`", MdSafe(s)))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }

                let nameservers = data.nameserver_names();
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

                if data.is_dnssec_signed() {
                    output.push("- **DNSSEC**: signed".to_string());
                }

                // WHOIS fallback data
                if let Some(whois) = whois_fallback {
                    let mut extra = Vec::new();

                    if data.get_registrant().is_none() {
                        if let Some(ref registrant) = whois.registrant {
                            extra.push(format!("- **Registrant**: {}", MdSafe(registrant)));
                        }
                    }
                    if data.get_registrant_organization().is_none() {
                        if let Some(ref org) = whois.organization {
                            extra.push(format!("- **Organization**: {}", MdSafe(org)));
                        }
                    }

                    // Registrant contact from WHOIS fallback
                    let rdap_has_registrant = data
                        .get_registrant_contact()
                        .as_ref()
                        .is_some_and(|c| c.has_info());
                    if !rdap_has_registrant {
                        let has_whois_contact = whois.registrant_email.is_some()
                            || whois.registrant_phone.is_some()
                            || whois.registrant_address.is_some()
                            || whois.registrant_country.is_some();
                        if has_whois_contact {
                            extra.push(String::new());
                            extra.push("### Registrant Contact".to_string());
                            extra.push(String::new());
                            if let Some(ref email) = whois.registrant_email {
                                extra.push(format!("- **Email**: `{}`", MdSafe(email)));
                            }
                            if let Some(ref phone) = whois.registrant_phone {
                                extra.push(format!("- **Phone**: {}", MdSafe(phone)));
                            }
                            if let Some(ref address) = whois.registrant_address {
                                extra.push(format!("- **Address**: {}", MdSafe(address)));
                            }
                            if let Some(ref country) = whois.registrant_country {
                                extra.push(format!("- **Country**: {}", MdSafe(country)));
                            }
                        }
                    }

                    // Admin contact from WHOIS fallback
                    let rdap_has_admin = data.get_admin_contact().is_some_and(|c| c.has_info());
                    if !rdap_has_admin {
                        let has_whois_admin = whois.admin_name.is_some()
                            || whois.admin_email.is_some()
                            || whois.admin_phone.is_some();
                        if has_whois_admin {
                            extra.push(String::new());
                            extra.push("### Admin Contact".to_string());
                            extra.push(String::new());
                            if let Some(ref name) = whois.admin_name {
                                extra.push(format!("- **Name**: {}", MdSafe(name)));
                            }
                            if let Some(ref org) = whois.admin_organization {
                                extra.push(format!("- **Organization**: {}", MdSafe(org)));
                            }
                            if let Some(ref email) = whois.admin_email {
                                extra.push(format!("- **Email**: `{}`", MdSafe(email)));
                            }
                            if let Some(ref phone) = whois.admin_phone {
                                extra.push(format!("- **Phone**: {}", MdSafe(phone)));
                            }
                        }
                    }

                    // Tech contact from WHOIS fallback
                    let rdap_has_tech = data.get_tech_contact().is_some_and(|c| c.has_info());
                    if !rdap_has_tech {
                        let has_whois_tech = whois.tech_name.is_some()
                            || whois.tech_email.is_some()
                            || whois.tech_phone.is_some();
                        if has_whois_tech {
                            extra.push(String::new());
                            extra.push("### Tech Contact".to_string());
                            extra.push(String::new());
                            if let Some(ref name) = whois.tech_name {
                                extra.push(format!("- **Name**: {}", MdSafe(name)));
                            }
                            if let Some(ref org) = whois.tech_organization {
                                extra.push(format!("- **Organization**: {}", MdSafe(org)));
                            }
                            if let Some(ref email) = whois.tech_email {
                                extra.push(format!("- **Email**: `{}`", MdSafe(email)));
                            }
                            if let Some(ref phone) = whois.tech_phone {
                                extra.push(format!("- **Phone**: {}", MdSafe(phone)));
                            }
                        }
                    }

                    if let Some(updated) = whois.updated_date {
                        extra.push(format!("- **Updated**: `{}`", updated.format("%Y-%m-%d")));
                    }

                    if !data.is_dnssec_signed() {
                        if let Some(ref dnssec) = whois.dnssec {
                            extra.push(format!("- **DNSSEC**: {}", MdSafe(dnssec)));
                        }
                    }

                    if !whois.whois_server.is_empty() {
                        extra.push(format!(
                            "- **WHOIS Server**: `{}`",
                            MdSafe(&whois.whois_server)
                        ));
                    }

                    if !extra.is_empty() {
                        output.push(String::new());
                        output.push("### Additional WHOIS Data".to_string());
                        output.push(String::new());
                        output.extend(extra);
                    }
                }
            }
            LookupResult::Whois {
                data, rdap_error, ..
            } => {
                if let Some(ref error) = rdap_error {
                    output.push(format!("- **RDAP Error**: {}", MdSafe(error)));
                }

                if let Some(ref registrar) = data.registrar {
                    output.push(format!("- **Registrar**: {}", MdSafe(registrar)));
                }
                if let Some(ref registrant) = data.registrant {
                    output.push(format!("- **Registrant**: {}", MdSafe(registrant)));
                }
                if let Some(ref organization) = data.organization {
                    output.push(format!("- **Organization**: {}", MdSafe(organization)));
                }

                // Registrant contact details
                let has_registrant_details = data.registrant_email.is_some()
                    || data.registrant_phone.is_some()
                    || data.registrant_address.is_some()
                    || data.registrant_country.is_some();

                if has_registrant_details {
                    output.push(String::new());
                    output.push("### Registrant Contact".to_string());
                    output.push(String::new());
                    if let Some(ref email) = data.registrant_email {
                        output.push(format!("- **Email**: `{}`", MdSafe(email)));
                    }
                    if let Some(ref phone) = data.registrant_phone {
                        output.push(format!("- **Phone**: {}", MdSafe(phone)));
                    }
                    if let Some(ref address) = data.registrant_address {
                        output.push(format!("- **Address**: {}", MdSafe(address)));
                    }
                    if let Some(ref country) = data.registrant_country {
                        output.push(format!("- **Country**: {}", MdSafe(country)));
                    }
                }

                // Admin contact
                self.format_whois_contact(
                    &mut output,
                    "Admin Contact",
                    &data.admin_name,
                    &data.admin_organization,
                    &data.admin_email,
                    &data.admin_phone,
                );

                // Tech contact
                self.format_whois_contact(
                    &mut output,
                    "Tech Contact",
                    &data.tech_name,
                    &data.tech_organization,
                    &data.tech_email,
                    &data.tech_phone,
                );

                if let Some(created) = data.creation_date {
                    output.push(format!("- **Created**: `{}`", created.format("%Y-%m-%d")));
                }
                if let Some(expires) = data.expiration_date {
                    let days_until = (expires - chrono::Utc::now()).num_days();
                    output.push(format!(
                        "- **Expires**: `{}` ({} days)",
                        expires.format("%Y-%m-%d"),
                        days_until
                    ));
                }

                if !data.status.is_empty() {
                    output.push(format!(
                        "- **Status**: {}",
                        data.status
                            .iter()
                            .map(|s| format!("`{}`", MdSafe(s)))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }

                if !data.nameservers.is_empty() {
                    output.push(format!(
                        "- **Nameservers**: {}",
                        data.nameservers
                            .iter()
                            .map(|ns| format!("`{}`", MdSafe(ns)))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }

                if let Some(ref dnssec) = data.dnssec {
                    output.push(format!("- **DNSSEC**: {}", MdSafe(dnssec)));
                }
            }
            LookupResult::Available {
                data,
                rdap_error,
                whois_error,
                whois_data,
            } => {
                let verdict = match data.confidence.as_str() {
                    "high" => "AVAILABLE",
                    "medium" => "MAY BE AVAILABLE",
                    _ => "UNKNOWN",
                };
                output.push(format!("- **Verdict**: {}", verdict));
                output.push(format!("- **Confidence**: {}", data.confidence));
                output.push(format!("- **Method**: {}", data.method));
                if let Some(ref details) = data.details {
                    output.push(format!("- **Details**: {}", MdSafe(details)));
                }
                if !rdap_error.is_empty() {
                    output.push(format!("- **RDAP Error**: {}", MdSafe(rdap_error)));
                }
                if !whois_error.is_empty() {
                    output.push(format!("- **WHOIS Error**: {}", MdSafe(whois_error)));
                }

                if let Some(w) = whois_data {
                    let mut bullets = Vec::new();
                    if !w.nameservers.is_empty() {
                        bullets.push(format!(
                            "- **Nameservers**: {}",
                            w.nameservers
                                .iter()
                                .map(|ns| format!("`{}`", MdSafe(ns)))
                                .collect::<Vec<_>>()
                                .join(", ")
                        ));
                    }
                    if !w.status.is_empty() {
                        bullets.push(format!(
                            "- **Status**: {}",
                            w.status
                                .iter()
                                .map(|s| format!("`{}`", MdSafe(s)))
                                .collect::<Vec<_>>()
                                .join(", ")
                        ));
                    }
                    if let Some(ref dnssec) = w.dnssec {
                        bullets.push(format!("- **DNSSEC**: {}", MdSafe(dnssec)));
                    }
                    if !w.whois_server.is_empty() {
                        bullets.push(format!("- **WHOIS Server**: `{}`", MdSafe(&w.whois_server)));
                    }
                    if !bullets.is_empty() {
                        output.push(String::new());
                        output.push("### Additional WHOIS data".to_string());
                        output.push(String::new());
                        output.extend(bullets);
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

        output.push(format!("## Availability: {}", MdSafe(&result.domain)));
        output.push(String::new());

        let avail_str = if result.available {
            "**AVAILABLE**"
        } else {
            "**TAKEN**"
        };
        output.push(format!("- **Result**: {}", avail_str));
        output.push(format!("- **Confidence**: {}", result.confidence));
        output.push(format!("- **Method**: {}", result.method));
        if let Some(ref details) = result.details {
            output.push(format!("- **Details**: {}", MdSafe(details)));
        }

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
}
