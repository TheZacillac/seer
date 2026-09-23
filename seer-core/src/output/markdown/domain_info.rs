use super::*;

impl MarkdownFormatter {
    pub(super) fn format_tld(&self, info: &crate::tld::TldInfo) -> String {
        let mut output = Vec::new();

        output.push(format!("## TLD Info: .{}", MdSafe(&info.tld)));
        output.push(String::new());

        let mut b = Bullets(&mut output);
        b.text("Type", &info.tld_type);
        // Server endpoints render as code spans, the registry site as text.
        for (label, value, code) in [
            ("WHOIS Server", &info.whois_server, true),
            ("RDAP URL", &info.rdap_url, true),
            ("Registry URL", &info.registry_url, false),
        ] {
            match value {
                Some(value) if code => b.code(label, value),
                Some(value) => b.text(label, value),
                None => b.raw(label, "*not available*"),
            }
        }

        output.join("\n")
    }

    pub(super) fn format_subdomains(&self, result: &crate::subdomains::SubdomainResult) -> String {
        let mut output = Vec::new();

        output.push(format!("## Subdomains: {}", MdSafe(&result.domain)));
        output.push(String::new());
        let mut b = Bullets(&mut output);
        b.text("Source", &result.source);
        b.raw("Count", result.count);
        output.push(String::new());

        if result.subdomains.is_empty() {
            output.push("*No subdomains found*".to_string());
        } else {
            for subdomain in &result.subdomains {
                output.push(format!("- `{}`", MdSafe(subdomain)));
            }
        }

        output.join("\n")
    }

    pub(super) fn format_watch(&self, report: &crate::watchlist::WatchReport) -> String {
        let mut output = Vec::new();

        output.push("## Domain Watch Report".to_string());
        output.push(String::new());
        output.push(format!(
            "- **Checked**: {}",
            report.checked_at.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        output.push(format!(
            "- **Total**: {} domains, {} warnings, {} critical",
            report.total, report.warnings, report.critical
        ));
        output.push(String::new());

        if report.results.is_empty() {
            output.push("No domains in watchlist.".to_string());
            return output.join("\n");
        }

        output.push("| Status | Domain | SSL Days | Domain Days | HTTP | Issues |".to_string());
        output.push("| --- | --- | --- | --- | --- | --- |".to_string());

        for r in &report.results {
            let icon = if r.issues.is_empty() { "ok" } else { "warn" };
            let ssl = r
                .ssl_days_remaining
                .map(|d| d.to_string())
                .unwrap_or_else(|| "N/A".to_string());
            let dom = r
                .domain_days_remaining
                .map(|d| d.to_string())
                .unwrap_or_else(|| "N/A".to_string());
            let http = r
                .http_status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "N/A".to_string());
            let issues = if r.issues.is_empty() {
                "-".to_string()
            } else {
                r.issues.join("; ")
            };
            output.push(format!(
                "| {} | {} | {} | {} | {} | {} |",
                icon,
                MdSafe(&r.domain),
                ssl,
                dom,
                http,
                MdSafe(&issues)
            ));
        }

        output.join("\n")
    }

    pub(super) fn format_domain_info(&self, info: &crate::domain_info::DomainInfo) -> String {
        let mut output = Vec::new();

        let source_str = match info.source {
            crate::domain_info::DomainInfoSource::Both => "both",
            crate::domain_info::DomainInfoSource::Rdap => "rdap",
            crate::domain_info::DomainInfoSource::Whois => "whois",
            crate::domain_info::DomainInfoSource::Available => "available",
        };

        // Helper: render Option<String> via MdSafe or fall back to "-".
        let opt_md = |o: &Option<String>| -> String {
            match o {
                Some(v) => format!("{}", MdSafe(v)),
                None => "-".to_string(),
            }
        };

        output.push(format!("## Domain Info: {}", MdSafe(&info.domain)));
        output.push(String::new());
        output.push(format!("**Source:** {}", source_str));
        // Same verdict wording as the human formatter and markdown lookup.
        if let Some(verdict) = &info.availability_verdict {
            let rendered = match verdict.as_str() {
                "available" => "AVAILABLE",
                "likely_available" => "MAY BE AVAILABLE",
                "registered" => "REGISTERED",
                "likely_registered" => "LIKELY REGISTERED",
                _ => "UNKNOWN",
            };
            output.push(String::new());
            output.push(format!("**Verdict:** {}", rendered));
        }
        output.push(String::new());

        // Registration table
        output.push("### Registration".to_string());
        output.push(String::new());
        output.push("| Field | Value |".to_string());
        output.push("| --- | --- |".to_string());
        output.push(format!("| Registrar | {} |", opt_md(&info.registrar)));
        output.push(format!("| Registrant | {} |", opt_md(&info.registrant)));
        output.push(format!("| Organization | {} |", opt_md(&info.organization)));
        let date_md = |d: Option<DateTime<Utc>>| {
            d.map_or_else(|| "-".to_string(), |d| d.format("%Y-%m-%d").to_string())
        };
        let list_md = |items: &[String]| {
            if items.is_empty() {
                "-".to_string()
            } else {
                code_list(items)
            }
        };
        output.push(format!("| Created | {} |", date_md(info.creation_date)));
        output.push(format!("| Expires | {} |", date_md(info.expiration_date)));
        output.push(format!("| Updated | {} |", date_md(info.updated_date)));
        output.push(format!("| Nameservers | {} |", list_md(&info.nameservers)));
        output.push(format!("| Status | {} |", list_md(&info.status)));
        output.push(format!("| DNSSEC | {} |", opt_md(&info.dnssec)));

        // Derived lifecycle rows — only when computed, to keep sparse
        // (e.g. available-domain) tables free of dash-only noise.
        if let Some(days) = info.days_until_expiration {
            output.push(format!("| Days Until Expiry | {} |", days));
        }
        if let Some(age) = info.domain_age_days {
            output.push(format!("| Domain Age (days) | {} |", age));
        }
        if let Some(expiry_status) = info.expiry_status {
            output.push(format!("| Expiry Status | {} |", expiry_status));
        }

        // Plain-English decodings of recognized EPP status codes.
        if !info.status_descriptions.is_empty() {
            output.push(String::new());
            output.push("### Status Codes".to_string());
            output.push(String::new());
            for sd in &info.status_descriptions {
                output.push(format!(
                    "- `{}` — {}",
                    MdSafe(&sd.code),
                    MdSafe(&sd.description)
                ));
            }
        }

        // Contacts table
        let contacts = info.contacts();
        if contacts.iter().any(|c| !c.is_empty()) {
            output.push(String::new());
            output.push("### Contacts".to_string());
            output.push(String::new());
            // Address/Country exist only for the registrant, but a
            // GDPR-redacted record often carries nothing else (e.g. just
            // `Registrant Country: US`), so they need their own columns.
            output.push(
                "| Role | Name | Organization | Email | Phone | Address | Country |".to_string(),
            );
            output.push("| --- | --- | --- | --- | --- | --- | --- |".to_string());
            for (role, c) in contact::ROLES.into_iter().zip(contacts) {
                if !c.is_empty() {
                    let cells: Vec<String> = c.fields().iter().map(|(_, f)| opt_md(f)).collect();
                    output.push(format!("| {} | {} |", role, cells.join(" | ")));
                }
            }
        }

        // Registrar Detail (RDAP registrar entity: abuse contact, IANA ID, URL)
        let detail = [
            ("IANA ID", &info.registrar_iana_id),
            ("URL", &info.registrar_url),
            ("Abuse Email", &info.registrar_abuse_email),
            ("Abuse Phone", &info.registrar_abuse_phone),
        ];
        if detail.iter().any(|(_, v)| v.is_some()) {
            output.extend([
                String::new(),
                "### Registrar Detail".to_string(),
                String::new(),
            ]);
            let mut b = Bullets(&mut output);
            for (label, value) in detail {
                b.opt(label, value);
            }
        }

        // Protocol Metadata
        if info.whois_server.is_some() || info.rdap_url.is_some() {
            output.extend([
                String::new(),
                "### Protocol Metadata".to_string(),
                String::new(),
            ]);
            let mut b = Bullets(&mut output);
            b.code_opt("WHOIS Server", &info.whois_server);
            b.code_opt("RDAP URL", &info.rdap_url);
        }

        output.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_info_renders_availability_verdict() {
        // Human `seer info` shows the availability verdict; markdown dropped it.
        let mut info = crate::domain_info::DomainInfo::from_sources("example.com", None, None);
        info.availability_verdict = Some("likely_available".to_string());
        let out = MarkdownFormatter::new().format_domain_info(&info);
        assert!(out.contains("**Verdict:** MAY BE AVAILABLE"), "got:\n{out}");
    }

    #[test]
    fn contacts_table_renders_registrant_address_and_country() {
        // A GDPR-redacted record with only `Registrant Country: US` set
        // `has_registrant` but rendered `| Registrant | - | - | - | - |`.
        let whois = WhoisResponse::parse(
            "example.com",
            "whois.test",
            "Registrar: Mock Registrar\nRegistrant Country: US\n",
        );
        let mut info =
            crate::domain_info::DomainInfo::from_sources("example.com", None, Some(&whois));
        assert_eq!(info.registrant_country.as_deref(), Some("US"), "fixture");
        info.registrant_address = Some("1 Main St|Springfield".to_string());
        info.admin_name = Some("Jane Admin".to_string());

        let out = MarkdownFormatter::new().format_domain_info(&info);
        assert!(
            out.contains("| Role | Name | Organization | Email | Phone | Address | Country |"),
            "got:\n{out}"
        );
        assert!(
            out.contains("| Registrant | - | - | - | - | 1 Main St\\|Springfield | US |"),
            "registrant address/country must render:\n{out}"
        );
        // Other rows keep the table rectangular.
        assert!(
            out.contains("| Admin | Jane Admin | - | - | - | - | - |"),
            "got:\n{out}"
        );
    }
}
