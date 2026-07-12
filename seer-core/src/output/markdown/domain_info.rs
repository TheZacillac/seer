use super::*;

impl MarkdownFormatter {
    pub(super) fn format_tld(&self, info: &crate::tld::TldInfo) -> String {
        let mut output = Vec::new();

        output.push(format!("## TLD Info: .{}", MdSafe(&info.tld)));
        output.push(String::new());

        output.push(format!("- **Type**: {}", MdSafe(&info.tld_type)));

        match info.whois_server {
            Some(ref server) => {
                output.push(format!("- **WHOIS Server**: `{}`", MdSafe(server)));
            }
            None => output.push("- **WHOIS Server**: *not available*".to_string()),
        }

        match info.rdap_url {
            Some(ref url) => output.push(format!("- **RDAP URL**: `{}`", MdSafe(url))),
            None => output.push("- **RDAP URL**: *not available*".to_string()),
        }

        match info.registry_url {
            Some(ref url) => output.push(format!("- **Registry URL**: {}", MdSafe(url))),
            None => output.push("- **Registry URL**: *not available*".to_string()),
        }

        output.join("\n")
    }

    pub(super) fn format_subdomains(&self, result: &crate::subdomains::SubdomainResult) -> String {
        let mut output = Vec::new();

        output.push(format!("## Subdomains: {}", MdSafe(&result.domain)));
        output.push(String::new());
        output.push(format!("- **Source**: {}", MdSafe(&result.source)));
        output.push(format!("- **Count**: {}", result.count));
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
        output.push(String::new());

        // Registration table
        output.push("### Registration".to_string());
        output.push(String::new());
        output.push("| Field | Value |".to_string());
        output.push("| --- | --- |".to_string());
        output.push(format!("| Registrar | {} |", opt_md(&info.registrar)));
        output.push(format!("| Registrant | {} |", opt_md(&info.registrant)));
        output.push(format!("| Organization | {} |", opt_md(&info.organization)));
        output.push(format!(
            "| Created | {} |",
            info.creation_date
                .map(|d| d.format("%Y-%m-%d").to_string())
                .as_deref()
                .unwrap_or("-")
        ));
        output.push(format!(
            "| Expires | {} |",
            info.expiration_date
                .map(|d| d.format("%Y-%m-%d").to_string())
                .as_deref()
                .unwrap_or("-")
        ));
        output.push(format!(
            "| Updated | {} |",
            info.updated_date
                .map(|d| d.format("%Y-%m-%d").to_string())
                .as_deref()
                .unwrap_or("-")
        ));
        output.push(format!(
            "| Nameservers | {} |",
            if info.nameservers.is_empty() {
                "-".to_string()
            } else {
                info.nameservers
                    .iter()
                    .map(|ns| format!("`{}`", MdSafe(ns)))
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        ));
        output.push(format!(
            "| Status | {} |",
            if info.status.is_empty() {
                "-".to_string()
            } else {
                info.status
                    .iter()
                    .map(|s| format!("`{}`", MdSafe(s)))
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        ));
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
        let has_any_contact = info.registrant_email.is_some()
            || info.registrant_phone.is_some()
            || info.registrant_address.is_some()
            || info.registrant_country.is_some()
            || info.admin_name.is_some()
            || info.admin_organization.is_some()
            || info.admin_email.is_some()
            || info.admin_phone.is_some()
            || info.tech_name.is_some()
            || info.tech_organization.is_some()
            || info.tech_email.is_some()
            || info.tech_phone.is_some();

        if has_any_contact {
            output.push(String::new());
            output.push("### Contacts".to_string());
            output.push(String::new());
            output.push("| Role | Name | Organization | Email | Phone |".to_string());
            output.push("| --- | --- | --- | --- | --- |".to_string());

            let has_registrant = info.registrant_email.is_some()
                || info.registrant_phone.is_some()
                || info.registrant_address.is_some()
                || info.registrant_country.is_some();
            if has_registrant {
                output.push(format!(
                    "| Registrant | - | - | {} | {} |",
                    opt_md(&info.registrant_email),
                    opt_md(&info.registrant_phone),
                ));
            }

            let has_admin = info.admin_name.is_some()
                || info.admin_organization.is_some()
                || info.admin_email.is_some()
                || info.admin_phone.is_some();
            if has_admin {
                output.push(format!(
                    "| Admin | {} | {} | {} | {} |",
                    opt_md(&info.admin_name),
                    opt_md(&info.admin_organization),
                    opt_md(&info.admin_email),
                    opt_md(&info.admin_phone),
                ));
            }

            let has_tech = info.tech_name.is_some()
                || info.tech_organization.is_some()
                || info.tech_email.is_some()
                || info.tech_phone.is_some();
            if has_tech {
                output.push(format!(
                    "| Tech | {} | {} | {} | {} |",
                    opt_md(&info.tech_name),
                    opt_md(&info.tech_organization),
                    opt_md(&info.tech_email),
                    opt_md(&info.tech_phone),
                ));
            }
        }

        // Registrar Detail (RDAP registrar entity: abuse contact, IANA ID, URL)
        let has_registrar_detail = info.registrar_iana_id.is_some()
            || info.registrar_url.is_some()
            || info.registrar_abuse_email.is_some()
            || info.registrar_abuse_phone.is_some();
        if has_registrar_detail {
            output.push(String::new());
            output.push("### Registrar Detail".to_string());
            output.push(String::new());
            if let Some(ref iana_id) = info.registrar_iana_id {
                output.push(format!("- **IANA ID**: {}", MdSafe(iana_id)));
            }
            if let Some(ref url) = info.registrar_url {
                output.push(format!("- **URL**: {}", MdSafe(url)));
            }
            if let Some(ref email) = info.registrar_abuse_email {
                output.push(format!("- **Abuse Email**: {}", MdSafe(email)));
            }
            if let Some(ref phone) = info.registrar_abuse_phone {
                output.push(format!("- **Abuse Phone**: {}", MdSafe(phone)));
            }
        }

        // Protocol Metadata
        let has_metadata = info.whois_server.is_some() || info.rdap_url.is_some();
        if has_metadata {
            output.push(String::new());
            output.push("### Protocol Metadata".to_string());
            output.push(String::new());
            if let Some(ref whois_server) = info.whois_server {
                output.push(format!("- **WHOIS Server**: `{}`", MdSafe(whois_server)));
            }
            if let Some(ref rdap_url) = info.rdap_url {
                output.push(format!("- **RDAP URL**: `{}`", MdSafe(rdap_url)));
            }
        }

        output.join("\n")
    }
}
