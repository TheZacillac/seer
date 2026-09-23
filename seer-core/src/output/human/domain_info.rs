use super::*;
use crate::domain_info::{DomainInfo, DomainInfoSource, ExpiryStatus};

impl HumanFormatter {
    pub(super) fn format_tld(&self, info: &crate::tld::TldInfo) -> String {
        let mut output = vec![self.header(&format!("TLD Info: .{}", info.tld))];
        let mut rows = self.rows(&mut output, "  ");
        rows.text("Type", &info.tld_type);
        for (label, value) in [
            ("WHOIS Server", &info.whois_server),
            ("RDAP URL", &info.rdap_url),
            ("Registry", &info.registry_url),
        ] {
            match value {
                Some(value) => rows.text(label, value),
                None => rows.kv(label, self.warning("not available")),
            }
        }

        output.join("\n")
    }

    pub(super) fn format_subdomains(&self, result: &crate::subdomains::SubdomainResult) -> String {
        let mut output =
            vec![self.header(&format!("Subdomains: {}", sanitize_display(&result.domain)))];
        let mut rows = self.rows(&mut output, "  ");
        rows.text("Source", &result.source);
        rows.kv("Count", self.value(&result.count.to_string()));

        if result.subdomains.is_empty() {
            rows.push(format!("  {}", self.warning("No subdomains found")));
        } else {
            rows.blank();
            for subdomain in &result.subdomains {
                rows.push(format!(
                    "    - {}",
                    self.value(&sanitize_display(subdomain))
                ));
            }
        }

        output.join("\n")
    }

    pub(super) fn format_watch(&self, report: &crate::watchlist::WatchReport) -> String {
        let mut output = vec![self.header("Domain Watch Report")];
        let mut rows = self.rows(&mut output, "  ");
        let checked = report.checked_at.format("%Y-%m-%d %H:%M:%S UTC");
        rows.kv("Checked", self.value(&checked.to_string()));
        let warnings = report.warnings.to_string();
        let critical = report.critical.to_string();
        rows.kv(
            "Total",
            format!(
                "{} domains, {} warnings, {} critical",
                self.value(&report.total.to_string()),
                if report.warnings > 0 {
                    self.warning(&warnings)
                } else {
                    self.value(&warnings)
                },
                if report.critical > 0 {
                    self.error(&critical)
                } else {
                    self.value(&critical)
                }
            ),
        );

        let days = |d: Option<i64>| d.map_or_else(|| "N/A".to_string(), |d| format!("{d} days"));
        for r in &report.results {
            rows.blank();
            let icon = if r.issues.is_empty() {
                self.success("v")
            } else {
                self.warning("!")
            };
            rows.push(format!(
                "  {} {}",
                icon,
                self.value(&sanitize_display(&r.domain))
            ));

            // Condensed status line: SSL | Domain | HTTP
            let http = r
                .http_status
                .map_or_else(|| "N/A".to_string(), |s| s.to_string());
            rows.push(format!(
                "      {}: {} | {}: {} | {}: {}",
                self.label("SSL"),
                self.value(&days(r.ssl_days_remaining)),
                self.label("Domain"),
                self.value(&days(r.domain_days_remaining)),
                self.label("HTTP"),
                self.value(&http)
            ));

            if !r.issues.is_empty() {
                rows.push(format!("      {}:", self.label("Issues")));
                for issue in &r.issues {
                    rows.push(format!(
                        "        - {}",
                        self.warning(&sanitize_display(issue))
                    ));
                }
            }
        }

        output.join("\n")
    }

    pub(super) fn format_domain_info(&self, info: &DomainInfo) -> String {
        let source = match info.source {
            DomainInfoSource::Both => "both",
            DomainInfoSource::Rdap => "rdap",
            DomainInfoSource::Whois => "whois",
            DomainInfoSource::Available => "available",
        };
        let mut output = vec![self.header(&format!(
            "Domain Info: {} (source: {})",
            sanitize_display(&info.domain),
            source
        ))];
        let mut rows = self.rows(&mut output, "  ");

        if let Some(verdict) = &info.availability_verdict {
            let colored = match verdict.as_str() {
                "available" => self.success("AVAILABLE"),
                "likely_available" => self.warning("MAY BE AVAILABLE"),
                "registered" => self.value("REGISTERED"),
                "likely_registered" => self.warning("LIKELY REGISTERED"),
                _ => self.error("UNKNOWN"),
            };
            rows.kv("Status", colored);
        }

        // Registration
        rows.opt("Registrar", &info.registrar);
        rows.opt("Registrant", &info.registrant);
        rows.opt("Organization", &info.organization);

        // Dates
        rows.date("Created", info.creation_date);
        rows.date("Expires", info.expiration_date);
        rows.date("Updated", info.updated_date);

        // Derived lifecycle (computed at construction from the dates above).
        if let Some(days) = info.days_until_expiration {
            let rendered = format!("{} days", days);
            let styled = if days <= 30 {
                self.warning(&rendered)
            } else {
                self.value(&rendered)
            };
            rows.kv("Days Until Expiry", styled);
        }
        if let Some(age) = info.domain_age_days {
            rows.kv("Domain Age", self.value(&format!("{} days", age)));
        }
        if let Some(expiry_status) = info.expiry_status {
            let rendered = expiry_status.to_string();
            let colored = match expiry_status {
                ExpiryStatus::Active => self.value(&rendered),
                ExpiryStatus::ExpiringSoon => self.warning(&rendered),
                _ => self.error(&rendered),
            };
            rows.kv("Expiry Status", colored);
        }

        // DNS. Nameservers/status originate from attacker-controlled WHOIS/RDAP
        // parsing, so they are sanitized like every other remote value (#53).
        if !info.nameservers.is_empty() {
            rows.text("Nameservers", &info.nameservers.join(", "));
        }
        if !info.status.is_empty() {
            rows.text("Status", &info.status.join(", "));
        }
        rows.opt("DNSSEC", &info.dnssec);

        // Plain-English decodings of recognized EPP status codes.
        if !info.status_descriptions.is_empty() {
            let mut codes = rows.section("Status Codes");
            for sd in &info.status_descriptions {
                codes.text(&sanitize_display(&sd.code), &sd.description);
            }
        }

        rows.contacts(info.contacts());

        // Registrar Detail (RDAP registrar entity: abuse contact, IANA ID, URL)
        let detail = [
            ("IANA ID", &info.registrar_iana_id),
            ("URL", &info.registrar_url),
            ("Abuse Email", &info.registrar_abuse_email),
            ("Abuse Phone", &info.registrar_abuse_phone),
        ];
        if detail.iter().any(|(_, v)| v.is_some()) {
            let mut section = rows.section("Registrar Detail");
            for (label, value) in detail {
                section.opt(label, value);
            }
        }

        // Protocol Metadata
        if info.whois_server.is_some() || info.rdap_url.is_some() {
            let mut section = rows.section("Protocol Metadata");
            section.opt("WHOIS Server", &info.whois_server);
            section.opt("RDAP URL", &info.rdap_url);
        }

        output.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watch_summary_includes_critical_count() {
        // Markdown printed "N warnings, M critical"; human omitted the
        // critical tally, so the same report was less complete by default.
        let report = crate::watchlist::WatchReport {
            checked_at: Utc::now(),
            results: Vec::new(),
            total: 3,
            warnings: 2,
            critical: 1,
        };
        let out = HumanFormatter::new().without_colors().format_watch(&report);
        assert!(
            out.contains("Total: 3 domains, 2 warnings, 1 critical"),
            "got:\n{out}"
        );
    }
}
