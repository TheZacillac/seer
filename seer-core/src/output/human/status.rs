use super::*;

impl HumanFormatter {
    pub(super) fn format_status(&self, response: &StatusResponse) -> String {
        let mut output =
            vec![self.header(&format!("Status: {}", sanitize_display(&response.domain)))];
        let mut rows = self.rows(&mut output, "  ");

        // HTTP Status
        if let Some(status) = response.http_status {
            let status_text =
                sanitize_display(response.http_status_text.as_deref().unwrap_or("Unknown"));
            let text = format!("{} ({})", status, status_text);
            let styled = if (200..300).contains(&status) {
                self.success(&text)
            } else if (300..400).contains(&status) {
                self.warning(&text)
            } else {
                self.error(&text)
            };
            rows.kv("HTTP Status", styled);
        }

        rows.opt("Site Title", &response.title);

        // SSL Certificate
        if let Some(ref cert) = response.certificate {
            let mut ssl = rows.section("SSL Certificate");
            ssl.text("Subject", &cert.subject);
            ssl.text("Issuer", &cert.issuer);
            let valid = if cert.is_valid {
                self.success("Valid")
            } else {
                self.error("Invalid")
            };
            ssl.kv("Status", valid);
            if !cert.hostname_verified {
                let warning = self.error("WARNING: certificate hostname not verified");
                ssl.push(format!("    {warning}"));
            }
            ssl.date("Valid From", Some(cert.valid_from));
            // Shared helper renders the already-expired (negative) case as
            // "expired N days ago" instead of a confusing "(-N days!)".
            let expiry = cert.valid_until.format("%Y-%m-%d").to_string();
            ssl.kv(
                "Expires",
                self.format_expiry_status(&expiry, cert.days_until_expiry),
            );
        } else {
            rows.blank();
            rows.kv(
                "SSL Certificate",
                self.warning("Not available (HTTPS may not be configured)"),
            );
        }

        // CAA policy (issuance-time authorization for certificate authorities)
        if let Some(ref caa) = response.caa {
            rows.extend(self.render_caa_block(caa, "  "));
        }

        // Domain Expiration
        if let Some(ref expiry) = response.domain_expiration {
            let mut registration = rows.section("Domain Registration");
            registration.opt("Registrar", &expiry.registrar);
            let date = expiry.expiration_date.format("%Y-%m-%d").to_string();
            registration.kv(
                "Expires",
                self.format_expiry_status(&date, expiry.days_until_expiry),
            );
        }

        // DNS Resolution
        if let Some(ref dns) = response.dns_resolution {
            let mut resolution = rows.section("DNS Resolution");
            if dns.resolves {
                resolution.push(format!("    {}", self.success("✓ Resolving")));
            } else {
                resolution.push(format!("    {}", self.error("✗ Domain does not resolve")));
            }
            if let Some(ref cname) = dns.cname_target {
                let target = self.success(&sanitize_display(cname));
                resolution.push(format!(
                    "    {}: Aliases to {}",
                    self.label("CNAME"),
                    target
                ));
            }
            for (label, values) in [
                ("IPv4 (A)", &dns.a_records),
                ("IPv6 (AAAA)", &dns.aaaa_records),
                ("Nameservers", &dns.nameservers),
            ] {
                if !values.is_empty() {
                    resolution.push(format!("    {}:", self.label(label)));
                    for value in values {
                        resolution
                            .push(format!("      • {}", self.value(&sanitize_display(value))));
                    }
                }
            }
        } else {
            rows.blank();
            rows.kv("DNS Resolution", self.warning("Check failed"));
        }

        // CAA note sits at the very bottom of the whole status output,
        // un-indented, with a blank separator line.
        if let Some(ref caa) = response.caa {
            self.push_caa_note_footer(&mut output, caa);
        }

        output.join("\n")
    }

    pub(super) fn format_ssl(&self, report: &crate::ssl::SslReport) -> String {
        let mut output =
            vec![self.header(&format!("SSL Report: {}", sanitize_display(&report.domain)))];
        let mut rows = self.rows(&mut output, "  ");
        let yes_no = |ok: bool| {
            if ok {
                self.success("yes")
            } else {
                self.error("no")
            }
        };
        rows.kv("Valid", yes_no(report.is_valid));
        rows.kv("Hostname Match", yes_no(report.hostname_verified));
        rows.kv(
            "Days Until Expiry",
            self.value(&report.days_until_expiry.to_string()),
        );

        if !report.warnings.is_empty() {
            rows.push(format!("  {}:", self.label("Warnings")));
            for w in &report.warnings {
                let rendered = match w.severity {
                    crate::ssl::CertWarningSeverity::Critical => self.error(&w.message),
                    crate::ssl::CertWarningSeverity::Warning => self.warning(&w.message),
                };
                rows.push(format!("    {} {}", self.error("⚠"), rendered));
            }
        }

        rows.opt("Protocol", &report.protocol_version);
        if !report.san_names.is_empty() {
            let sans: Vec<String> = report
                .san_names
                .iter()
                .map(|s| sanitize_display(s))
                .collect();
            rows.kv("SANs", self.value(&sans.join(", ")));
        }

        if !report.chain.is_empty() {
            rows.blank();
            rows.push(format!("  {}:", self.label("Certificate Chain")));
            for (i, cert) in report.chain.iter().enumerate() {
                rows.push(format!(
                    "    [{}] {}",
                    i,
                    self.value(&sanitize_display(&cert.subject))
                ));
                let mut detail = rows.at("        ");
                detail.text("Issuer", &cert.issuer);
                detail.opt("Algorithm", &cert.signature_algorithm);
                if let Some(ref key_type) = cert.key_type {
                    let key_type = sanitize_display(key_type);
                    let key = match cert.key_bits {
                        Some(bits) => format!("{key_type} ({bits} bits)"),
                        None => key_type,
                    };
                    detail.kv("Key", self.value(&key));
                }
                detail.kv(
                    "Validity",
                    format!(
                        "{} to {}",
                        self.value(&cert.valid_from.format("%Y-%m-%d").to_string()),
                        self.value(&cert.valid_until.format("%Y-%m-%d").to_string())
                    ),
                );
            }
        }

        if let Some(ref caa) = report.caa {
            rows.extend(self.render_caa_block(caa, "  "));
            self.push_caa_note_footer(&mut output, caa);
        }

        output.join("\n")
    }
}
