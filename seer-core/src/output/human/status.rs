use super::*;

impl HumanFormatter {
    pub(super) fn format_status(&self, response: &StatusResponse) -> String {
        let mut output = Vec::new();

        output.push(self.header(&format!("Status: {}", sanitize_display(&response.domain))));

        // HTTP Status
        if let Some(status) = response.http_status {
            let status_text =
                sanitize_display(response.http_status_text.as_deref().unwrap_or("Unknown"));
            let status_display = if (200..300).contains(&status) {
                self.success(&format!("{} ({})", status, status_text))
            } else if (300..400).contains(&status) {
                self.warning(&format!("{} ({})", status, status_text))
            } else {
                self.error(&format!("{} ({})", status, status_text))
            };
            output.push(format!(
                "  {}: {}",
                self.label("HTTP Status"),
                status_display
            ));
        }

        // Site Title
        if let Some(ref title) = response.title {
            output.push(format!(
                "  {}: {}",
                self.label("Site Title"),
                self.value(&sanitize_display(title))
            ));
        }

        // SSL Certificate
        if let Some(ref cert) = response.certificate {
            output.push(format!("\n  {}:", self.label("SSL Certificate")));
            output.push(format!(
                "    {}: {}",
                self.label("Subject"),
                self.value(&sanitize_display(&cert.subject))
            ));
            output.push(format!(
                "    {}: {}",
                self.label("Issuer"),
                self.value(&sanitize_display(&cert.issuer))
            ));

            let valid_status = if cert.is_valid {
                self.success("Valid")
            } else {
                self.error("Invalid")
            };
            output.push(format!("    {}: {}", self.label("Status"), valid_status));

            if !cert.hostname_verified {
                output.push(format!(
                    "    {}",
                    self.error("WARNING: certificate hostname not verified")
                ));
            }

            output.push(format!(
                "    {}: {}",
                self.label("Valid From"),
                self.value(&cert.valid_from.format("%Y-%m-%d").to_string())
            ));

            let expiry_str = cert.valid_until.format("%Y-%m-%d").to_string();
            // Shared helper renders the already-expired (negative) case as
            // "expired N days ago" instead of a confusing "(-N days!)".
            let expiry_display = self.format_expiry_status(&expiry_str, cert.days_until_expiry);
            output.push(format!("    {}: {}", self.label("Expires"), expiry_display));
        } else {
            output.push(format!(
                "\n  {}: {}",
                self.label("SSL Certificate"),
                self.warning("Not available (HTTPS may not be configured)")
            ));
        }

        // CAA policy (issuance-time authorization for certificate authorities)
        if let Some(ref caa) = response.caa {
            output.extend(self.render_caa_block(caa, "  "));
        }

        // Domain Expiration
        if let Some(ref expiry) = response.domain_expiration {
            output.push(format!("\n  {}:", self.label("Domain Registration")));

            if let Some(ref registrar) = expiry.registrar {
                output.push(format!(
                    "    {}: {}",
                    self.label("Registrar"),
                    self.value(&sanitize_display(registrar))
                ));
            }

            let expiry_str = expiry.expiration_date.format("%Y-%m-%d").to_string();
            let expiry_display = self.format_expiry_status(&expiry_str, expiry.days_until_expiry);
            output.push(format!("    {}: {}", self.label("Expires"), expiry_display));
        }

        // DNS Resolution
        if let Some(ref dns) = response.dns_resolution {
            output.push(format!("\n  {}:", self.label("DNS Resolution")));

            // Status line
            if dns.resolves {
                output.push(format!("    {}", self.success("✓ Resolving")));
            } else {
                output.push(format!("    {}", self.error("✗ Domain does not resolve")));
            }

            // CNAME if present
            if let Some(ref cname) = dns.cname_target {
                output.push(format!(
                    "    {}: Aliases to {}",
                    self.label("CNAME"),
                    self.success(&sanitize_display(cname))
                ));
            }

            // IPv4 addresses (A records)
            if !dns.a_records.is_empty() {
                output.push(format!("    {}:", self.label("IPv4 (A)")));
                for ip in &dns.a_records {
                    output.push(format!("      • {}", self.value(&sanitize_display(ip))));
                }
            }

            // IPv6 addresses (AAAA records)
            if !dns.aaaa_records.is_empty() {
                output.push(format!("    {}:", self.label("IPv6 (AAAA)")));
                for ip in &dns.aaaa_records {
                    output.push(format!("      • {}", self.value(&sanitize_display(ip))));
                }
            }

            // Nameservers
            if !dns.nameservers.is_empty() {
                output.push(format!("    {}:", self.label("Nameservers")));
                for ns in &dns.nameservers {
                    output.push(format!("      • {}", self.value(&sanitize_display(ns))));
                }
            }
        } else {
            output.push(format!(
                "\n  {}: {}",
                self.label("DNS Resolution"),
                self.warning("Check failed")
            ));
        }

        // CAA note sits at the very bottom of the whole status output,
        // un-indented, with a blank separator line.
        if let Some(ref caa) = response.caa {
            self.push_caa_note_footer(&mut output, caa);
        }

        output.join("\n")
    }

    pub(super) fn format_ssl(&self, report: &crate::ssl::SslReport) -> String {
        let mut output = Vec::new();

        output.push(self.header(&format!("SSL Report: {}", sanitize_display(&report.domain))));

        output.push(format!(
            "  {}: {}",
            self.label("Valid"),
            if report.is_valid {
                self.success("yes")
            } else {
                self.error("no")
            }
        ));
        output.push(format!(
            "  {}: {}",
            self.label("Hostname Match"),
            if report.hostname_verified {
                self.success("yes")
            } else {
                self.error("no")
            }
        ));
        output.push(format!(
            "  {}: {}",
            self.label("Days Until Expiry"),
            self.value(&report.days_until_expiry.to_string())
        ));

        if let Some(ref proto) = report.protocol_version {
            output.push(format!(
                "  {}: {}",
                self.label("Protocol"),
                self.value(&sanitize_display(proto))
            ));
        }

        if !report.san_names.is_empty() {
            let sanitized_sans: Vec<String> = report
                .san_names
                .iter()
                .map(|s| sanitize_display(s))
                .collect();
            output.push(format!(
                "  {}: {}",
                self.label("SANs"),
                self.value(&sanitized_sans.join(", "))
            ));
        }

        if !report.chain.is_empty() {
            output.push(String::new());
            output.push(format!("  {}:", self.label("Certificate Chain")));
            for (i, cert) in report.chain.iter().enumerate() {
                output.push(format!(
                    "    [{}] {}",
                    i,
                    self.value(&sanitize_display(&cert.subject))
                ));
                output.push(format!(
                    "        {}: {}",
                    self.label("Issuer"),
                    self.value(&sanitize_display(&cert.issuer))
                ));
                if let Some(ref alg) = cert.signature_algorithm {
                    output.push(format!(
                        "        {}: {}",
                        self.label("Algorithm"),
                        self.value(&sanitize_display(alg))
                    ));
                }
                if let Some(ref key_type) = cert.key_type {
                    let key_info = if let Some(bits) = cert.key_bits {
                        format!("{} ({} bits)", sanitize_display(key_type), bits)
                    } else {
                        sanitize_display(key_type)
                    };
                    output.push(format!(
                        "        {}: {}",
                        self.label("Key"),
                        self.value(&key_info)
                    ));
                }
                output.push(format!(
                    "        {}: {} to {}",
                    self.label("Validity"),
                    self.value(&cert.valid_from.format("%Y-%m-%d").to_string()),
                    self.value(&cert.valid_until.format("%Y-%m-%d").to_string())
                ));
            }
        }

        if let Some(ref caa) = report.caa {
            output.extend(self.render_caa_block(caa, "  "));
            self.push_caa_note_footer(&mut output, caa);
        }

        output.join("\n")
    }
}
