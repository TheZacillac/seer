use super::*;

/// Human-readable expiry phrase for markdown (no color). Mirrors the human
/// formatter's `format_expiry_status` wording, including the already-expired
/// case which previously rendered as a confusing "(-N days)".
fn expiry_phrase(days_until: i64) -> String {
    if days_until < 0 {
        format!("expired {} days ago", -days_until)
    } else {
        format!("expires in {} days", days_until)
    }
}

impl MarkdownFormatter {
    pub(super) fn format_status(&self, response: &StatusResponse) -> String {
        let mut output = vec![
            format!("## Status: {}", MdSafe(&response.domain)),
            String::new(),
        ];
        let mut b = Bullets(&mut output);

        if let Some(status) = response.http_status {
            let status_text = response.http_status_text.as_deref().unwrap_or("Unknown");
            b.raw(
                "HTTP Status",
                format!("`{}` ({})", status, MdSafe(status_text)),
            );
        }
        b.opt("Site Title", &response.title);

        // SSL Certificate
        b.push(String::new());
        b.push("### SSL Certificate".to_string());
        b.push(String::new());
        if let Some(ref cert) = response.certificate {
            b.code("Subject", &cert.subject);
            b.text("Issuer", &cert.issuer);
            b.raw("Status", if cert.is_valid { "Valid" } else { "Invalid" });
            // `is_valid` is date-range only, so a mismatched cert still reads
            // "Valid" above; surface the hostname check explicitly (the human
            // formatter prints the same warning).
            let hostname = if cert.hostname_verified {
                "yes"
            } else {
                "**no** — ⚠ certificate hostname not verified"
            };
            b.raw("Hostname Match", hostname);
            b.date("Valid From", Some(cert.valid_from));
            let expires = format!(
                "`{}` ({})",
                cert.valid_until.format("%Y-%m-%d"),
                expiry_phrase(cert.days_until_expiry)
            );
            b.raw("Expires", expires);
        } else {
            b.push("*Not available (HTTPS may not be configured)*".to_string());
        }

        if let Some(ref caa) = response.caa {
            output.extend(self.render_caa_section(caa));
        }

        // Domain Expiration
        let mut b = Bullets(&mut output);
        if let Some(ref expiry) = response.domain_expiration {
            b.push(String::new());
            b.push("### Domain Registration".to_string());
            b.push(String::new());
            b.opt("Registrar", &expiry.registrar);
            let expires = format!(
                "`{}` ({})",
                expiry.expiration_date.format("%Y-%m-%d"),
                expiry_phrase(expiry.days_until_expiry)
            );
            b.raw("Expires", expires);
        }

        // DNS Resolution
        b.push(String::new());
        b.push("### DNS Resolution".to_string());
        b.push(String::new());
        if let Some(ref dns) = response.dns_resolution {
            b.raw("Resolves", if dns.resolves { "Yes" } else { "No" });
            b.code_opt("CNAME", &dns.cname_target);
            b.code_list("IPv4 (A)", &dns.a_records);
            b.code_list("IPv6 (AAAA)", &dns.aaaa_records);
            b.code_list("Nameservers", &dns.nameservers);
        } else {
            b.push("*Check failed*".to_string());
        }

        output.join("\n")
    }

    pub(super) fn format_ssl(&self, report: &crate::ssl::SslReport) -> String {
        let mut output = vec![
            format!("## SSL Report: {}", MdSafe(&report.domain)),
            String::new(),
        ];
        let mut b = Bullets(&mut output);
        let yes_no = |ok: bool| if ok { "yes" } else { "no" };
        b.raw("Valid", yes_no(report.is_valid));
        b.raw("Hostname Match", yes_no(report.hostname_verified));
        b.raw("Days Until Expiry", report.days_until_expiry);
        b.opt("Protocol", &report.protocol_version);
        b.code_list("SANs", &report.san_names);

        if !report.warnings.is_empty() {
            output.extend([String::new(), "### Warnings".to_string(), String::new()]);
            for w in &report.warnings {
                let tag = match w.severity {
                    crate::ssl::CertWarningSeverity::Critical => "**Critical**",
                    crate::ssl::CertWarningSeverity::Warning => "Warning",
                };
                output.push(format!("- ⚠ {}: {}", tag, MdSafe(&w.message)));
            }
        }

        if !report.chain.is_empty() {
            output.extend([
                String::new(),
                "### Certificate Chain".to_string(),
                String::new(),
                "| # | Subject | Issuer | Valid Until | Key |".to_string(),
                "| --- | --- | --- | --- | --- |".to_string(),
            ]);
            for (i, cert) in report.chain.iter().enumerate() {
                let key_info = match (&cert.key_type, cert.key_bits) {
                    (Some(kt), Some(bits)) => format!("{} ({} bits)", MdSafe(kt), bits),
                    (Some(kt), None) => format!("{}", MdSafe(kt)),
                    _ => "N/A".to_string(),
                };
                output.push(format!(
                    "| {} | {} | {} | {} | {} |",
                    i,
                    MdSafe(&cert.subject),
                    MdSafe(&cert.issuer),
                    cert.valid_until.format("%Y-%m-%d"),
                    key_info
                ));
            }
        }

        if let Some(ref caa) = report.caa {
            output.extend(self.render_caa_section(caa));
        }

        output.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::StatusResponse;

    #[test]
    fn test_markdown_format_status() {
        let response = StatusResponse::new("example.com".to_string());
        let formatter = MarkdownFormatter::new();
        let output = formatter.format_status(&response);
        assert!(output.contains("## Status: example.com"));
        assert!(output.contains("### SSL Certificate"));
        assert!(output.contains("### DNS Resolution"));
    }

    #[test]
    fn status_reports_certificate_hostname_match() {
        // `is_valid` is date-range only, so a mismatched cert rendered as
        // "- **Status**: Valid" with no warning in markdown, while the human
        // formatter flagged it.
        let mut response = StatusResponse::new("example.com".to_string());
        response.certificate = Some(crate::status::CertificateInfo {
            issuer: "CN=Mock CA".to_string(),
            subject: "CN=other.example".to_string(),
            valid_from: "2025-01-01T00:00:00Z".parse().unwrap(),
            valid_until: "2027-01-01T00:00:00Z".parse().unwrap(),
            days_until_expiry: 180,
            is_valid: true,
            hostname_verified: false,
        });
        let out = MarkdownFormatter::new().format_status(&response);
        assert!(
            out.contains("- **Hostname Match**: **no** — ⚠ certificate hostname not verified"),
            "mismatch must be flagged:\n{out}"
        );

        if let Some(cert) = response.certificate.as_mut() {
            cert.hostname_verified = true;
        }
        let out = MarkdownFormatter::new().format_status(&response);
        assert!(out.contains("- **Hostname Match**: yes"), "got:\n{out}");
        assert!(!out.contains("not verified"), "got:\n{out}");
    }
}
