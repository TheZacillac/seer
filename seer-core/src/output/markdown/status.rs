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
        let mut output = Vec::new();

        output.push(format!("## Status: {}", MdSafe(&response.domain)));
        output.push(String::new());

        // HTTP Status
        if let Some(status) = response.http_status {
            let status_text = response.http_status_text.as_deref().unwrap_or("Unknown");
            output.push(format!(
                "- **HTTP Status**: `{}` ({})",
                status,
                MdSafe(status_text)
            ));
        }

        // Site Title
        if let Some(ref title) = response.title {
            output.push(format!("- **Site Title**: {}", MdSafe(title)));
        }

        // SSL Certificate
        output.push(String::new());
        if let Some(ref cert) = response.certificate {
            output.push("### SSL Certificate".to_string());
            output.push(String::new());
            output.push(format!("- **Subject**: `{}`", MdSafe(&cert.subject)));
            output.push(format!("- **Issuer**: {}", MdSafe(&cert.issuer)));
            output.push(format!(
                "- **Status**: {}",
                if cert.is_valid { "Valid" } else { "Invalid" }
            ));
            output.push(format!(
                "- **Valid From**: `{}`",
                cert.valid_from.format("%Y-%m-%d")
            ));
            output.push(format!(
                "- **Expires**: `{}` ({})",
                cert.valid_until.format("%Y-%m-%d"),
                expiry_phrase(cert.days_until_expiry)
            ));
        } else {
            output.push("### SSL Certificate".to_string());
            output.push(String::new());
            output.push("*Not available (HTTPS may not be configured)*".to_string());
        }

        if let Some(ref caa) = response.caa {
            output.extend(self.render_caa_section(caa));
        }

        // Domain Expiration
        if let Some(ref expiry) = response.domain_expiration {
            output.push(String::new());
            output.push("### Domain Registration".to_string());
            output.push(String::new());
            if let Some(ref registrar) = expiry.registrar {
                output.push(format!("- **Registrar**: {}", MdSafe(registrar)));
            }
            output.push(format!(
                "- **Expires**: `{}` ({})",
                expiry.expiration_date.format("%Y-%m-%d"),
                expiry_phrase(expiry.days_until_expiry)
            ));
        }

        // DNS Resolution
        output.push(String::new());
        if let Some(ref dns) = response.dns_resolution {
            output.push("### DNS Resolution".to_string());
            output.push(String::new());
            output.push(format!(
                "- **Resolves**: {}",
                if dns.resolves { "Yes" } else { "No" }
            ));

            if let Some(ref cname) = dns.cname_target {
                output.push(format!("- **CNAME**: `{}`", MdSafe(cname)));
            }
            if !dns.a_records.is_empty() {
                output.push(format!(
                    "- **IPv4 (A)**: {}",
                    dns.a_records
                        .iter()
                        .map(|ip| format!("`{}`", MdSafe(ip)))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            if !dns.aaaa_records.is_empty() {
                output.push(format!(
                    "- **IPv6 (AAAA)**: {}",
                    dns.aaaa_records
                        .iter()
                        .map(|ip| format!("`{}`", MdSafe(ip)))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            if !dns.nameservers.is_empty() {
                output.push(format!(
                    "- **Nameservers**: {}",
                    dns.nameservers
                        .iter()
                        .map(|ns| format!("`{}`", MdSafe(ns)))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        } else {
            output.push("### DNS Resolution".to_string());
            output.push(String::new());
            output.push("*Check failed*".to_string());
        }

        output.join("\n")
    }

    pub(super) fn format_ssl(&self, report: &crate::ssl::SslReport) -> String {
        let mut output = Vec::new();

        output.push(format!("## SSL Report: {}", MdSafe(&report.domain)));
        output.push(String::new());

        output.push(format!(
            "- **Valid**: {}",
            if report.is_valid { "yes" } else { "no" }
        ));
        output.push(format!(
            "- **Hostname Match**: {}",
            if report.hostname_verified {
                "yes"
            } else {
                "no"
            }
        ));
        output.push(format!(
            "- **Days Until Expiry**: {}",
            report.days_until_expiry
        ));

        if let Some(ref proto) = report.protocol_version {
            output.push(format!("- **Protocol**: {}", MdSafe(proto)));
        }

        if !report.san_names.is_empty() {
            output.push(format!(
                "- **SANs**: {}",
                report
                    .san_names
                    .iter()
                    .map(|s| format!("`{}`", MdSafe(s)))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        if !report.chain.is_empty() {
            output.push(String::new());
            output.push("### Certificate Chain".to_string());
            output.push(String::new());
            output.push("| # | Subject | Issuer | Valid Until | Key |".to_string());
            output.push("| --- | --- | --- | --- | --- |".to_string());
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
}
