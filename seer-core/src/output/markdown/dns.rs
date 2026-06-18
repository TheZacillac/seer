use super::*;

impl MarkdownFormatter {
    pub(super) fn format_dns(&self, records: &[DnsRecord]) -> String {
        let mut output = Vec::new();

        if records.is_empty() {
            output.push("*No records found*".to_string());
            output.push(String::new());
            output.push("> Note: DNS responses are not DNSSEC-validated.".to_string());
            return output.join("\n");
        }

        let domain = &records[0].name;
        // Label by the record type only when the set is uniform; an ANY query
        // returns mixed types and must not be labeled by records[0].
        let first_type = records[0].record_type;
        let record_type = if records.iter().all(|r| r.record_type == first_type) {
            first_type.to_string()
        } else {
            "ANY".to_string()
        };
        output.push(format!(
            "## DNS {} Records: {}",
            record_type,
            MdSafe(domain)
        ));
        output.push(String::new());
        output.push("| Name | TTL | Type | Data |".to_string());
        output.push("| --- | --- | --- | --- |".to_string());

        for record in records {
            let data_str = record.data.to_string();
            output.push(format!(
                "| `{}` | {} | {} | `{}` |",
                MdSafe(&record.name),
                record.ttl,
                record.record_type,
                MdSafe(&data_str)
            ));
        }

        output.push(String::new());
        output.push("> Note: DNS responses are not DNSSEC-validated.".to_string());

        output.join("\n")
    }

    pub(super) fn format_follow_iteration(&self, iteration: &FollowIteration) -> String {
        let time_str = iteration.timestamp.format("%H:%M:%S").to_string();

        if let Some(ref error) = iteration.error {
            return format!(
                "[{}] Iteration {}/{}: **ERROR** - {}",
                time_str,
                iteration.iteration,
                iteration.total_iterations,
                MdSafe(error)
            );
        }

        let record_count = iteration.record_count();
        let status = if iteration.iteration == 1 {
            String::new()
        } else if iteration.changed {
            " (**CHANGED**)".to_string()
        } else {
            " (unchanged)".to_string()
        };

        let values: Vec<String> = iteration
            .records
            .iter()
            .map(|r| r.data.to_string().trim_end_matches('.').to_string())
            .collect();

        let values_str = if values.is_empty() {
            String::new()
        } else {
            let joined = values.join(", ");
            format!(" `{}`", MdSafe(&joined))
        };

        format!(
            "[{}] Iteration {}/{}: {} record(s){}{}",
            time_str,
            iteration.iteration,
            iteration.total_iterations,
            record_count,
            status,
            values_str
        )
    }

    pub(super) fn format_follow(&self, result: &FollowResult) -> String {
        let mut output = Vec::new();

        output.push(format!(
            "## DNS Follow: {} {}",
            MdSafe(&result.domain),
            result.record_type
        ));
        output.push(String::new());

        // Summary
        output.push(format!(
            "- **Iterations**: {}/{}",
            result.completed_iterations(),
            result.iterations_requested
        ));

        if result.interrupted {
            output.push("- **Status**: Interrupted".to_string());
        }

        output.push(format!("- **Total changes**: {}", result.total_changes));

        let duration = result.ended_at - result.started_at;
        let total_secs = duration.num_seconds();
        let duration_str = if total_secs < 60 {
            format!("{}s", total_secs)
        } else if total_secs < 3600 {
            format!("{}m {}s", total_secs / 60, total_secs % 60)
        } else {
            format!("{}h {}m", total_secs / 3600, (total_secs % 3600) / 60)
        };
        output.push(format!("- **Duration**: {}", duration_str));

        // Iteration details table
        if !result.iterations.is_empty() {
            output.push(String::new());
            output.push("### Iteration Details".to_string());
            output.push(String::new());
            output.push("| # | Time | Records | Status |".to_string());
            output.push("| --- | --- | --- | --- |".to_string());

            for iteration in &result.iterations {
                let time_str = iteration.timestamp.format("%H:%M:%S").to_string();
                let status = if iteration.error.is_some() {
                    "ERROR"
                } else if iteration.changed {
                    "CHANGED"
                } else if iteration.iteration == 1 {
                    "initial"
                } else {
                    "stable"
                };

                output.push(format!(
                    "| {} | {} | {} | {} |",
                    iteration.iteration,
                    time_str,
                    iteration.record_count(),
                    status
                ));
            }
        }

        output.join("\n")
    }

    pub(super) fn format_dnssec(&self, report: &crate::dns::DnssecReport) -> String {
        let mut output = Vec::new();

        output.push(format!("## DNSSEC: {}", MdSafe(&report.domain)));
        output.push(String::new());

        output.push(format!("- **Status**: `{}`", MdSafe(&report.status)));
        output.push(format!(
            "- **Chain Valid**: {}",
            if report.chain_valid { "yes" } else { "no" }
        ));
        output.push(
            "> Note: reflects DS/DNSKEY digest consistency only — RRSIG signatures, validity \
             periods, and the chain to the root are NOT cryptographically verified."
                .to_string(),
        );
        output.push(format!("- **Enabled**: {}", report.enabled));
        output.push(format!("- **DS Records**: {}", report.ds_records.len()));
        output.push(format!(
            "- **DNSKEY Records**: {}",
            report.dnskey_records.len()
        ));

        if !report.ds_records.is_empty() {
            output.push(String::new());
            output.push("### DS Records".to_string());
            output.push(String::new());
            output.push("| Key Tag | Algorithm | Digest Type | Matched | Verified |".to_string());
            output.push("| --- | --- | --- | --- | --- |".to_string());
            for ds in &report.ds_records {
                // `algorithm_name` / `digest_type_name` come from a small
                // internal lookup table today, but wrapping in MdSafe is
                // cheap and prevents a future contributor adding a parser
                // path that pulls these from the wire from producing a
                // Markdown injection.
                output.push(format!(
                    "| {} | {} ({}) | {} ({}) | {} | {} |",
                    ds.key_tag,
                    ds.algorithm,
                    MdSafe(&ds.algorithm_name),
                    ds.digest_type,
                    MdSafe(&ds.digest_type_name),
                    if ds.matched_key { "yes" } else { "no" },
                    if ds.digest_verified { "yes" } else { "no" },
                ));
            }
        }

        if !report.dnskey_records.is_empty() {
            output.push(String::new());
            output.push("### DNSKEY Records".to_string());
            output.push(String::new());
            output.push("| Key Tag | Flags | Role | Algorithm |".to_string());
            output.push("| --- | --- | --- | --- |".to_string());
            for key in &report.dnskey_records {
                let role = if key.is_ksk {
                    "KSK"
                } else if key.is_zsk {
                    "ZSK"
                } else {
                    "Other"
                };
                output.push(format!(
                    "| {} | {} | {} | {} ({}) |",
                    key.key_tag,
                    key.flags,
                    role,
                    key.algorithm,
                    MdSafe(&key.algorithm_name)
                ));
            }
        }

        if !report.issues.is_empty() {
            output.push(String::new());
            output.push("### Issues".to_string());
            output.push(String::new());
            for issue in &report.issues {
                output.push(format!("- {}", MdSafe(issue)));
            }
        }

        output.join("\n")
    }

    pub(super) fn format_dns_comparison(&self, comparison: &crate::dns::DnsComparison) -> String {
        let mut output = Vec::new();

        output.push(format!(
            "## DNS Comparison: {} {}",
            MdSafe(&comparison.domain),
            comparison.record_type
        ));
        output.push(String::new());

        if comparison.matches {
            output.push("**Result**: Records match".to_string());
        } else {
            output.push("**Result**: Records differ".to_string());
        }
        output.push(String::new());

        // Server A
        output.push(format!(
            "### Server A ({})",
            MdSafe(&comparison.server_a.nameserver)
        ));
        output.push(String::new());
        if let Some(ref err) = comparison.server_a.error {
            output.push(format!("**Error**: {}", MdSafe(err)));
        } else if comparison.server_a.records.is_empty() {
            output.push("*No records found*".to_string());
        } else {
            output.push("| Record |".to_string());
            output.push("| --- |".to_string());
            for record in &comparison.server_a.records {
                let s = record.format_short();
                output.push(format!("| `{}` |", MdSafe(&s)));
            }
        }
        output.push(String::new());

        // Server B
        output.push(format!(
            "### Server B ({})",
            MdSafe(&comparison.server_b.nameserver)
        ));
        output.push(String::new());
        if let Some(ref err) = comparison.server_b.error {
            output.push(format!("**Error**: {}", MdSafe(err)));
        } else if comparison.server_b.records.is_empty() {
            output.push("*No records found*".to_string());
        } else {
            output.push("| Record |".to_string());
            output.push("| --- |".to_string());
            for record in &comparison.server_b.records {
                let s = record.format_short();
                output.push(format!("| `{}` |", MdSafe(&s)));
            }
        }
        output.push(String::new());

        // Differences
        output.push("### Comparison".to_string());
        output.push(String::new());

        if comparison.common.is_empty() {
            output.push("- **Common**: *(none)*".to_string());
        } else {
            output.push(format!(
                "- **Common**: {}",
                comparison
                    .common
                    .iter()
                    .map(|r| format!("`{}`", MdSafe(r)))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        if comparison.only_in_a.is_empty() {
            output.push(format!(
                "- **Only in {}**: *(none)*",
                MdSafe(&comparison.server_a.nameserver)
            ));
        } else {
            output.push(format!(
                "- **Only in {}**: {}",
                MdSafe(&comparison.server_a.nameserver),
                comparison
                    .only_in_a
                    .iter()
                    .map(|r| format!("`{}`", MdSafe(r)))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        if comparison.only_in_b.is_empty() {
            output.push(format!(
                "- **Only in {}**: *(none)*",
                MdSafe(&comparison.server_b.nameserver)
            ));
        } else {
            output.push(format!(
                "- **Only in {}**: {}",
                MdSafe(&comparison.server_b.nameserver),
                comparison
                    .only_in_b
                    .iter()
                    .map(|r| format!("`{}`", MdSafe(r)))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        output.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::RecordType;

    #[test]
    fn test_markdown_format_dns_records() {
        let records = vec![DnsRecord {
            name: "example.com".to_string(),
            record_type: RecordType::A,
            ttl: 300,
            data: crate::dns::RecordData::A {
                address: "93.184.216.34".to_string(),
            },
        }];
        let formatter = MarkdownFormatter::new();
        let output = formatter.format_dns(&records);
        assert!(output.contains("## DNS A Records: example.com"));
        assert!(output.contains("| Name | TTL | Type | Data |"));
        assert!(output.contains("93.184.216.34"));
        assert!(
            output.contains("DNSSEC-validated"),
            "DNS output must disclose DNSSEC is not validated"
        );
    }

    #[test]
    fn test_markdown_format_dns_empty() {
        let formatter = MarkdownFormatter::new();
        let output = formatter.format_dns(&[]);
        assert!(output.contains("No records found"));
        assert!(output.contains("DNSSEC-validated"));
    }
}
