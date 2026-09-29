use super::*;

impl MarkdownFormatter {
    pub(super) fn format_dns(&self, records: &[DnsRecord]) -> String {
        let mut output = Vec::new();

        if records.is_empty() {
            output.push("*No records found*".to_string());
            output.push(String::new());
            output.push(format!("> {DNSSEC_NOTE}."));
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
        record_table(&mut output, records);

        output.push(String::new());
        output.push(format!("> {DNSSEC_NOTE}."));

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
            format!(" `{}`", MdCode(&joined))
        };

        let mut output = vec![format!(
            "[{}] Iteration {}/{}: {} record(s){}{}",
            time_str,
            iteration.iteration,
            iteration.total_iterations,
            record_count,
            status,
            values_str
        )];

        // Per-value change lists, matching the human formatter's +/- lines.
        for added in &iteration.added {
            output.push(format!(
                "- Added: `{}`",
                MdCode(added.trim_end_matches('.'))
            ));
        }
        for removed in &iteration.removed {
            output.push(format!(
                "- Removed: `{}`",
                MdCode(removed.trim_end_matches('.'))
            ));
        }

        output.join("\n")
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

        // Reuse the shared duration formatter rather than re-deriving the
        // <60 / <3600 / else breakdown (kept identical to the human path).
        let duration = result.ended_at - result.started_at;
        let duration_str = format_duration(duration);
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

        let (depth, note) = dnssec_depth(report.authentication_tier);
        let mut b = Bullets(&mut output);
        b.code("Status", &report.status);
        b.raw("Chain Valid", if report.chain_valid { "yes" } else { "no" });
        b.raw("Verification depth", depth);
        b.raw("Enabled", report.enabled);
        b.raw("DS Records", report.ds_records.len());
        b.raw("DNSKEY Records", report.dnskey_records.len());
        // A quote inside a list would end it; it follows the list instead.
        if let Some(note) = note {
            output.extend([String::new(), format!("> {note}")]);
        }

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
        let result = format!("**Result**: {}", comparison.summary());
        let mut output = vec![
            format!(
                "## DNS Comparison: {} {}",
                MdSafe(&comparison.domain),
                comparison.record_type
            ),
            String::new(),
            result,
            String::new(),
        ];

        for (label, server) in [
            ("Server A", &comparison.server_a),
            ("Server B", &comparison.server_b),
        ] {
            output.push(format!("### {} ({})", label, MdSafe(&server.nameserver)));
            output.push(String::new());
            if let Some(ref err) = server.error {
                output.push(format!("**Error**: {}", MdSafe(err)));
                output.push(String::new());
                continue;
            }
            if let Some(status) = server.status_label() {
                output.push(format!("**Status**: {status}"));
                output.push(String::new());
            }
            if !server.cname_chain.is_empty() {
                let hops: Vec<String> = server
                    .cname_chain
                    .iter()
                    .map(|hop| format!("{} → {}", hop.name, hop.format_short()))
                    .collect();
                output.push(format!("**CNAME chain**: {}", code_list(&hops)));
                output.push(String::new());
            }
            if server.records.is_empty() {
                output.push("*No records found*".to_string());
            } else {
                output.push("| Record |".to_string());
                output.push("| --- |".to_string());
                for record in &server.records {
                    output.push(format!("| `{}` |", MdCodeCell(&record.format_short())));
                }
            }
            output.push(String::new());
        }

        // Differences
        output.push("### Comparison".to_string());
        output.push(String::new());
        let listed = |values: &[String]| {
            if values.is_empty() {
                "*(none)*".to_string()
            } else {
                code_list(values)
            }
        };
        let mut b = Bullets(&mut output);
        b.raw("Common", listed(&comparison.common));
        for (server, only) in [
            (&comparison.server_a, &comparison.only_in_a),
            (&comparison.server_b, &comparison.only_in_b),
        ] {
            let label = format!("Only in {}", MdSafe(&server.nameserver));
            b.raw(&label, listed(only));
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

    #[test]
    fn markdown_follow_duration_matches_shared_formatter() {
        use chrono::{Duration, Utc};

        // 125s span → "2m 5s" via the shared helper. The markdown follow
        // formatter must reuse that exact string (no re-derived breakdown).
        let started = Utc::now();
        let ended = started + Duration::seconds(125);
        let result = FollowResult {
            domain: "example.com".to_string(),
            record_type: RecordType::A,
            nameserver: None,
            iterations_requested: 1,
            interval_secs: 0,
            iterations: Vec::new(),
            interrupted: false,
            total_changes: 0,
            started_at: started,
            ended_at: ended,
        };

        let expected = format_duration(ended - started);
        assert_eq!(expected, "2m 5s", "sanity: shared formatter output");

        let out = MarkdownFormatter::new().format_follow(&result);
        assert!(
            out.contains(&format!("- **Duration**: {}", expected)),
            "markdown duration must match the shared formatter:\n{out}"
        );
    }

    #[test]
    fn markdown_follow_iteration_lists_added_and_removed_values() {
        // The human formatter prints the per-value +/- change lists; the
        // markdown iteration line dropped them, so `--format markdown` only
        // said "CHANGED" without saying what changed.
        let iteration = FollowIteration {
            iteration: 2,
            total_iterations: 3,
            timestamp: Utc::now(),
            records: vec![DnsRecord {
                name: "example.com".to_string(),
                record_type: RecordType::A,
                ttl: 60,
                data: crate::dns::RecordData::A {
                    address: "5.6.7.8".to_string(),
                },
            }],
            changed: true,
            added: vec!["5.6.7.8".to_string()],
            removed: vec!["1.2.3.4".to_string(), "evil`|x".to_string()],
            error: None,
        };
        let out = MarkdownFormatter::new().format_follow_iteration(&iteration);
        assert!(out.contains("(**CHANGED**) `5.6.7.8`"), "got:\n{out}");
        assert!(out.contains("\n- Added: `5.6.7.8`"), "got:\n{out}");
        assert!(out.contains("\n- Removed: `1.2.3.4`"), "got:\n{out}");
        // Change values are attacker-controlled record data, escaped for a
        // code span: the backtick is neutralized, a pipe is harmless there.
        assert!(out.contains("\n- Removed: `evil'|x`"), "got:\n{out}");
    }
}
