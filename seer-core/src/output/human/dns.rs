use super::*;

impl HumanFormatter {
    pub(super) fn format_dns(&self, records: &[DnsRecord]) -> String {
        let mut output = Vec::new();

        if records.is_empty() {
            output.push(self.warning("No records found"));
            // DNSSEC disclaimer applies whether or not records were returned.
            output.push(String::new());
            output.push(self.warning(DNSSEC_NOTE));
            return output.join("\n");
        }

        let domain = &records[0].name;
        // Label the block by the record type when the set is uniform. An ANY
        // query returns mixed types, so labeling by records[0] (e.g. "A") is
        // misleading — fall back to "ANY" whenever more than one type appears.
        let first_type = records[0].record_type;
        let record_type = if records.iter().all(|r| r.record_type == first_type) {
            first_type.to_string()
        } else {
            "ANY".to_string()
        };
        output.push(self.header(&format!(
            "DNS {} Records: {}",
            record_type,
            sanitize_line(domain)
        )));

        for record in records {
            output.push(format!(
                "  {} {} {} {}",
                self.value(&sanitize_line(&record.name)),
                self.label(&format!("{}", record.ttl)),
                self.label(&format!("{}", record.record_type)),
                self.success(&sanitize_line(&record.data.to_string()))
            ));
        }

        // DNSSEC disclosure (M12): Seer's resolver does not validate DNSSEC,
        // and UDP DNS is trivially spoofable. Surface this once per DNS block.
        output.push(String::new());
        output.push(self.warning(DNSSEC_NOTE));

        output.join("\n")
    }

    pub(super) fn format_follow_iteration(&self, iteration: &FollowIteration) -> String {
        let mut output = Vec::new();

        let time_str = iteration.timestamp.format("%H:%M:%S").to_string();
        let iter_str = format!(
            "Iteration {}/{}",
            iteration.iteration, iteration.total_iterations
        );

        if let Some(ref error) = iteration.error {
            output.push(format!(
                "[{}] {}: {}",
                self.label(&time_str),
                iter_str,
                self.error(&sanitize_line(error))
            ));
            return output.join("\n");
        }

        let record_count = iteration.record_count();
        let status = if iteration.iteration == 1 {
            "".to_string()
        } else if iteration.changed {
            format!(" ({})", self.warning("CHANGED"))
        } else {
            format!(" ({})", self.success("unchanged"))
        };

        // Collect record values, trimming trailing dots. Record data (TXT/CAA
        // in particular) is attacker-controlled and re-printed on every
        // iteration, so sanitize each value before it reaches the terminal.
        let values: Vec<String> = iteration
            .records
            .iter()
            .map(|r| sanitize_line(r.data.to_string().trim_end_matches('.')))
            .collect();

        output.push(format!(
            "[{}] {}: {} record(s){}",
            self.label(&time_str),
            iter_str,
            record_count,
            status
        ));

        // Show records comma-separated on a single indented line
        if !values.is_empty() {
            output.push(format!("  {}", self.value(&values.join(", "))));
        }

        // Show changes if any
        for added in &iteration.added {
            let value = sanitize_line(added.trim_end_matches('.'));
            output.push(format!("  {} {}", self.success("+"), self.success(&value)));
        }
        for removed in &iteration.removed {
            let value = sanitize_line(removed.trim_end_matches('.'));
            output.push(format!("  {} {}", self.error("-"), self.error(&value)));
        }

        output.join("\n")
    }

    pub(super) fn format_follow(&self, result: &FollowResult) -> String {
        let mut output = vec![self.header(&format!(
            "DNS Follow Complete: {} {}",
            sanitize_line(&result.domain),
            result.record_type
        ))];
        let mut rows = self.rows(&mut output, "  ");

        // Summary
        let completed = format!(
            "{}/{}",
            result.completed_iterations(),
            result.iterations_requested
        );
        rows.kv("Iterations completed", completed);
        if result.interrupted {
            rows.kv("Status", self.warning("Interrupted"));
        }
        let changes = result.total_changes.to_string();
        let changes = if result.total_changes > 0 {
            self.warning(&changes)
        } else {
            self.success(&changes)
        };
        rows.kv("Total changes detected", changes);
        let duration = result.ended_at - result.started_at;
        rows.kv("Duration", self.value(&format_duration(duration)));

        // Show iteration details
        if !result.iterations.is_empty() {
            let mut details = rows.section("Iteration Details");
            for iteration in &result.iterations {
                let time_str = iteration.timestamp.format("%H:%M:%S").to_string();
                let status = if iteration.error.is_some() {
                    self.error("ERROR")
                } else if iteration.changed {
                    self.warning("CHANGED")
                } else if iteration.iteration == 1 {
                    self.value("initial")
                } else {
                    self.success("stable")
                };
                details.push(format!(
                    "    [{}] #{}: {} record(s) - {}",
                    time_str,
                    iteration.iteration,
                    iteration.record_count(),
                    status
                ));
            }
        }

        output.join("\n")
    }

    pub(super) fn format_dnssec(&self, report: &crate::dns::DnssecReport) -> String {
        let mut output = vec![
            format!(
                "DNSSEC Report for {}",
                self.success(&sanitize_line(&report.domain))
            ),
            String::new(),
        ];
        let mut rows = self.rows(&mut output, "  ");

        let status = match report.status.as_str() {
            "signed" => self.success(&report.status),
            "unsigned" | "partial" => self.warning(&report.status),
            _ => self.error(&report.status),
        };
        rows.kv("Status", status);
        let chain = if report.chain_valid {
            self.success("valid")
        } else if report.has_ds_records && report.has_dnskey_records {
            self.error("invalid")
        } else {
            self.warning("n/a")
        };
        rows.kv("Chain Valid", chain);
        let (depth, note) = dnssec_depth(report.authentication_tier);
        rows.kv("Verification depth", self.value(depth));
        if let Some(note) = note {
            rows.push(format!("  {}", self.warning(note)));
        }
        rows.kv("Enabled", self.value(&report.enabled.to_string()));
        let ds_count = report.ds_records.len().to_string();
        rows.kv("DS Records", self.value(&ds_count));
        let dnskey_count = report.dnskey_records.len().to_string();
        rows.kv("DNSKEY Records", self.value(&dnskey_count));

        if !report.ds_records.is_empty() {
            let mut ds_rows = rows.section("DS Records");
            for ds in &report.ds_records {
                let match_indicator = if ds.matched_key && ds.digest_verified {
                    self.success("\u{2713} verified")
                } else if ds.matched_key {
                    self.error("\u{2717} digest mismatch")
                } else {
                    self.error("\u{2717} no matching key")
                };
                ds_rows.push(format!(
                    "    Key Tag: {}, Algorithm: {} ({}), Digest: {} ({}) [{}]",
                    ds.key_tag,
                    ds.algorithm,
                    sanitize_line(&ds.algorithm_name),
                    ds.digest_type,
                    sanitize_line(&ds.digest_type_name),
                    match_indicator,
                ));
            }
        }

        if !report.dnskey_records.is_empty() {
            let mut key_rows = rows.section("DNSKEY Records");
            for key in &report.dnskey_records {
                let role = if key.is_ksk {
                    "KSK"
                } else if key.is_zsk {
                    "ZSK"
                } else {
                    "Other"
                };
                key_rows.push(format!(
                    "    Key Tag: {}, Flags: {}, Role: {}, Algorithm: {} ({})",
                    key.key_tag,
                    key.flags,
                    role,
                    key.algorithm,
                    sanitize_line(&key.algorithm_name)
                ));
            }
        }

        if !report.issues.is_empty() {
            let mut issue_rows = rows.section("Issues");
            for issue in &report.issues {
                issue_rows.push(format!("    - {}", sanitize_line(issue)));
            }
        }

        output.join("\n")
    }

    pub(super) fn format_dns_comparison(&self, comparison: &crate::dns::DnsComparison) -> String {
        let mut output = vec![self.header(&format!(
            "DNS Comparison: {} {}",
            sanitize_line(&comparison.domain),
            comparison.record_type
        ))];

        // Match status
        if comparison.matches {
            output.push(format!("  {} Records match", self.success("✓")));
        } else {
            output.push(format!("  {} Records differ", self.error("✗")));
        }
        output.push(String::new());

        // Each server's answer (or error), then the set comparison.
        for (label, server) in [
            ("Server A", &comparison.server_a),
            ("Server B", &comparison.server_b),
        ] {
            let nameserver = self.value(&sanitize_line(&server.nameserver));
            if let Some(ref err) = server.error {
                output.push(format!(
                    "  {} ({}): {}",
                    self.label(label),
                    nameserver,
                    self.error(&sanitize_line(err))
                ));
            } else {
                output.push(format!(
                    "  {} ({}): {} records",
                    self.label(label),
                    nameserver,
                    self.value(&server.records.len().to_string())
                ));
                for record in &server.records {
                    let record = sanitize_line(&record.format_short());
                    output.push(format!("    - {}", self.value(&record)));
                }
            }
            output.push(String::new());
        }

        let joined = |values: &[String]| sanitize_line(&values.join(", "));
        let mut rows = self.rows(&mut output, "  ");
        let common = if comparison.common.is_empty() {
            self.warning("(none)")
        } else {
            self.value(&joined(&comparison.common))
        };
        rows.kv("Common", common);
        for (server, only) in [
            (&comparison.server_a, &comparison.only_in_a),
            (&comparison.server_b, &comparison.only_in_b),
        ] {
            let label = format!("Only in {}", sanitize_line(&server.nameserver));
            let rendered = if only.is_empty() {
                self.warning("(none)")
            } else {
                self.error(&joined(only))
            };
            rows.kv(&label, rendered);
        }

        output.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{RecordData, RecordType};

    /// A TXT value carrying an OSC 52 clipboard write and a CSI screen clear.
    const EVIL_TXT: &str = "v=spf1\x1b]52;c;AAAA\x07 -all\x1b[2J";

    fn follow_iteration_with_evil_txt() -> FollowIteration {
        FollowIteration {
            iteration: 2,
            total_iterations: 3,
            timestamp: Utc::now(),
            records: vec![DnsRecord {
                name: "example.com".to_string(),
                record_type: RecordType::TXT,
                ttl: 300,
                data: RecordData::TXT {
                    text: EVIL_TXT.to_string(),
                },
            }],
            changed: true,
            added: vec![EVIL_TXT.to_string()],
            removed: vec![format!("old{EVIL_TXT}")],
            error: None,
        }
    }

    #[test]
    fn follow_iteration_sanitizes_record_values_and_changes() {
        // `seer follow` re-prints every record value, plus the added/removed
        // change lists, on each iteration — the only human DNS path that
        // skipped sanitize_line, so an OSC 52 clipboard write or a screen
        // clear in a TXT record reached the terminal verbatim.
        let out = HumanFormatter::new()
            .without_colors()
            .format_follow_iteration(&follow_iteration_with_evil_txt());
        assert!(
            !out.contains('\x1b'),
            "ESC must not reach terminal: {out:?}"
        );
        assert!(
            !out.contains('\x07'),
            "BEL must not reach terminal: {out:?}"
        );
        assert!(!out.contains("52;c;"), "OSC 52 payload leaked: {out:?}");
        // The legitimate text survives in the values line (TXT data renders
        // quoted) and both change lines.
        assert!(out.contains("  \"v=spf1 -all\""), "value line: {out:?}");
        assert!(out.contains("+ v=spf1 -all"), "added line: {out:?}");
        assert!(out.contains("- oldv=spf1 -all"), "removed line: {out:?}");
    }

    #[test]
    fn remote_newlines_cannot_forge_record_or_change_rows() {
        // Human DNS rows kept `\n`, so a TXT value could print a fake,
        // aligned A record row (or a fake `+` change line) of its own.
        let forged = "v=spf1 -all\n  example.com 300 A 6.6.6.6";
        let record = DnsRecord {
            name: "example.com".to_string(),
            record_type: RecordType::TXT,
            ttl: 300,
            data: RecordData::TXT {
                text: forged.to_string(),
            },
        };
        let f = HumanFormatter::new().without_colors();
        let mut it = follow_iteration_with_evil_txt();
        it.records = vec![record.clone()];
        it.added = vec!["x\n  + 6.6.6.6".to_string()];
        for out in [f.format_dns(&[record]), f.format_follow_iteration(&it)] {
            assert!(
                !out.lines()
                    .any(|l| l.trim_start().starts_with("example.com 300 A")),
                "forged record row:\n{out}"
            );
            assert!(
                !out.lines().any(|l| l.trim_start().starts_with("+ 6.6.6.6")),
                "forged change row:\n{out}"
            );
        }
    }

    #[test]
    fn follow_iteration_sanitizes_error() {
        let mut it = follow_iteration_with_evil_txt();
        it.error = Some(format!("resolver said: {EVIL_TXT}"));
        let out = HumanFormatter::new()
            .without_colors()
            .format_follow_iteration(&it);
        assert!(
            !out.contains('\x1b'),
            "ESC must not reach terminal: {out:?}"
        );
        assert!(out.contains("resolver said: v=spf1 -all"), "got: {out:?}");
    }
}
