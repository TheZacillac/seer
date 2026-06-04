use super::*;

impl HumanFormatter {
    pub(super) fn format_dns(&self, records: &[DnsRecord]) -> String {
        let mut output = Vec::new();

        if records.is_empty() {
            output.push(self.warning("No records found"));
            // DNSSEC disclaimer applies whether or not records were returned.
            output.push(String::new());
            output.push(self.warning("Note: DNS responses are not DNSSEC-validated"));
            return output.join("\n");
        }

        let domain = &records[0].name;
        let record_type = &records[0].record_type;
        output.push(self.header(&format!(
            "DNS {} Records: {}",
            record_type,
            sanitize_display(domain)
        )));

        for record in records {
            output.push(format!(
                "  {} {} {} {}",
                self.value(&sanitize_display(&record.name)),
                self.label(&format!("{}", record.ttl)),
                self.label(&format!("{}", record.record_type)),
                self.success(&sanitize_display(&record.data.to_string()))
            ));
        }

        // DNSSEC disclosure (M12): Seer's resolver does not validate DNSSEC,
        // and UDP DNS is trivially spoofable. Surface this once per DNS block.
        output.push(String::new());
        output.push(self.warning("Note: DNS responses are not DNSSEC-validated"));

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
                self.error(error)
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

        // Collect record values, trimming trailing dots
        let values: Vec<String> = iteration
            .records
            .iter()
            .map(|r| r.data.to_string().trim_end_matches('.').to_string())
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
        if !iteration.added.is_empty() {
            for added in &iteration.added {
                let value = added.trim_end_matches('.');
                output.push(format!("  {} {}", self.success("+"), self.success(value)));
            }
        }
        if !iteration.removed.is_empty() {
            for removed in &iteration.removed {
                let value = removed.trim_end_matches('.');
                output.push(format!("  {} {}", self.error("-"), self.error(value)));
            }
        }

        output.join("\n")
    }

    pub(super) fn format_follow(&self, result: &FollowResult) -> String {
        let mut output = Vec::new();

        output.push(self.header(&format!(
            "DNS Follow Complete: {} {}",
            result.domain, result.record_type
        )));

        // Summary
        output.push(format!(
            "  {}: {}/{}",
            self.label("Iterations completed"),
            result.completed_iterations(),
            result.iterations_requested
        ));

        if result.interrupted {
            output.push(format!(
                "  {}: {}",
                self.label("Status"),
                self.warning("Interrupted")
            ));
        }

        output.push(format!(
            "  {}: {}",
            self.label("Total changes detected"),
            if result.total_changes > 0 {
                self.warning(&result.total_changes.to_string())
            } else {
                self.success(&result.total_changes.to_string())
            }
        ));

        let duration = result.ended_at - result.started_at;
        output.push(format!(
            "  {}: {}",
            self.label("Duration"),
            self.value(&format_duration(duration))
        ));

        // Show iteration details
        if !result.iterations.is_empty() {
            output.push(format!("\n  {}:", self.label("Iteration Details")));
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

                output.push(format!(
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
        let mut output = Vec::new();

        output.push(format!(
            "DNSSEC Report for {}",
            self.success(&sanitize_display(&report.domain))
        ));
        output.push(String::new());

        let status_colored = match report.status.as_str() {
            "secure" => self.success(&report.status),
            "insecure" | "partial" => self.warning(&report.status),
            _ => self.error(&report.status),
        };
        output.push(format!("  {}: {}", self.label("Status"), status_colored));
        let chain_colored = if report.chain_valid {
            self.success("valid")
        } else if report.has_ds_records && report.has_dnskey_records {
            self.error("invalid")
        } else {
            self.warning("n/a")
        };
        output.push(format!(
            "  {}: {}",
            self.label("Chain Valid"),
            chain_colored
        ));
        output.push(self.warning(
            "  Note: reflects DS/DNSKEY digest consistency only — RRSIG signatures, validity \
             periods, and the chain to the root are NOT cryptographically verified.",
        ));
        output.push(format!(
            "  {}: {}",
            self.label("Enabled"),
            self.value(&report.enabled.to_string())
        ));
        output.push(format!(
            "  {}: {}",
            self.label("DS Records"),
            self.value(&report.ds_records.len().to_string())
        ));
        output.push(format!(
            "  {}: {}",
            self.label("DNSKEY Records"),
            self.value(&report.dnskey_records.len().to_string())
        ));

        if !report.ds_records.is_empty() {
            output.push(String::new());
            output.push(format!("  {}:", self.label("DS Records")));
            for ds in &report.ds_records {
                let match_indicator = if ds.matched_key && ds.digest_verified {
                    self.success("\u{2713} verified")
                } else if ds.matched_key {
                    self.error("\u{2717} digest mismatch")
                } else {
                    self.error("\u{2717} no matching key")
                };
                output.push(format!(
                    "    Key Tag: {}, Algorithm: {} ({}), Digest: {} ({}) [{}]",
                    ds.key_tag,
                    ds.algorithm,
                    sanitize_display(&ds.algorithm_name),
                    ds.digest_type,
                    sanitize_display(&ds.digest_type_name),
                    match_indicator,
                ));
            }
        }

        if !report.dnskey_records.is_empty() {
            output.push(String::new());
            output.push(format!("  {}:", self.label("DNSKEY Records")));
            for key in &report.dnskey_records {
                let role = if key.is_ksk {
                    "KSK"
                } else if key.is_zsk {
                    "ZSK"
                } else {
                    "Other"
                };
                output.push(format!(
                    "    Key Tag: {}, Flags: {}, Role: {}, Algorithm: {} ({})",
                    key.key_tag,
                    key.flags,
                    role,
                    key.algorithm,
                    sanitize_display(&key.algorithm_name)
                ));
            }
        }

        if !report.issues.is_empty() {
            output.push(String::new());
            output.push(format!("  {}:", self.label("Issues")));
            for issue in &report.issues {
                output.push(format!("    - {}", sanitize_display(issue)));
            }
        }

        output.join("\n")
    }

    pub(super) fn format_dns_comparison(&self, comparison: &crate::dns::DnsComparison) -> String {
        let mut output = Vec::new();

        output.push(self.header(&format!(
            "DNS Comparison: {} {}",
            comparison.domain, comparison.record_type
        )));

        // Match status
        if comparison.matches {
            output.push(format!("  {} Records match", self.success("✓")));
        } else {
            output.push(format!("  {} Records differ", self.error("✗")));
        }
        output.push(String::new());

        // Server A
        if let Some(ref err) = comparison.server_a.error {
            output.push(format!(
                "  {} ({}): {}",
                self.label("Server A"),
                self.value(&sanitize_display(&comparison.server_a.nameserver)),
                self.error(&sanitize_display(err))
            ));
        } else {
            output.push(format!(
                "  {} ({}): {} records",
                self.label("Server A"),
                self.value(&sanitize_display(&comparison.server_a.nameserver)),
                self.value(&comparison.server_a.records.len().to_string())
            ));
            for record in &comparison.server_a.records {
                output.push(format!(
                    "    - {}",
                    self.value(&sanitize_display(&record.format_short()))
                ));
            }
        }
        output.push(String::new());

        // Server B
        if let Some(ref err) = comparison.server_b.error {
            output.push(format!(
                "  {} ({}): {}",
                self.label("Server B"),
                self.value(&sanitize_display(&comparison.server_b.nameserver)),
                self.error(&sanitize_display(err))
            ));
        } else {
            output.push(format!(
                "  {} ({}): {} records",
                self.label("Server B"),
                self.value(&sanitize_display(&comparison.server_b.nameserver)),
                self.value(&comparison.server_b.records.len().to_string())
            ));
            for record in &comparison.server_b.records {
                output.push(format!(
                    "    - {}",
                    self.value(&sanitize_display(&record.format_short()))
                ));
            }
        }
        output.push(String::new());

        // Common records
        output.push(format!(
            "  {}: {}",
            self.label("Common"),
            if comparison.common.is_empty() {
                self.warning("(none)")
            } else {
                self.value(&sanitize_display(&comparison.common.join(", ")))
            }
        ));

        // Only in A
        output.push(format!(
            "  {}: {}",
            self.label(&format!(
                "Only in {}",
                sanitize_display(&comparison.server_a.nameserver)
            )),
            if comparison.only_in_a.is_empty() {
                self.warning("(none)")
            } else {
                self.error(&sanitize_display(&comparison.only_in_a.join(", ")))
            }
        ));

        // Only in B
        output.push(format!(
            "  {}: {}",
            self.label(&format!(
                "Only in {}",
                sanitize_display(&comparison.server_b.nameserver)
            )),
            if comparison.only_in_b.is_empty() {
                self.warning("(none)")
            } else {
                self.error(&sanitize_display(&comparison.only_in_b.join(", ")))
            }
        ));

        output.join("\n")
    }
}
