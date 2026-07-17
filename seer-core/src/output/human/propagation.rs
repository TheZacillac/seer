use super::*;

impl HumanFormatter {
    pub(super) fn format_propagation(&self, result: &PropagationResult) -> String {
        let mut output = Vec::new();

        output.push(self.header(&format!(
            "Propagation Check: {} {}",
            result.domain, result.record_type
        )));

        // Summary
        let percentage = result.propagation_percentage;
        let percentage_str = format!("{:.1}%", percentage);
        let status = if percentage >= 100.0 {
            self.success(&format!("✓ Fully propagated ({})", percentage_str))
        } else if percentage >= 80.0 {
            self.warning(&format!("◐ Mostly propagated ({})", percentage_str))
        } else if percentage >= 50.0 {
            self.warning(&format!("◑ Partially propagated ({})", percentage_str))
        } else {
            self.error(&format!("✗ Not propagated ({})", percentage_str))
        };
        output.push(format!("  {}", status));

        output.push(format!(
            "  {}: {}/{}",
            self.label("Servers responding"),
            result.servers_responding,
            result.servers_checked
        ));

        // Consensus values, grouped by record type. When only one type is
        // present (the common case — `check()` queries a single type), the
        // per-type subheader is elided for compactness; multi-type results
        // get a labeled block per type. Same rule applies to the two
        // inconsistency blocks below.
        if !result.consensus_values.is_empty() {
            output.push(format!("  {}:", self.label("Consensus values")));
            render_grouped(
                &mut output,
                &result.consensus_values,
                |v| v.record_type.to_string(),
                |out, hdr| out.push(format!("    {}:", self.label(hdr))),
                |out, v, nested| {
                    let indent = if nested { "      " } else { "    " };
                    out.push(format!(
                        "{}- {}",
                        indent,
                        self.success(&sanitize_display(&v.value))
                    ));
                },
            );
        }

        if !result.inconsistencies.is_empty() {
            output.push(format!("  {}:", self.label("Inconsistencies")));
            render_grouped(
                &mut output,
                &result.inconsistencies,
                |inc| inc.record_type.to_string(),
                |out, hdr| out.push(format!("    {}:", self.label(hdr))),
                |out, inc, nested| {
                    let indent = if nested { "      " } else { "    " };
                    out.push(format!(
                        "{}- {}",
                        indent,
                        self.warning(&sanitize_display(&inc.to_string()))
                    ));
                },
            );
        }

        // Per-vantage nameserver-IP disagreements: the primary signal for
        // glue-record propagation lag (a regional resolver still serving the
        // old IP for a nameserver hostname). Grouped by NS hostname rather
        // than record type. Only present for NS-record lookups.
        let ns_details = result.nameserver_details.as_ref();
        if let Some(details) = ns_details.filter(|d| !d.inconsistencies.is_empty()) {
            output.push(format!(
                "  {}:",
                self.label("Nameserver IP inconsistencies")
            ));
            render_grouped(
                &mut output,
                &details.inconsistencies,
                |inc| inc.nameserver.clone(),
                |out, hdr| out.push(format!("    {}:", self.label(hdr))),
                |out, inc, nested| {
                    let indent = if nested { "      " } else { "    " };
                    out.push(format!(
                        "{}- {}",
                        indent,
                        self.warning(&sanitize_display(&inc.to_string()))
                    ));
                },
            );
        }

        // Unreachable servers (timeouts, network errors) — distinct from
        // answer conflicts. Reporting these separately prevents a single
        // timeout from being misread as divergent DNS state.
        if !result.unreachable_servers.is_empty() {
            output.push(format!("  {}:", self.label("Unreachable servers")));
            for unreachable in &result.unreachable_servers {
                let error_msg = unreachable.error.as_deref().unwrap_or("no response");
                output.push(format!(
                    "    - {} ({}): {}",
                    self.warning(&sanitize_display(&unreachable.name)),
                    sanitize_display(&unreachable.ip),
                    sanitize_display(error_msg),
                ));
            }
        }

        // Group results by region
        let mut by_region: std::collections::HashMap<&str, Vec<_>> =
            std::collections::HashMap::new();
        for server_result in &result.results {
            by_region
                .entry(server_result.server.location.as_str())
                .or_default()
                .push(server_result);
        }

        // Sort regions for consistent output
        let mut regions: Vec<_> = by_region.keys().cloned().collect();
        regions.sort();

        output.push(format!("\n  {}:", self.label("Results by Region")));
        for region in &regions {
            output.push(format!("\n    {}:", self.label(region)));
            if let Some(server_results) = by_region.get(region) {
                for server_result in server_results {
                    let status_icon = if server_result.success { "✓" } else { "✗" };
                    let status_colored = if server_result.success {
                        self.success(status_icon)
                    } else {
                        self.error(status_icon)
                    };

                    let values = if server_result.success {
                        if server_result.records.is_empty() {
                            "NXDOMAIN".to_string()
                        } else {
                            server_result
                                .records
                                .iter()
                                .map(|r| {
                                    let short = r.format_short();
                                    let display = sanitize_display(&short);
                                    // Prefer the per-vantage view: the IPs
                                    // *this* resolver returned for the NS
                                    // hostname. Fall back to the cross-server
                                    // consensus only when the per-vantage
                                    // lookup wasn't issued or yielded nothing.
                                    let key = short.to_ascii_lowercase();
                                    let ips = ns_details.and_then(|d| {
                                        d.per_vantage
                                            .get(&server_result.server.ip)
                                            .and_then(|m| m.get(&key))
                                            .filter(|v| !v.is_empty())
                                            .or_else(|| {
                                                d.consensus.get(&key).filter(|v| !v.is_empty())
                                            })
                                    });
                                    match ips {
                                        Some(ips) => format!("{} ({})", display, ips.join(", ")),
                                        None => display,
                                    }
                                })
                                .collect::<Vec<_>>()
                                .join(", ")
                        }
                    } else {
                        sanitize_display(server_result.error.as_deref().unwrap_or("Error"))
                    };

                    output.push(format!(
                        "      {} {} ({}) - {} [{}ms]",
                        status_colored,
                        self.value(&server_result.server.name),
                        server_result.server.ip,
                        values,
                        server_result.response_time_ms
                    ));
                }
            }
        }

        // DNSSEC disclosure (M12). The resolver does not perform DNSSEC
        // validation and UDP DNS is trivially spoofable — surface this so
        // users don't treat the results as authenticated.
        if !result.dnssec_validated {
            output.push(String::new());
            output.push(self.warning("Note: DNS responses are not DNSSEC-validated"));
        }

        output.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::PropagationResult;

    fn formatter() -> HumanFormatter {
        HumanFormatter::new().without_colors()
    }

    /// Inconsistency fixture row: (type, server name, server ip, values, consensus).
    type InconsistencyRow<'a> = (
        crate::dns::RecordType,
        &'a str,
        &'a str,
        Vec<&'a str>,
        Vec<&'a str>,
    );

    fn propagation_fixture(
        consensus: Vec<(crate::dns::RecordType, &str)>,
        inconsistencies: Vec<InconsistencyRow<'_>>,
    ) -> PropagationResult {
        PropagationResult {
            domain: "example.com".to_string(),
            record_type: consensus
                .first()
                .map(|(t, _)| *t)
                .unwrap_or(crate::dns::RecordType::A),
            servers_checked: 5,
            servers_responding: 5,
            propagation_percentage: 100.0,
            results: vec![],
            consensus_values: consensus
                .into_iter()
                .map(|(t, v)| crate::dns::ConsensusValue::new(t, v))
                .collect(),
            inconsistencies: inconsistencies
                .into_iter()
                .map(|(t, name, ip, values, cons)| crate::dns::Inconsistency {
                    record_type: t,
                    server_name: name.to_string(),
                    server_ip: ip.to_string(),
                    values: values.into_iter().map(String::from).collect(),
                    consensus: cons.into_iter().map(String::from).collect(),
                })
                .collect(),
            unreachable_servers: vec![],
            dnssec_validated: false,
            nameserver_details: None,
        }
    }

    #[test]
    fn propagation_single_type_skips_per_type_subheader() {
        let f = formatter();
        let result = propagation_fixture(
            vec![
                (crate::dns::RecordType::A, "1.2.3.4"),
                (crate::dns::RecordType::A, "5.6.7.8"),
            ],
            vec![],
        );
        let out = f.format_propagation(&result);

        assert!(out.contains("Consensus values:"), "got: {}", out);
        // Single-type: values appear directly under the section header
        // without an extra "A:" sub-label.
        assert!(out.contains("    - 1.2.3.4"), "got: {}", out);
        assert!(out.contains("    - 5.6.7.8"), "got: {}", out);
        // No per-type subheader for the only type present.
        assert!(
            !out.contains("    A:"),
            "single-type output should not emit a type subheader, got: {}",
            out
        );
    }

    #[test]
    fn propagation_multi_type_groups_with_subheaders() {
        let f = formatter();
        let result = propagation_fixture(
            vec![
                (crate::dns::RecordType::A, "1.2.3.4"),
                (crate::dns::RecordType::AAAA, "2001:db8::1"),
            ],
            vec![],
        );
        let out = f.format_propagation(&result);

        // Multi-type: each type gets its own subheader and items indent deeper.
        assert!(out.contains("    A:"), "missing A subheader, got: {}", out);
        assert!(
            out.contains("    AAAA:"),
            "missing AAAA subheader, got: {}",
            out
        );
        assert!(out.contains("      - 1.2.3.4"), "got: {}", out);
        assert!(out.contains("      - 2001:db8::1"), "got: {}", out);
    }

    #[test]
    fn propagation_inconsistencies_render_with_record_type() {
        let f = formatter();
        let result = propagation_fixture(
            vec![(crate::dns::RecordType::A, "1.2.3.4")],
            vec![(
                crate::dns::RecordType::A,
                "Quad9",
                "9.9.9.9",
                vec!["5.6.7.8"],
                vec!["1.2.3.4"],
            )],
        );
        let out = f.format_propagation(&result);

        // The Display impl on Inconsistency tags the record type inline so a
        // consumer reading a flat log line still sees what kind of record
        // diverged.
        assert!(
            out.contains("Quad9 (9.9.9.9) [A]: 5.6.7.8 vs consensus: 1.2.3.4"),
            "expected typed inconsistency line, got: {}",
            out
        );
    }
}
