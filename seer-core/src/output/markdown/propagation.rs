use super::*;

impl MarkdownFormatter {
    pub(super) fn format_propagation(&self, result: &PropagationResult) -> String {
        let mut output = Vec::new();

        output.push(format!(
            "## Propagation: {} {}",
            MdSafe(&result.domain),
            result.record_type
        ));
        output.push(String::new());

        // Summary
        let percentage = result.propagation_percentage;
        let status = if percentage >= 100.0 {
            "Fully propagated"
        } else if percentage >= 80.0 {
            "Mostly propagated"
        } else if percentage >= 50.0 {
            "Partially propagated"
        } else {
            "Not propagated"
        };
        output.push(format!("**{:.1}%** - {}", percentage, status));
        output.push(String::new());
        output.push(format!(
            "- **Servers responding**: {}/{}",
            result.servers_responding, result.servers_checked
        ));

        // Consensus values, grouped by record type. Single-type results
        // collapse to one inline line; multi-type results get a header line
        // plus one rendered line per type. Unlike the inconsistency blocks
        // below, the per-group items are joined into a single line — so this
        // block doesn't share the `render_grouped` helper they use.
        if !result.consensus_values.is_empty() {
            let mut grouped: std::collections::BTreeMap<String, Vec<&str>> =
                std::collections::BTreeMap::new();
            for v in &result.consensus_values {
                grouped
                    .entry(v.record_type.to_string())
                    .or_default()
                    .push(v.value.as_str());
            }

            let render_values = |values: &[&str]| -> String {
                values
                    .iter()
                    .map(|v| format!("`{}`", MdSafe(v)))
                    .collect::<Vec<_>>()
                    .join(", ")
            };

            if grouped.len() == 1 {
                let (_, values) = grouped.iter().next().expect("non-empty by check above");
                output.push(format!("- **Consensus values**: {}", render_values(values)));
            } else {
                output.push("- **Consensus values**:".to_string());
                for (record_type, values) in &grouped {
                    output.push(format!(
                        "    - **{}**: {}",
                        MdSafe(record_type),
                        render_values(values)
                    ));
                }
            }
        }

        // Inconsistencies (genuine answer conflicts), grouped by record type.
        if !result.inconsistencies.is_empty() {
            output.push(String::new());
            output.push("### Inconsistencies".to_string());
            output.push(String::new());
            render_grouped(
                &mut output,
                &result.inconsistencies,
                |inc| inc.record_type.to_string(),
                |out, hdr| {
                    out.push(format!("**{}**", MdSafe(hdr)));
                    out.push(String::new());
                },
                |out, inc, _nested| out.push(format!("- {}", MdSafe(&inc.to_string()))),
            );
        }

        // Per-vantage nameserver-IP disagreements (glue-update lag), grouped
        // by NS hostname. Only present for NS-record lookups.
        let ns_details = result.nameserver_details.as_ref();
        if let Some(details) = ns_details.filter(|d| !d.inconsistencies.is_empty()) {
            output.push(String::new());
            output.push("### Nameserver IP inconsistencies".to_string());
            output.push(String::new());
            render_grouped(
                &mut output,
                &details.inconsistencies,
                |inc| inc.nameserver.clone(),
                |out, hdr| {
                    out.push(format!("**{}**", MdSafe(hdr)));
                    out.push(String::new());
                },
                |out, inc, _nested| out.push(format!("- {}", MdSafe(&inc.to_string()))),
            );
        }

        // Unreachable servers (distinct from answer conflicts)
        if !result.unreachable_servers.is_empty() {
            output.push(String::new());
            output.push("### Unreachable servers".to_string());
            output.push(String::new());
            for unreachable in &result.unreachable_servers {
                let error_msg = unreachable.error.as_deref().unwrap_or("no response");
                output.push(format!(
                    "- **{}** (`{}`): {}",
                    MdSafe(&unreachable.name),
                    MdSafe(&unreachable.ip),
                    MdSafe(error_msg)
                ));
            }
        }

        // Results table
        output.push(String::new());
        output.push("### Results".to_string());
        output.push(String::new());
        output.push("| Server | Location | IP | Result | Time |".to_string());
        output.push("| --- | --- | --- | --- | --- |".to_string());

        for sr in &result.results {
            let result_str = if sr.success {
                if sr.records.is_empty() {
                    "NXDOMAIN".to_string()
                } else {
                    sr.records
                        .iter()
                        .map(|r| {
                            let short = r.format_short();
                            let key = short.to_ascii_lowercase();
                            // Per-vantage view first, then cross-server
                            // consensus as a fallback.
                            let ips = ns_details.and_then(|d| {
                                d.per_vantage
                                    .get(&sr.server.ip)
                                    .and_then(|m| m.get(&key))
                                    .filter(|v| !v.is_empty())
                                    .or_else(|| d.consensus.get(&key).filter(|v| !v.is_empty()))
                            });
                            match ips {
                                Some(ips) => format!("{} ({})", short, ips.join(", ")),
                                None => short,
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            } else {
                sr.error.as_deref().unwrap_or("Error").to_string()
            };

            output.push(format!(
                "| {} | {} | `{}` | `{}` | {}ms |",
                MdSafe(&sr.server.name),
                MdSafe(&sr.server.location),
                MdSafe(&sr.server.ip),
                MdSafe(&result_str),
                sr.response_time_ms
            ));
        }

        if !result.dnssec_validated {
            output.push(String::new());
            output.push("> Note: DNS responses are not DNSSEC-validated.".to_string());
        }

        output.join("\n")
    }
}
