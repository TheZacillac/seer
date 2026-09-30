use super::*;
use crate::dns::{PropagationVerdict, ServerVerdict};

/// A consensus that fits in this many characters is shown on one line.
const INLINE_CONSENSUS_WIDTH: usize = 72;

impl HumanFormatter {
    pub(super) fn format_propagation(&self, result: &PropagationResult) -> String {
        let mut output = Vec::new();
        output.push(self.header(&format!(
            "Propagation: {} {}",
            sanitize_line(&result.domain),
            result.record_type
        )));
        output.push(format!("  {}", self.propagation_summary(result)));

        let ns_details = result.nameserver_details.as_ref();
        let mut rows = self.rows(&mut output, "  ");
        if result.servers_responding > 0 {
            if let Some(label) = result.empty_consensus_label() {
                rows.kv("Consensus", self.success(&format!("no records ({label})")));
            } else {
                let multi_type = result
                    .consensus_values
                    .iter()
                    .any(|v| v.record_type != result.record_type);
                // NS consensus names carry the addresses most servers gave them.
                let values: Vec<String> = result
                    .consensus_values
                    .iter()
                    .map(|v| {
                        let mut text = sanitize_line(&v.value);
                        if let Some(ips) = ns_details
                            .and_then(|d| d.consensus.get(&v.value.to_ascii_lowercase()))
                            .filter(|ips| !ips.is_empty())
                        {
                            text = format!("{text} ({})", sanitize_line(&ips.join(", ")));
                        }
                        if multi_type {
                            text = format!("{:<6} {text}", v.record_type.to_string());
                        }
                        text
                    })
                    .collect();
                let inline = values.join(", ");
                if !multi_type && inline.chars().count() <= INLINE_CONSENSUS_WIDTH {
                    rows.kv("Consensus", self.success(&inline));
                } else {
                    rows.push(format!("  {}:", self.label("Consensus")));
                    rows.extend(
                        values
                            .iter()
                            .map(|v| format!("    {}", self.success(v)))
                            .collect(),
                    );
                }
            }
        }
        let silent = result.servers_checked - result.servers_responding;
        if silent > 0 && result.servers_responding > 0 {
            rows.kv(
                "No answer",
                self.warning(&format!(
                    "{silent} of {} servers (reasons below)",
                    result.servers_checked
                )),
            );
        }

        // Per-vantage nameserver-IP disagreements: the primary signal for
        // glue-record propagation lag (a regional resolver still serving the
        // old IP for a nameserver hostname). Only present for NS lookups.
        if let Some(details) = ns_details.filter(|d| !d.inconsistencies.is_empty()) {
            output.push(String::new());
            output.push(format!(
                "  {}:",
                self.label("Nameserver IP inconsistencies")
            ));
            render_grouped(
                &mut output,
                &details.inconsistencies,
                |inc| inc.nameserver.clone(),
                |out, hdr| out.push(format!("    {}:", self.label(&sanitize_line(hdr)))),
                |out, inc, nested| {
                    let indent = if nested { "      " } else { "    " };
                    out.push(format!(
                        "{}- {}",
                        indent,
                        self.warning(&sanitize_line(&inc.to_string()))
                    ));
                },
            );
        }

        self.propagation_table(&mut output, result);

        output.push(String::new());
        output.push(self.dim("✓ matches consensus   ≠ different answer   ✗ no answer"));
        if result.looks_location_dependent() {
            output.push(self.dim(GEO_NOTE));
        }
        // DNSSEC disclosure (M12). The resolver does not perform DNSSEC
        // validation and UDP DNS is trivially spoofable — surface this so
        // users don't treat the results as authenticated.
        if !result.dnssec_validated {
            output.push(self.warning(DNSSEC_NOTE));
        }

        output.join("\n")
    }

    /// The verdict line: `◐ Mostly propagated — 19 of 20 responding servers
    /// agree`.
    fn propagation_summary(&self, result: &PropagationResult) -> String {
        let verdict = result.verdict();
        let detail = propagation_detail(result);
        let headline = match verdict {
            PropagationVerdict::Full => self.success(&format!("✓ {}", verdict.label())),
            PropagationVerdict::Mostly => self.warning(&format!("◐ {}", verdict.label())),
            PropagationVerdict::Partial => self.warning(&format!("◑ {}", verdict.label())),
            PropagationVerdict::Split | PropagationVerdict::NoAnswer => {
                self.error(&format!("✗ {}", verdict.label()))
            }
        };
        format!("{headline} {}", self.dim(&format!("— {detail}")))
    }

    /// One aligned row per server, grouped by region in list order: a mark,
    /// the server, its time, and — only where it says something the summary
    /// does not — the differing answer or the reason there was none.
    fn propagation_table(&self, output: &mut Vec<String>, result: &PropagationResult) {
        let name_width = result
            .results
            .iter()
            .map(|r| sanitize_line(&r.server.name).chars().count())
            .max()
            .unwrap_or(0);
        let ip_width = result
            .results
            .iter()
            .map(|r| sanitize_line(&r.server.ip).chars().count())
            .max()
            .unwrap_or(0);

        let mut regions: Vec<&str> = Vec::new();
        for r in &result.results {
            if !regions.contains(&r.server.location.as_str()) {
                regions.push(&r.server.location);
            }
        }
        for region in regions {
            output.push(String::new());
            output.push(format!("  {}", self.label(&sanitize_line(region))));
            for sr in result
                .results
                .iter()
                .filter(|r| r.server.location == region)
            {
                let name = format!("{:<name_width$}", sanitize_line(&sr.server.name));
                let ip = format!("{:<ip_width$}", sanitize_line(&sr.server.ip));
                let time = format!("{:>7}", format!("{} ms", sr.response_time_ms));
                let line = match result.server_verdict(sr) {
                    ServerVerdict::Agrees => format!(
                        "{} {} {} {}",
                        self.success("✓"),
                        self.value(&name),
                        self.dim(&ip),
                        self.dim(&time)
                    ),
                    ServerVerdict::Differs(inc) => {
                        let answer = propagation_difference(inc, sr.empty_answer_label());
                        format!(
                            "{} {} {} {}  {}",
                            self.warning("≠"),
                            self.value(&name),
                            self.dim(&ip),
                            self.dim(&time),
                            self.warning(&sanitize_line(&answer))
                        )
                    }
                    // A silent server's time is only the timeout: leave it out.
                    ServerVerdict::NoAnswer(reason) => format!(
                        "{} {} {} {:>7}  {}",
                        self.error("✗"),
                        self.value(&name),
                        self.dim(&ip),
                        "",
                        self.dim(&sanitize_line(reason))
                    ),
                };
                output.push(format!("    {}", line.trim_end()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{
        ConsensusValue, DnsRecord, DnsServer, DnsStatus, Inconsistency, PropagationResult,
        PropagationServerResult, RecordData, RecordType,
    };

    fn formatter() -> HumanFormatter {
        HumanFormatter::new().without_colors()
    }

    fn a_record(ip: &str) -> DnsRecord {
        DnsRecord {
            name: "example.com".into(),
            record_type: RecordType::A,
            ttl: 300,
            data: RecordData::A { address: ip.into() },
        }
    }

    fn row(name: &str, ip: &str, region: &str, values: &[&str]) -> PropagationServerResult {
        PropagationServerResult {
            server: DnsServer::new(name, ip, region, name),
            records: values.iter().map(|v| a_record(v)).collect(),
            response_time_ms: 12,
            success: true,
            error: None,
            status: Some(DnsStatus::NoError),
        }
    }

    fn silent(name: &str, ip: &str, region: &str, reason: &str) -> PropagationServerResult {
        PropagationServerResult {
            response_time_ms: 5000,
            success: false,
            error: Some(reason.into()),
            status: None,
            ..row(name, ip, region, &[])
        }
    }

    fn inconsistency(name: &str, ip: &str, values: &[&str], consensus: &[&str]) -> Inconsistency {
        Inconsistency {
            record_type: RecordType::A,
            server_name: name.into(),
            server_ip: ip.into(),
            values: values.iter().map(|v| v.to_string()).collect(),
            consensus: consensus.iter().map(|v| v.to_string()).collect(),
            nxdomain: false,
            consensus_nxdomain: false,
        }
    }

    /// Three servers in two regions: one agrees, one differs, one is silent.
    fn fixture() -> PropagationResult {
        PropagationResult {
            domain: "example.com".into(),
            record_type: RecordType::A,
            servers_checked: 3,
            servers_responding: 2,
            propagation_percentage: 50.0,
            results: vec![
                row("Google", "8.8.8.8", "North America", &["1.2.3.4"]),
                row("Yandex", "77.88.8.8", "Europe", &["5.6.7.8"]),
                silent("Slow DNS", "192.0.2.53", "Europe", "timed out"),
            ],
            consensus_values: vec![ConsensusValue::new(RecordType::A, "1.2.3.4")],
            inconsistencies: vec![inconsistency(
                "Yandex",
                "77.88.8.8",
                &["5.6.7.8"],
                &["1.2.3.4"],
            )],
            unreachable_servers: vec![],
            dnssec_validated: false,
            nameserver_details: None,
        }
    }

    #[test]
    fn summary_counts_only_responding_servers() {
        let out = formatter().format_propagation(&fixture());
        assert!(
            out.contains("  ◑ Partially propagated — 1 of 2 responding servers agree"),
            "got: {out}"
        );
        assert!(out.contains("  Consensus: 1.2.3.4\n"), "got: {out}");
        assert!(
            out.contains("  No answer: 1 of 3 servers (reasons below)"),
            "got: {out}"
        );
    }

    /// Rows are aligned and grouped by region in list order; only the
    /// differing and silent rows say more, and a silent row shows no time.
    #[test]
    fn rows_mark_agreement_and_explain_the_rest() {
        let out = formatter().format_propagation(&fixture());
        let expected = [
            "  North America",
            "    ✓ Google   8.8.8.8      12 ms",
            "",
            "  Europe",
            "    ≠ Yandex   77.88.8.8    12 ms  5.6.7.8",
            "    ✗ Slow DNS 192.0.2.53          timed out",
        ]
        .join("\n");
        assert!(out.contains(&expected), "got:\n{out}");
        assert!(out.find("North America") < out.find("Europe"));
    }

    #[test]
    fn multi_type_consensus_lists_one_value_per_line() {
        let mut result = fixture();
        result.consensus_values = vec![
            ConsensusValue::new(RecordType::A, "1.2.3.4"),
            ConsensusValue::new(RecordType::AAAA, "2001:db8::1"),
        ];
        let out = formatter().format_propagation(&result);
        assert!(
            out.contains("  Consensus:\n    A      1.2.3.4\n    AAAA   2001:db8::1"),
            "got: {out}"
        );
    }

    #[test]
    fn large_differing_sets_show_what_is_missing_and_extra() {
        let consensus = ["a", "b", "c", "d"];
        let inc = inconsistency("S", "192.0.2.1", &["a", "b", "z"], &consensus);
        assert_eq!(
            propagation_difference(&inc, "NODATA"),
            "missing 2 of 4; extra: z"
        );
        // Small sets are shown whole.
        let inc = inconsistency("S", "192.0.2.1", &["z"], &["a"]);
        assert_eq!(propagation_difference(&inc, "NODATA"), "z");
        let inc = inconsistency("S", "192.0.2.1", &[], &["a"]);
        assert_eq!(
            propagation_difference(&inc, "NXDOMAIN"),
            "no records (NXDOMAIN)"
        );
    }

    #[test]
    fn no_answer_at_all_says_so_without_a_consensus() {
        let mut result = fixture();
        result.results = vec![silent("Slow DNS", "192.0.2.53", "Europe", "timed out")];
        result.servers_checked = 1;
        result.servers_responding = 0;
        result.propagation_percentage = 0.0;
        result.consensus_values.clear();
        result.inconsistencies.clear();
        let out = formatter().format_propagation(&result);
        assert!(
            out.contains("✗ No server answered — none of the 1 servers answered"),
            "got: {out}"
        );
        assert!(!out.contains("Consensus"), "got: {out}");
    }
}
