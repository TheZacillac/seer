use std::collections::HashMap;

use super::types::{
    ConsensusValue, Inconsistency, NameserverIpInconsistency, ServerResult, UnreachableServer,
};
use crate::dns::records::RecordType;

/// Outcome of analyzing a set of per-server responses for a single record type.
///
/// Replaces what used to be a 4-tuple return; names the fields so the call
/// site reads clearly and so future fields (DNSSEC validation status,
/// partial-consensus details, etc.) can be added without a signature churn.
pub(super) struct AnalysisOutcome {
    pub propagation_percentage: f64,
    pub consensus_values: Vec<ConsensusValue>,
    pub inconsistencies: Vec<Inconsistency>,
    pub unreachable_servers: Vec<UnreachableServer>,
}

/// Compute the cross-server consensus IP set for each nameserver hostname.
///
/// For each hostname, picks the value set (sorted+deduped IPs) that the largest
/// number of *successfully-responding* propagation servers agree on. Ties are
/// broken by `HashMap` iteration order — fine in practice because ties only
/// occur during active flux, which is exactly when the propagation report is
/// meant to be ambiguous. Servers without an entry for a hostname (e.g. the
/// per-vantage A/AAAA lookup wasn't issued) are skipped, not counted as empty.
pub(super) fn build_nameserver_consensus(
    results: &[ServerResult],
    nameservers: &[String],
) -> HashMap<String, Vec<String>> {
    let mut consensus = HashMap::new();
    for ns in nameservers {
        let mut counts: HashMap<&Vec<String>, usize> = HashMap::new();
        for sr in results.iter().filter(|sr| sr.success) {
            if let Some(ips) = sr.nameserver_ips.get(ns) {
                *counts.entry(ips).or_insert(0) += 1;
            }
        }
        if let Some((winner, _)) = counts.into_iter().max_by_key(|(_, c)| *c) {
            consensus.insert(ns.clone(), winner.clone());
        }
    }
    consensus
}

/// Build per-vantage inconsistencies: any successful server whose IP set for a
/// nameserver disagrees with the consensus for that nameserver. Servers
/// without an observed IP set for a given hostname are skipped (no data ≠ a
/// disagreement). When the consensus itself is empty for a nameserver, no
/// inconsistencies are emitted for that hostname — we only have a "wrong"
/// answer if there's a "right" one to compare against.
pub(super) fn build_nameserver_inconsistencies(
    results: &[ServerResult],
    consensus: &HashMap<String, Vec<String>>,
) -> Vec<NameserverIpInconsistency> {
    let mut out = Vec::new();
    for sr in results.iter().filter(|sr| sr.success) {
        for (ns, ips) in &sr.nameserver_ips {
            let Some(expected) = consensus.get(ns) else {
                continue;
            };
            if expected.is_empty() {
                continue;
            }
            if ips != expected {
                out.push(NameserverIpInconsistency {
                    server_name: sr.server.name.clone(),
                    server_ip: sr.server.ip.clone(),
                    nameserver: ns.clone(),
                    values: ips.clone(),
                    consensus: expected.clone(),
                });
            }
        }
    }
    // Stable ordering for deterministic test output and human-readable diffs.
    out.sort_by(|a, b| (&a.nameserver, &a.server_name).cmp(&(&b.nameserver, &b.server_name)));
    out
}

pub(super) fn analyze_results(
    results: &[ServerResult],
    record_type: RecordType,
) -> AnalysisOutcome {
    // Collect unreachable servers up front so they are reported regardless of
    // whether any server succeeded.
    let unreachable_servers: Vec<UnreachableServer> = results
        .iter()
        .filter(|r| !r.success)
        .map(|r| UnreachableServer {
            name: r.server.name.clone(),
            ip: r.server.ip.clone(),
            error: r.error.clone(),
        })
        .collect();

    let successful: Vec<_> = results.iter().filter(|r| r.success).collect();

    if successful.is_empty() {
        // No genuine answer conflicts — every server is in `unreachable_servers`.
        // Callers detect "no data" via `servers_responding == 0`, not via
        // a synthetic inconsistency.
        return AnalysisOutcome {
            propagation_percentage: 0.0,
            consensus_values: vec![],
            inconsistencies: vec![],
            unreachable_servers,
        };
    }

    // Build sorted value sets once per server result
    let sorted_value_sets: Vec<Vec<String>> = successful
        .iter()
        .map(|result| {
            let mut values: Vec<String> = result.records.iter().map(|r| r.format_short()).collect();
            values.sort();
            values
        })
        .collect();

    // Count occurrences of each value set
    let mut value_counts: HashMap<&Vec<String>, usize> = HashMap::new();
    for values in &sorted_value_sets {
        *value_counts.entry(values).or_insert(0) += 1;
    }

    // Find the most common value set (consensus)
    let Some((consensus_values, consensus_count)) =
        value_counts.into_iter().max_by_key(|(_, count)| *count)
    else {
        // Should never happen since `successful` is non-empty (every successful
        // result contributes a value set), but handle gracefully.
        return AnalysisOutcome {
            propagation_percentage: 0.0,
            consensus_values: vec![],
            inconsistencies: vec![],
            unreachable_servers,
        };
    };

    // Calculate propagation percentage based on ALL servers checked (not just
    // responding ones) so unreachable servers count as non-propagated.
    let propagation_percentage = (consensus_count as f64 / results.len() as f64) * 100.0;

    // Find inconsistencies (reuse pre-computed sorted value sets).
    // Note: failed/unreachable servers are NOT merged in here — they are
    // reported separately via `unreachable_servers` so that
    // `has_inconsistencies()` reflects only genuine answer conflicts.
    let mut inconsistencies: Vec<Inconsistency> = Vec::new();
    for (result, values) in successful.iter().zip(sorted_value_sets.iter()) {
        if values != consensus_values {
            inconsistencies.push(Inconsistency {
                record_type,
                server_name: result.server.name.clone(),
                server_ip: result.server.ip.clone(),
                values: values.clone(),
                consensus: consensus_values.clone(),
            });
        }
    }

    // Tag each consensus value with the queried record type so downstream
    // consumers don't have to cross-reference `PropagationResult.record_type`.
    let tagged_consensus: Vec<ConsensusValue> = consensus_values
        .iter()
        .map(|v| ConsensusValue::new(record_type, v.clone()))
        .collect();

    AnalysisOutcome {
        propagation_percentage,
        consensus_values: tagged_consensus,
        inconsistencies,
        unreachable_servers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::propagation::types::DnsServer;
    use crate::dns::{DnsRecord, RecordData};

    #[test]
    fn analyze_results_routes_failed_servers_to_unreachable() {
        let ok_server = DnsServer::new("OK", "1.1.1.1", "NA", "OK");
        let bad_server = DnsServer::new("Bad", "203.0.113.1", "NA", "Bad");

        let results = vec![
            ServerResult {
                server: ok_server.clone(),
                records: vec![DnsRecord {
                    name: "example.com".to_string(),
                    record_type: RecordType::A,
                    ttl: 300,
                    data: RecordData::A {
                        address: "1.2.3.4".to_string(),
                    },
                }],
                response_time_ms: 10,
                success: true,
                error: None,
                nameserver_ips: HashMap::new(),
            },
            ServerResult {
                server: bad_server.clone(),
                records: vec![],
                response_time_ms: 5000,
                success: false,
                error: Some("timed out".to_string()),
                nameserver_ips: HashMap::new(),
            },
        ];

        let outcome = analyze_results(&results, RecordType::A);

        assert!(
            outcome.inconsistencies.is_empty(),
            "timeout must not produce an inconsistency, got: {:?}",
            outcome.inconsistencies
        );
        assert_eq!(outcome.unreachable_servers.len(), 1);
        assert_eq!(outcome.unreachable_servers[0].name, "Bad");
        assert_eq!(
            outcome.unreachable_servers[0].error.as_deref(),
            Some("timed out")
        );
    }

    #[test]
    fn test_analyze_empty_results() {
        // No servers at all → no consensus, no inconsistencies (a missing
        // answer is reported via unreachable_servers / servers_responding,
        // not as a fake "no servers responded" inconsistency).
        let results: Vec<ServerResult> = vec![];
        let outcome = analyze_results(&results, RecordType::A);
        assert_eq!(outcome.propagation_percentage, 0.0);
        assert!(outcome.consensus_values.is_empty());
        assert!(outcome.inconsistencies.is_empty());
        assert!(outcome.unreachable_servers.is_empty());
    }

    #[test]
    fn test_analyze_consistent_results() {
        let server = DnsServer::new("Test", "1.1.1.1", "Test", "Test");
        let results = vec![
            ServerResult {
                server: server.clone(),
                records: vec![DnsRecord {
                    name: "example.com".to_string(),
                    record_type: RecordType::A,
                    ttl: 300,
                    data: RecordData::A {
                        address: "1.2.3.4".to_string(),
                    },
                }],
                response_time_ms: 10,
                success: true,
                error: None,
                nameserver_ips: HashMap::new(),
            },
            ServerResult {
                server: server.clone(),
                records: vec![DnsRecord {
                    name: "example.com".to_string(),
                    record_type: RecordType::A,
                    ttl: 300,
                    data: RecordData::A {
                        address: "1.2.3.4".to_string(),
                    },
                }],
                response_time_ms: 15,
                success: true,
                error: None,
                nameserver_ips: HashMap::new(),
            },
        ];
        let outcome = analyze_results(&results, RecordType::A);
        assert_eq!(outcome.propagation_percentage, 100.0);
        assert_eq!(
            outcome.consensus_values,
            vec![ConsensusValue::new(RecordType::A, "1.2.3.4")]
        );
        assert!(outcome.inconsistencies.is_empty());
        assert!(outcome.unreachable_servers.is_empty());
    }

    fn ns_server_result(name: &str, ip: &str, ns_ips: &[(&str, &[&str])]) -> ServerResult {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        for (ns, ips) in ns_ips {
            let mut v: Vec<String> = ips.iter().map(|s| s.to_string()).collect();
            v.sort();
            map.insert(ns.to_string(), v);
        }
        ServerResult {
            server: DnsServer::new(name, ip, "NA", "Test"),
            records: vec![],
            response_time_ms: 10,
            success: true,
            error: None,
            nameserver_ips: map,
        }
    }

    #[test]
    fn nameserver_consensus_picks_majority_ip_set() {
        // Two resolvers see 1.2.3.4 for ns1, one stale resolver sees 9.9.9.9.
        let results = vec![
            ns_server_result("A", "1.1.1.1", &[("ns1.example.com.", &["1.2.3.4"])]),
            ns_server_result("B", "8.8.8.8", &[("ns1.example.com.", &["1.2.3.4"])]),
            ns_server_result("C", "9.9.9.9", &[("ns1.example.com.", &["9.9.9.9"])]),
        ];
        let consensus = build_nameserver_consensus(&results, &["ns1.example.com.".to_string()]);
        assert_eq!(
            consensus.get("ns1.example.com.").cloned(),
            Some(vec!["1.2.3.4".to_string()])
        );
    }

    #[test]
    fn nameserver_inconsistencies_flag_stale_vantage() {
        // The third resolver still serves the old glue IP — it must surface
        // as an inconsistency, not silently fold into the consensus.
        let results = vec![
            ns_server_result("A", "1.1.1.1", &[("ns1.example.com.", &["1.2.3.4"])]),
            ns_server_result("B", "8.8.8.8", &[("ns1.example.com.", &["1.2.3.4"])]),
            ns_server_result("Stale", "9.9.9.9", &[("ns1.example.com.", &["9.9.9.9"])]),
        ];
        let consensus = build_nameserver_consensus(&results, &["ns1.example.com.".to_string()]);
        let inconsistencies = build_nameserver_inconsistencies(&results, &consensus);
        assert_eq!(inconsistencies.len(), 1);
        let inc = &inconsistencies[0];
        assert_eq!(inc.server_name, "Stale");
        assert_eq!(inc.nameserver, "ns1.example.com.");
        assert_eq!(inc.values, vec!["9.9.9.9".to_string()]);
        assert_eq!(inc.consensus, vec!["1.2.3.4".to_string()]);
    }

    #[test]
    fn nameserver_inconsistencies_skip_servers_without_data() {
        // Server C never got a chance to answer the A/AAAA followup (no entry
        // in nameserver_ips) — must NOT be treated as "saw nothing" / a
        // disagreement. Missing data ≠ wrong data.
        let mut c = ns_server_result("C", "9.9.9.9", &[]);
        c.nameserver_ips.clear();
        let results = vec![
            ns_server_result("A", "1.1.1.1", &[("ns1.example.com.", &["1.2.3.4"])]),
            ns_server_result("B", "8.8.8.8", &[("ns1.example.com.", &["1.2.3.4"])]),
            c,
        ];
        let consensus = build_nameserver_consensus(&results, &["ns1.example.com.".to_string()]);
        let inconsistencies = build_nameserver_inconsistencies(&results, &consensus);
        assert!(inconsistencies.is_empty(), "got: {:?}", inconsistencies);
    }

    #[test]
    fn nameserver_inconsistencies_ignore_unsuccessful_servers() {
        // Failed propagation servers must not contribute to consensus or
        // inconsistency — they're missing data points, not divergent answers.
        let mut failed = ns_server_result("Down", "203.0.113.1", &[]);
        failed.success = false;
        failed.error = Some("timed out".to_string());
        let results = vec![
            ns_server_result("A", "1.1.1.1", &[("ns1.example.com.", &["1.2.3.4"])]),
            failed,
        ];
        let consensus = build_nameserver_consensus(&results, &["ns1.example.com.".to_string()]);
        assert_eq!(
            consensus.get("ns1.example.com.").cloned(),
            Some(vec!["1.2.3.4".to_string()])
        );
        let inconsistencies = build_nameserver_inconsistencies(&results, &consensus);
        assert!(inconsistencies.is_empty());
    }

    #[test]
    fn nameserver_inconsistencies_skip_empty_consensus() {
        // If nobody could resolve a nameserver, consensus is absent / empty —
        // we have no "right" answer to compare against, so no inconsistency.
        let results = vec![
            ns_server_result("A", "1.1.1.1", &[("ns1.example.com.", &[])]),
            ns_server_result("B", "8.8.8.8", &[("ns1.example.com.", &[])]),
        ];
        let consensus = build_nameserver_consensus(&results, &["ns1.example.com.".to_string()]);
        let inconsistencies = build_nameserver_inconsistencies(&results, &consensus);
        assert!(inconsistencies.is_empty(), "got: {:?}", inconsistencies);
    }
}
