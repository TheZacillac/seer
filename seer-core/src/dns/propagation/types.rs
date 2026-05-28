use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::dns::records::{DnsRecord, RecordType};

/// A DNS server used for propagation checking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsServer {
    pub name: String,
    pub ip: String,
    pub location: String,
    pub provider: String,
}

impl DnsServer {
    pub fn new(name: &str, ip: &str, location: &str, provider: &str) -> Self {
        Self {
            name: name.to_string(),
            ip: ip.to_string(),
            location: location.to_string(),
            provider: provider.to_string(),
        }
    }
}

/// Result from querying a single DNS server during propagation check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerResult {
    pub server: DnsServer,
    pub records: Vec<DnsRecord>,
    pub response_time_ms: u64,
    pub success: bool,
    pub error: Option<String>,
    /// For NS-record propagation checks: A/AAAA addresses **this resolver**
    /// returns when asked for each nameserver hostname it observed. Captures
    /// the per-vantage view so glue-record propagation lag (one regional
    /// recursor still serving the old IP) is visible. Keys are lowercased
    /// FQDNs; values are sorted+deduped. Empty for non-NS checks or when
    /// the follow-up A/AAAA lookups failed.
    #[serde(default)]
    pub nameserver_ips: HashMap<String, Vec<String>>,
}

/// A consensus DNS value tagged with the record type it was observed for.
///
/// Carries the record type alongside the value so downstream consumers
/// (formatters, API clients) do not have to cross-reference the parent
/// `PropagationResult.record_type` to know what kind of record a given
/// consensus entry represents.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConsensusValue {
    #[serde(rename = "type")]
    pub record_type: RecordType,
    pub value: String,
}

impl ConsensusValue {
    pub fn new(record_type: RecordType, value: impl Into<String>) -> Self {
        Self {
            record_type,
            value: value.into(),
        }
    }
}

impl std::fmt::Display for ConsensusValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.record_type, self.value)
    }
}

/// Record of a server that failed to respond during a propagation check.
///
/// Distinct from `inconsistencies` — unreachable servers returned no answer at
/// all (timeout, network error, refused), whereas inconsistencies represent
/// servers that successfully responded with an answer that differs from the
/// consensus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnreachableServer {
    pub name: String,
    pub ip: String,
    pub error: Option<String>,
}

/// A server that responded successfully but with an answer that differs from
/// the consensus. Carries the queried record type and the raw value sets on
/// both sides so consumers can render or compare them without parsing strings.
///
/// Empty `values` / `consensus` represent NXDOMAIN (no records).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inconsistency {
    #[serde(rename = "type")]
    pub record_type: RecordType,
    pub server_name: String,
    pub server_ip: String,
    pub values: Vec<String>,
    pub consensus: Vec<String>,
}

/// Per-vantage disagreement on a nameserver's A/AAAA addresses observed
/// during an NS-record propagation check.
///
/// Produced when a propagation resolver, asked directly for the A/AAAA of an
/// NS hostname returned in the NS answer, gives a value set that differs from
/// the cross-server consensus. This is the primary signal for glue-record
/// propagation lag: a regional recursor still serving the previous IP for
/// `ns1.example.com` shows up here even when every server agrees on the NS
/// names themselves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameserverIpInconsistency {
    pub server_name: String,
    pub server_ip: String,
    pub nameserver: String,
    pub values: Vec<String>,
    pub consensus: Vec<String>,
}

/// Render a value set for human-readable Display output, substituting
/// `empty_label` when the set is empty (NXDOMAIN/NODATA semantics).
fn render_value_set(values: &[String], empty_label: &str) -> String {
    if values.is_empty() {
        empty_label.to_string()
    } else {
        values.join(", ")
    }
}

impl std::fmt::Display for NameserverIpInconsistency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({}) for {}: {} vs consensus: {}",
            self.server_name,
            self.server_ip,
            self.nameserver,
            render_value_set(&self.values, "no records"),
            render_value_set(&self.consensus, "no records"),
        )
    }
}

impl std::fmt::Display for Inconsistency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({}) [{}]: {} vs consensus: {}",
            self.server_name,
            self.server_ip,
            self.record_type,
            render_value_set(&self.values, "NXDOMAIN"),
            render_value_set(&self.consensus, "NXDOMAIN"),
        )
    }
}

fn default_dnssec_validated() -> bool {
    false
}

/// Aggregated result of DNS propagation check across multiple global servers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationResult {
    pub domain: String,
    pub record_type: RecordType,
    pub servers_checked: usize,
    pub servers_responding: usize,
    pub propagation_percentage: f64,
    pub results: Vec<ServerResult>,
    pub consensus_values: Vec<ConsensusValue>,
    /// Servers that responded successfully but with an answer that differs
    /// from the consensus. A non-empty value means the domain has genuinely
    /// divergent answers in flight.
    pub inconsistencies: Vec<Inconsistency>,
    /// Servers that could not be reached (timeouts, network errors, refusals).
    /// These are NOT inconsistencies — they are missing data points.
    #[serde(default)]
    pub unreachable_servers: Vec<UnreachableServer>,
    /// Whether the DNS responses in this result were DNSSEC-validated.
    ///
    /// Currently always `false`: Seer's resolver does not perform DNSSEC
    /// validation, and UDP DNS responses are trivially spoofable. Callers
    /// and formatters should surface this to avoid giving a false sense of
    /// authenticity.
    #[serde(default = "default_dnssec_validated")]
    pub dnssec_validated: bool,
    /// Consensus A/AAAA addresses for nameserver hostnames returned by an
    /// NS-record propagation check, aggregated across all responding
    /// propagation servers (i.e. the value set the largest number of global
    /// recursors agree on). Keys are lowercased FQDNs (typically with trailing
    /// dot). Empty for non-NS checks. For per-vantage views see
    /// `results[i].nameserver_ips`; for resolvers that disagree with the
    /// consensus see `nameserver_inconsistencies`.
    #[serde(default)]
    pub resolved_ips: HashMap<String, Vec<String>>,
    /// Per-vantage A/AAAA mismatches: a propagation resolver returned IPs for
    /// a nameserver hostname that differ from the cross-server consensus.
    /// This is the primary signal for glue-record propagation lag — empty for
    /// non-NS checks.
    #[serde(default)]
    pub nameserver_inconsistencies: Vec<NameserverIpInconsistency>,
}

impl PropagationResult {
    pub fn is_fully_propagated(&self) -> bool {
        self.propagation_percentage >= 100.0
    }

    /// Returns true only when one or more servers returned an answer that
    /// disagrees with the consensus. Servers that timed out or otherwise
    /// failed to respond do NOT flip this to true — they are reported via
    /// `unreachable_servers` / `has_unreachable_servers()` instead.
    pub fn has_inconsistencies(&self) -> bool {
        !self.inconsistencies.is_empty()
    }

    /// Returns true when one or more servers failed to respond.
    pub fn has_unreachable_servers(&self) -> bool {
        !self.unreachable_servers.is_empty()
    }

    /// Returns true when one or more propagation resolvers reported A/AAAA
    /// for a nameserver hostname that differs from the cross-server consensus.
    /// Only meaningful for NS-record checks.
    pub fn has_nameserver_inconsistencies(&self) -> bool {
        !self.nameserver_inconsistencies.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_server_new() {
        let server = DnsServer::new("Test", "1.2.3.4", "Test Region", "Test Provider");
        assert_eq!(server.name, "Test");
        assert_eq!(server.ip, "1.2.3.4");
        assert_eq!(server.location, "Test Region");
        assert_eq!(server.provider, "Test Provider");
    }

    #[test]
    fn test_propagation_result_methods() {
        let result = PropagationResult {
            domain: "example.com".to_string(),
            record_type: RecordType::A,
            servers_checked: 10,
            servers_responding: 10,
            propagation_percentage: 100.0,
            results: vec![],
            consensus_values: vec![ConsensusValue::new(RecordType::A, "1.2.3.4")],
            inconsistencies: vec![],
            unreachable_servers: vec![],
            dnssec_validated: false,
            resolved_ips: HashMap::new(),
            nameserver_inconsistencies: vec![],
        };
        assert!(result.is_fully_propagated());
        assert!(!result.has_inconsistencies());
        assert!(!result.has_unreachable_servers());
    }

    #[test]
    fn test_propagation_result_with_inconsistencies() {
        let result = PropagationResult {
            domain: "example.com".to_string(),
            record_type: RecordType::A,
            servers_checked: 10,
            servers_responding: 8,
            propagation_percentage: 75.0,
            results: vec![],
            consensus_values: vec![ConsensusValue::new(RecordType::A, "1.2.3.4")],
            inconsistencies: vec![Inconsistency {
                record_type: RecordType::A,
                server_name: "Server X".to_string(),
                server_ip: "203.0.113.99".to_string(),
                values: vec!["9.9.9.9".to_string()],
                consensus: vec!["1.2.3.4".to_string()],
            }],
            unreachable_servers: vec![],
            dnssec_validated: false,
            resolved_ips: HashMap::new(),
            nameserver_inconsistencies: vec![],
        };
        assert!(!result.is_fully_propagated());
        assert!(result.has_inconsistencies());
    }

    #[test]
    fn has_inconsistencies_is_false_when_only_timeouts() {
        // 28 agreeing servers + 1 unreachable server should NOT report an
        // inconsistency — the unreachable server is a missing data point, not
        // a conflicting answer.
        let result = PropagationResult {
            domain: "example.com".to_string(),
            record_type: RecordType::A,
            servers_checked: 29,
            servers_responding: 28,
            propagation_percentage: (28.0 / 29.0) * 100.0,
            results: vec![],
            consensus_values: vec![ConsensusValue::new(RecordType::A, "1.2.3.4")],
            inconsistencies: vec![],
            unreachable_servers: vec![UnreachableServer {
                name: "Flaky DNS".to_string(),
                ip: "203.0.113.1".to_string(),
                error: Some("timed out".to_string()),
            }],
            dnssec_validated: false,
            resolved_ips: HashMap::new(),
            nameserver_inconsistencies: vec![],
        };
        assert!(!result.has_inconsistencies());
        assert!(result.has_unreachable_servers());
    }

    #[test]
    fn has_inconsistencies_is_true_when_answers_differ() {
        let result = PropagationResult {
            domain: "example.com".to_string(),
            record_type: RecordType::A,
            servers_checked: 10,
            servers_responding: 10,
            propagation_percentage: 90.0,
            results: vec![],
            consensus_values: vec![ConsensusValue::new(RecordType::A, "1.2.3.4")],
            inconsistencies: vec![Inconsistency {
                record_type: RecordType::A,
                server_name: "Server Y".to_string(),
                server_ip: "203.0.113.2".to_string(),
                values: vec!["5.6.7.8".to_string()],
                consensus: vec!["1.2.3.4".to_string()],
            }],
            unreachable_servers: vec![],
            dnssec_validated: false,
            resolved_ips: HashMap::new(),
            nameserver_inconsistencies: vec![],
        };
        assert!(result.has_inconsistencies());
        assert!(!result.has_unreachable_servers());
    }

    #[test]
    fn test_propagation_result_serialization() {
        let result = PropagationResult {
            domain: "test.com".to_string(),
            record_type: RecordType::A,
            servers_checked: 5,
            servers_responding: 5,
            propagation_percentage: 100.0,
            results: vec![],
            consensus_values: vec![ConsensusValue::new(RecordType::A, "1.2.3.4")],
            inconsistencies: vec![],
            unreachable_servers: vec![],
            dnssec_validated: false,
            resolved_ips: HashMap::new(),
            nameserver_inconsistencies: vec![],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("test.com"));
        assert!(json.contains("100"));
        assert!(json.contains("unreachable_servers"));
        assert!(json.contains("dnssec_validated"));
    }
}
