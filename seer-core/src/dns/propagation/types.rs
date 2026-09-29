use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::dns::query::DnsStatus;
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
///
/// `success` means the server gave a definitive answer — NOERROR (records,
/// or none: NODATA) or NXDOMAIN. A server that responded with SERVFAIL,
/// REFUSED or another error code, sent only a referral, or did not respond
/// at all is unsuccessful, with the reason in `error`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerResult {
    pub server: DnsServer,
    /// The answers of the queried type (for ANY: every answer).
    pub records: Vec<DnsRecord>,
    pub response_time_ms: u64,
    pub success: bool,
    pub error: Option<String>,
    /// The response code the server sent; `None` when it sent no response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<DnsStatus>,
}

impl ServerResult {
    /// How an empty answer from this server reads: `NXDOMAIN` when the name
    /// does not exist, `NODATA` when it exists without records of the type.
    pub fn empty_answer_label(&self) -> &'static str {
        if self.status == Some(DnsStatus::NxDomain) {
            "NXDOMAIN"
        } else {
            "NODATA"
        }
    }
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

impl Inconsistency {
    /// Consensus values this server did not return.
    pub fn missing_count(&self) -> usize {
        self.consensus
            .iter()
            .filter(|v| !self.values.contains(v))
            .count()
    }

    /// Values this server returned that the consensus lacks, in order.
    pub fn extra_values(&self) -> Vec<&str> {
        self.values
            .iter()
            .filter(|v| !self.consensus.contains(v))
            .map(String::as_str)
            .collect()
    }
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

/// NS-record-specific propagation detail.
///
/// All three fields below are only meaningful for NS-record checks. Grouping
/// them under a single `Option<NameserverDetails>` on `PropagationResult`
/// keeps the generic propagation type free of NS-only data and makes the
/// optionality explicit — non-NS checks serialize the field as absent rather
/// than as three empty collections sitting on the wire.
///
/// Maps use lowercased FQDNs (typically with trailing dot) as nameserver
/// keys; `per_vantage` keys are propagation server IPs (matching
/// `ServerResult.server.ip`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NameserverDetails {
    /// Cross-server consensus: for each nameserver hostname, the A/AAAA value
    /// set that the largest number of *successfully-responding* propagation
    /// resolvers agreed on. Sorted+deduped per entry.
    pub consensus: HashMap<String, Vec<String>>,
    /// Per-vantage view: for each propagation server (keyed by its IP), the
    /// A/AAAA value set that resolver returned when asked for each nameserver
    /// hostname. Missing entries mean the per-vantage A/AAAA lookup wasn't
    /// issued or yielded nothing.
    pub per_vantage: HashMap<String, HashMap<String, Vec<String>>>,
    /// Propagation resolvers whose per-vantage IPs disagree with `consensus`.
    /// The primary signal for glue-record propagation lag — a regional
    /// recursor still serving the previous IP for an NS hostname.
    pub inconsistencies: Vec<NameserverIpInconsistency>,
}

impl NameserverDetails {
    /// True if any propagation resolver returned IPs for a nameserver
    /// hostname that differ from the cross-server consensus.
    pub fn has_inconsistencies(&self) -> bool {
        !self.inconsistencies.is_empty()
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
    /// NS-record-specific propagation detail (consensus, per-vantage view,
    /// inconsistencies). `None` for non-NS lookups and for NS lookups that
    /// observed no NS records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nameserver_details: Option<NameserverDetails>,
}

/// The overall reading of a propagation check, from the share of responding
/// servers that agree with the consensus. Every renderer words the summary
/// through this, so the thresholds live in one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropagationVerdict {
    /// Every responding server agrees.
    Full,
    /// At least 80% agree.
    Mostly,
    /// At least half agree.
    Partial,
    /// No answer is held by a majority.
    Split,
    /// No server answered.
    NoAnswer,
}

impl PropagationVerdict {
    /// Short human label: `Fully propagated`, `No majority answer`, …
    pub fn label(self) -> &'static str {
        match self {
            PropagationVerdict::Full => "Fully propagated",
            PropagationVerdict::Mostly => "Mostly propagated",
            PropagationVerdict::Partial => "Partially propagated",
            PropagationVerdict::Split => "No majority answer",
            PropagationVerdict::NoAnswer => "No server answered",
        }
    }
}

/// How one server's result relates to the consensus — the row
/// classification every renderer shares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerVerdict<'a> {
    /// Answered with the consensus value set.
    Agrees,
    /// Answered with a different value set.
    Differs(&'a Inconsistency),
    /// Gave no definitive answer; the reason.
    NoAnswer(&'a str),
}

impl PropagationResult {
    /// Returns true only when one or more servers returned an answer that
    /// disagrees with the consensus. Servers that timed out or otherwise
    /// failed to respond do NOT flip this to true — they are reported via
    /// `unreachable_servers` instead.
    pub fn has_inconsistencies(&self) -> bool {
        !self.inconsistencies.is_empty()
    }

    /// Responding servers that returned the consensus value set.
    pub fn servers_agreeing(&self) -> usize {
        self.servers_responding
            .saturating_sub(self.inconsistencies.len())
    }

    /// The overall reading, from `propagation_percentage` (the agreeing share
    /// of responding servers).
    pub fn verdict(&self) -> PropagationVerdict {
        let pct = self.propagation_percentage;
        if self.servers_responding == 0 {
            PropagationVerdict::NoAnswer
        } else if pct >= 100.0 {
            PropagationVerdict::Full
        } else if pct >= 80.0 {
            PropagationVerdict::Mostly
        } else if pct >= 50.0 {
            PropagationVerdict::Partial
        } else {
            PropagationVerdict::Split
        }
    }

    /// How many different answers the responding servers gave (the
    /// consensus counted once). Three or more usually means the name answers
    /// by the resolver's location (GeoDNS / CDN), not a propagation delay,
    /// which typically shows two: the old answer and the new.
    pub fn distinct_answers(&self) -> usize {
        if self.servers_responding == 0 {
            return 0;
        }
        let mut sets: Vec<&Vec<String>> = Vec::new();
        for inc in &self.inconsistencies {
            if !sets.contains(&&inc.values) {
                sets.push(&inc.values);
            }
        }
        1 + sets.len()
    }

    /// Whether the answers look location-dependent rather than mid-change:
    /// an address-type query (A, AAAA, CNAME) answered at least three
    /// different ways ([`distinct_answers`](Self::distinct_answers)). GeoDNS
    /// and CDNs hand each resolver the addresses nearest it.
    pub fn looks_location_dependent(&self) -> bool {
        matches!(
            self.record_type,
            RecordType::A | RecordType::AAAA | RecordType::CNAME
        ) && self.distinct_answers() >= 3
    }

    /// Classifies one of this result's `results` against the consensus.
    pub fn server_verdict<'a>(&'a self, result: &'a ServerResult) -> ServerVerdict<'a> {
        if !result.success {
            return ServerVerdict::NoAnswer(result.error.as_deref().unwrap_or("no response"));
        }
        self.inconsistencies
            .iter()
            .find(|inc| inc.server_ip == result.server.ip && inc.server_name == result.server.name)
            .map_or(ServerVerdict::Agrees, ServerVerdict::Differs)
    }

    /// How an empty consensus reads (`NXDOMAIN` or `NODATA`), taken from an
    /// agreeing server; `None` when the consensus has values or nobody
    /// answered.
    pub fn empty_consensus_label(&self) -> Option<&'static str> {
        if !self.consensus_values.is_empty() {
            return None;
        }
        self.results
            .iter()
            .find(|r| self.server_verdict(r) == ServerVerdict::Agrees)
            .map(ServerResult::empty_answer_label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_result(domain: &str, propagation_percentage: f64) -> PropagationResult {
        PropagationResult {
            domain: domain.to_string(),
            record_type: RecordType::A,
            servers_checked: 0,
            servers_responding: 0,
            propagation_percentage,
            results: vec![],
            consensus_values: vec![ConsensusValue::new(RecordType::A, "1.2.3.4")],
            inconsistencies: vec![],
            unreachable_servers: vec![],
            dnssec_validated: false,
            nameserver_details: None,
        }
    }

    #[test]
    fn test_dns_server_new() {
        let server = DnsServer::new("Test", "1.2.3.4", "Test Region", "Test Provider");
        assert_eq!(server.name, "Test");
        assert_eq!(server.ip, "1.2.3.4");
        assert_eq!(server.location, "Test Region");
        assert_eq!(server.provider, "Test Provider");
    }

    #[test]
    fn has_inconsistencies_is_false_when_only_timeouts() {
        // 28 agreeing servers + 1 unreachable server should NOT report an
        // inconsistency — the unreachable server is a missing data point, not
        // a conflicting answer.
        let mut result = empty_result("example.com", (28.0 / 29.0) * 100.0);
        result.servers_checked = 29;
        result.servers_responding = 28;
        result.unreachable_servers = vec![UnreachableServer {
            name: "Flaky DNS".to_string(),
            ip: "203.0.113.1".to_string(),
            error: Some("timed out".to_string()),
        }];
        assert!(!result.has_inconsistencies());
    }

    #[test]
    fn has_inconsistencies_is_true_when_answers_differ() {
        let mut result = empty_result("example.com", 90.0);
        result.servers_checked = 10;
        result.servers_responding = 10;
        result.inconsistencies = vec![Inconsistency {
            record_type: RecordType::A,
            server_name: "Server Y".to_string(),
            server_ip: "203.0.113.2".to_string(),
            values: vec!["5.6.7.8".to_string()],
            consensus: vec!["1.2.3.4".to_string()],
        }];
        assert!(result.has_inconsistencies());
    }

    #[test]
    fn nameserver_details_has_inconsistencies_reflects_field() {
        // NS lookup with no glue-lag → details, no inconsistencies.
        let mut details = NameserverDetails {
            consensus: HashMap::new(),
            per_vantage: HashMap::new(),
            inconsistencies: vec![],
        };
        assert!(!details.has_inconsistencies());

        // NS lookup with glue-lag → at least one inconsistency.
        details.inconsistencies.push(NameserverIpInconsistency {
            server_name: "Stale".to_string(),
            server_ip: "9.9.9.9".to_string(),
            nameserver: "ns1.example.com.".to_string(),
            values: vec!["9.9.9.9".to_string()],
            consensus: vec!["1.2.3.4".to_string()],
        });
        assert!(details.has_inconsistencies());
    }

    #[test]
    fn test_propagation_result_serialization() {
        let mut result = empty_result("test.com", 100.0);
        result.servers_checked = 5;
        result.servers_responding = 5;
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("test.com"));
        assert!(json.contains("100"));
        assert!(json.contains("unreachable_servers"));
        assert!(json.contains("dnssec_validated"));
        // Non-NS lookup: nameserver_details should be omitted from the
        // serialized form rather than emitted as `null`.
        assert!(!json.contains("nameserver_details"));
    }

    #[test]
    fn nameserver_details_serializes_when_present() {
        let mut result = empty_result("test.com", 100.0);
        result.record_type = RecordType::NS;
        result.nameserver_details = Some(NameserverDetails {
            consensus: [("ns1.example.com.".to_string(), vec!["1.2.3.4".to_string()])]
                .into_iter()
                .collect(),
            per_vantage: HashMap::new(),
            inconsistencies: vec![],
        });
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("nameserver_details"));
        assert!(json.contains("consensus"));
        assert!(json.contains("ns1.example.com"));
    }

    fn server(name: &str, ip: &str) -> DnsServer {
        DnsServer::new(name, ip, "Test", "Test")
    }

    fn answered(name: &str, ip: &str, status: DnsStatus) -> ServerResult {
        ServerResult {
            server: server(name, ip),
            records: vec![],
            response_time_ms: 1,
            success: true,
            error: None,
            status: Some(status),
        }
    }

    #[test]
    fn verdict_reads_the_agreeing_share_of_responding_servers() {
        let cases = [
            (0, 0.0, PropagationVerdict::NoAnswer),
            (4, 100.0, PropagationVerdict::Full),
            (5, 80.0, PropagationVerdict::Mostly),
            (4, 50.0, PropagationVerdict::Partial),
            (3, 33.3, PropagationVerdict::Split),
        ];
        for (responding, pct, want) in cases {
            let mut result = empty_result("example.com", pct);
            result.servers_responding = responding;
            assert_eq!(result.verdict(), want, "{responding} responding at {pct}%");
        }
    }

    #[test]
    fn server_verdict_classifies_each_row() {
        let mut result = empty_result("example.com", 50.0);
        let agrees = answered("A", "192.0.2.1", DnsStatus::NoError);
        let differs = answered("B", "192.0.2.2", DnsStatus::NoError);
        let mut silent = answered("C", "192.0.2.3", DnsStatus::NoError);
        silent.success = false;
        silent.status = None;
        silent.error = Some("timed out".into());
        result.inconsistencies = vec![Inconsistency {
            record_type: RecordType::A,
            server_name: "B".into(),
            server_ip: "192.0.2.2".into(),
            values: vec!["5.6.7.8".into()],
            consensus: vec!["1.2.3.4".into()],
        }];
        result.servers_responding = 2;

        assert_eq!(result.server_verdict(&agrees), ServerVerdict::Agrees);
        assert!(matches!(
            result.server_verdict(&differs),
            ServerVerdict::Differs(inc) if inc.values == ["5.6.7.8"]
        ));
        assert_eq!(
            result.server_verdict(&silent),
            ServerVerdict::NoAnswer("timed out")
        );
        assert_eq!(result.servers_agreeing(), 1);
    }

    #[test]
    fn inconsistency_counts_missing_and_extra_values() {
        let inc = Inconsistency {
            record_type: RecordType::TXT,
            server_name: "S".into(),
            server_ip: "192.0.2.1".into(),
            values: vec!["a".into(), "b".into(), "z".into()],
            consensus: vec!["a".into(), "b".into(), "c".into(), "d".into()],
        };
        assert_eq!(inc.missing_count(), 2);
        assert_eq!(inc.extra_values(), ["z"]);
    }

    #[test]
    fn distinct_answers_counts_the_consensus_once() {
        let inc = |ip: &str, value: &str| Inconsistency {
            record_type: RecordType::A,
            server_name: ip.into(),
            server_ip: ip.into(),
            values: vec![value.into()],
            consensus: vec!["1.2.3.4".into()],
        };
        let mut result = empty_result("example.com", 50.0);
        assert_eq!(result.distinct_answers(), 0, "nobody answered");
        result.servers_responding = 4;
        assert_eq!(result.distinct_answers(), 1);
        result.inconsistencies = vec![
            inc("192.0.2.1", "5.6.7.8"),
            inc("192.0.2.2", "5.6.7.8"),
            inc("192.0.2.3", "9.9.9.9"),
        ];
        assert_eq!(result.distinct_answers(), 3);
        assert!(result.looks_location_dependent());
        // A TXT set split three ways is truncation or policy, not GeoDNS.
        result.record_type = RecordType::TXT;
        assert!(!result.looks_location_dependent());
    }

    #[test]
    fn empty_answers_name_nxdomain_or_nodata() {
        assert_eq!(
            answered("A", "192.0.2.1", DnsStatus::NxDomain).empty_answer_label(),
            "NXDOMAIN"
        );
        assert_eq!(
            answered("A", "192.0.2.1", DnsStatus::NoError).empty_answer_label(),
            "NODATA"
        );

        let mut result = empty_result("example.com", 100.0);
        // A consensus with values has no empty label.
        assert_eq!(result.empty_consensus_label(), None);
        result.consensus_values.clear();
        result.results = vec![answered("A", "192.0.2.1", DnsStatus::NxDomain)];
        result.servers_responding = 1;
        assert_eq!(result.empty_consensus_label(), Some("NXDOMAIN"));
    }
}
