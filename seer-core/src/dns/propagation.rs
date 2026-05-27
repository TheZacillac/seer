use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use futures::future::join_all;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use tracing::{debug, instrument, warn};

use super::records::{DnsRecord, RecordData, RecordType};
use super::resolver::DnsResolver;
use crate::error::{Result, SeerError};

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

/// Built-in list of global DNS servers for propagation checking.
/// Constructed once on first access; callers that need ownership call
/// `default_dns_servers().to_vec()`.
static DEFAULT_DNS_SERVERS: Lazy<Vec<DnsServer>> = Lazy::new(|| {
    vec![
        // North America
        DnsServer::new("Google", "8.8.8.8", "North America", "Google"),
        DnsServer::new("Cloudflare", "1.1.1.1", "North America", "Cloudflare"),
        DnsServer::new(
            "OpenDNS",
            "208.67.222.222",
            "North America",
            "Cisco OpenDNS",
        ),
        DnsServer::new("Quad9", "9.9.9.9", "North America", "Quad9"),
        DnsServer::new("Level3", "4.2.2.1", "North America", "Lumen"),
        // Europe
        DnsServer::new("DNS.Watch", "84.200.69.80", "Europe", "DNS.Watch"),
        DnsServer::new("Mullvad", "194.242.2.2", "Europe", "Mullvad"),
        DnsServer::new("dns0.eu", "193.110.81.0", "Europe", "dns0.eu"),
        DnsServer::new("Yandex", "77.88.8.8", "Europe", "Yandex"),
        DnsServer::new("UncensoredDNS", "91.239.100.100", "Europe", "UncensoredDNS"),
        // Asia Pacific
        DnsServer::new("AliDNS", "223.5.5.5", "Asia Pacific", "Alibaba"),
        DnsServer::new("114DNS", "114.114.114.114", "Asia Pacific", "114DNS"),
        DnsServer::new("Tencent DNSPod", "119.29.29.29", "Asia Pacific", "Tencent"),
        DnsServer::new("TWNIC", "101.101.101.101", "Asia Pacific", "TWNIC"),
        DnsServer::new("HiNet", "168.95.1.1", "Asia Pacific", "Chunghwa Telecom"),
        // Latin America
        DnsServer::new("Claro Brasil", "200.248.178.54", "Latin America", "Claro"),
        DnsServer::new(
            "Telefonica Brasil",
            "200.176.2.10",
            "Latin America",
            "Telefonica",
        ),
        DnsServer::new("Antel Uruguay", "200.40.30.245", "Latin America", "Antel"),
        DnsServer::new("Telmex Mexico", "200.33.146.217", "Latin America", "Telmex"),
        DnsServer::new(
            "CenturyLink LATAM",
            "200.75.51.132",
            "Latin America",
            "CenturyLink",
        ),
        // Africa
        DnsServer::new("Liquid Telecom", "41.63.64.74", "Africa", "Liquid Telecom"),
        DnsServer::new("SEACOM", "196.216.2.1", "Africa", "SEACOM"),
        DnsServer::new("Safaricom Kenya", "196.201.214.40", "Africa", "Safaricom"),
        DnsServer::new("MTN South Africa", "196.11.180.20", "Africa", "MTN"),
        DnsServer::new("Telecom Egypt", "196.205.152.10", "Africa", "Telecom Egypt"),
        // Middle East
        DnsServer::new("Etisalat UAE", "213.42.20.20", "Middle East", "Etisalat"),
        DnsServer::new("STC Saudi", "212.118.129.106", "Middle East", "STC"),
        DnsServer::new("Bezeq Israel", "192.115.106.81", "Middle East", "Bezeq"),
        DnsServer::new(
            "Turk Telekom",
            "195.175.39.39",
            "Middle East",
            "Turk Telekom",
        ),
        DnsServer::new("Ooredoo Qatar", "212.77.192.10", "Middle East", "Ooredoo"),
    ]
});

/// Returns the default list of global DNS servers for propagation checking.
/// The list is built once and handed out as a borrow. Callers needing an
/// owned `Vec` (e.g. `PropagationChecker` which allows mutation) can call
/// `.to_vec()` on the returned slice.
pub fn default_dns_servers() -> &'static [DnsServer] {
    &DEFAULT_DNS_SERVERS
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

impl std::fmt::Display for NameserverIpInconsistency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let render = |v: &[String]| -> String {
            if v.is_empty() {
                "no records".to_string()
            } else {
                v.join(", ")
            }
        };
        write!(
            f,
            "{} ({}) for {}: {} vs consensus: {}",
            self.server_name,
            self.server_ip,
            self.nameserver,
            render(&self.values),
            render(&self.consensus),
        )
    }
}

impl std::fmt::Display for Inconsistency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let render = |v: &[String]| -> String {
            if v.is_empty() {
                "NXDOMAIN".to_string()
            } else {
                v.join(", ")
            }
        };
        write!(
            f,
            "{} ({}) [{}]: {} vs consensus: {}",
            self.server_name,
            self.server_ip,
            self.record_type,
            render(&self.values),
            render(&self.consensus),
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

/// Checks DNS propagation across multiple global DNS servers.
#[derive(Debug, Clone)]
pub struct PropagationChecker {
    resolver: DnsResolver,
    servers: Vec<DnsServer>,
}

impl Default for PropagationChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl PropagationChecker {
    pub fn new() -> Self {
        Self {
            resolver: DnsResolver::new().with_timeout(Duration::from_secs(5)),
            servers: default_dns_servers().to_vec(),
        }
    }

    pub fn with_servers(mut self, servers: Vec<DnsServer>) -> Self {
        self.servers = servers;
        self
    }

    pub fn add_server(mut self, server: DnsServer) -> Self {
        self.servers.push(server);
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.resolver = DnsResolver::new().with_timeout(timeout);
        self
    }

    /// Outer deadline for the entire propagation check across all servers.
    /// Individual server queries have their own per-query timeout via the resolver;
    /// this guards against the aggregate wall-clock time exceeding a safe limit.
    const PROPAGATION_TIMEOUT: Duration = Duration::from_secs(15);

    /// Hard cap on the post-check nameserver-IP enrichment step for NS lookups.
    /// If it expires, propagation results are returned without IP annotations
    /// rather than failing the whole call — enrichment is best-effort.
    /// Bumped from the single-vantage version (5s) because per-vantage
    /// resolution fans out 29 servers × N nameservers; even fully parallel,
    /// the slowest single A/AAAA query gates completion and DNS-over-WAN to
    /// distant resolvers can exceed the per-query timeout.
    const NS_RESOLUTION_TIMEOUT: Duration = Duration::from_secs(8);

    #[instrument(skip(self), fields(domain = %domain, record_type = %record_type))]
    pub async fn check(&self, domain: &str, record_type: RecordType) -> Result<PropagationResult> {
        debug!(servers = self.servers.len(), "Starting propagation check");

        let futures: Vec<_> = self
            .servers
            .iter()
            .map(|server| self.query_server(domain, record_type, server.clone()))
            .collect();

        let results = tokio::time::timeout(Self::PROPAGATION_TIMEOUT, join_all(futures))
            .await
            .map_err(|_| {
                warn!(
                    domain = %domain,
                    timeout_secs = Self::PROPAGATION_TIMEOUT.as_secs(),
                    "Propagation check timed out"
                );
                SeerError::Timeout(format!(
                    "propagation check for {} timed out after {}s",
                    domain,
                    Self::PROPAGATION_TIMEOUT.as_secs()
                ))
            })?;

        let mut results = results;
        let servers_checked = results.len();
        let servers_responding = results.iter().filter(|r| r.success).count();

        // Calculate propagation and find consensus
        let (propagation_percentage, consensus_values, inconsistencies, unreachable_servers) =
            analyze_results(&results, record_type);

        // For NS lookups, ask each responding propagation server what A/AAAA
        // it returns for every nameserver hostname observed in the NS answers.
        // This is the per-vantage view that surfaces glue-record propagation
        // lag — a regional recursor still serving the previous IP shows up as
        // a `NameserverIpInconsistency`. Bounded by NS_RESOLUTION_TIMEOUT so a
        // slow secondary lookup cannot extend total wall-clock beyond the
        // documented bound; on timeout we surface results without IP
        // annotations rather than failing the call.
        let (resolved_ips, nameserver_inconsistencies) = if record_type == RecordType::NS {
            match tokio::time::timeout(
                Self::NS_RESOLUTION_TIMEOUT,
                self.resolve_nameserver_ips_per_vantage(&mut results),
            )
            .await
            {
                Ok((consensus, inconsistencies)) => (consensus, inconsistencies),
                Err(_) => {
                    warn!(
                        domain = %domain,
                        timeout_secs = Self::NS_RESOLUTION_TIMEOUT.as_secs(),
                        "Per-vantage nameserver IP enrichment timed out; returning results without IP annotations"
                    );
                    (HashMap::new(), Vec::new())
                }
            }
        } else {
            (HashMap::new(), Vec::new())
        };

        Ok(PropagationResult {
            domain: domain.to_string(),
            record_type,
            servers_checked,
            servers_responding,
            propagation_percentage,
            results,
            consensus_values,
            inconsistencies,
            unreachable_servers,
            // DNSSEC validation is not currently performed by the resolver.
            // This field exists so callers / formatters can disclose the
            // lack of authentication to users.
            dnssec_validated: false,
            resolved_ips,
            nameserver_inconsistencies,
        })
    }

    /// Per-vantage resolution: for every unique nameserver hostname returned
    /// across all NS answers, ask each successfully-responding propagation
    /// server (via its own IP) for that hostname's A/AAAA addresses. Each
    /// server's view is written into `ServerResult.nameserver_ips`; the
    /// cross-server consensus and the set of disagreeing resolvers are
    /// returned to the caller.
    ///
    /// Failed A/AAAA lookups from a given vantage are recorded as an empty
    /// list — empty matches an NXDOMAIN/NODATA response, and either way the
    /// resolver couldn't provide an IP. If that empty differs from the
    /// consensus it surfaces as a `NameserverIpInconsistency`.
    ///
    /// Hostnames are lowercased for dedup so case-variant responses from
    /// different upstream resolvers do not trigger redundant lookups.
    /// Formatters must lowercase the record value before looking up the map.
    async fn resolve_nameserver_ips_per_vantage(
        &self,
        results: &mut [ServerResult],
    ) -> (HashMap<String, Vec<String>>, Vec<NameserverIpInconsistency>) {
        let unique: HashSet<String> = results
            .iter()
            .flat_map(|sr| sr.records.iter())
            .filter_map(|r| match &r.data {
                RecordData::NS { nameserver } => Some(nameserver.to_ascii_lowercase()),
                _ => None,
            })
            .collect();

        if unique.is_empty() {
            return (HashMap::new(), Vec::new());
        }

        // Build a flat (server_index, nameserver) work list of A+AAAA lookups
        // and fan out in parallel. Only successful propagation servers — those
        // that already answered the NS query — are queried; an unreachable
        // server can't meaningfully report a per-vantage IP either.
        let unique_vec: Vec<String> = unique.into_iter().collect();
        let mut tasks = Vec::new();
        for (idx, sr) in results.iter().enumerate() {
            if !sr.success {
                continue;
            }
            for ns in &unique_vec {
                let resolver = self.resolver.clone();
                let server_ip = sr.server.ip.clone();
                let ns = ns.clone();
                tasks.push(async move {
                    let (a_res, aaaa_res) = tokio::join!(
                        resolver.resolve(&ns, RecordType::A, Some(&server_ip)),
                        resolver.resolve(&ns, RecordType::AAAA, Some(&server_ip)),
                    );
                    let mut ips: Vec<String> = Vec::new();
                    if let Ok(records) = a_res {
                        for r in &records {
                            if let RecordData::A { address } = &r.data {
                                ips.push(address.clone());
                            }
                        }
                    }
                    if let Ok(records) = aaaa_res {
                        for r in &records {
                            if let RecordData::AAAA { address } = &r.data {
                                ips.push(address.clone());
                            }
                        }
                    }
                    ips.sort();
                    ips.dedup();
                    (idx, ns, ips)
                });
            }
        }

        let outputs = join_all(tasks).await;
        for (idx, ns, ips) in outputs {
            results[idx].nameserver_ips.insert(ns, ips);
        }

        let consensus = build_nameserver_consensus(results, &unique_vec);
        let inconsistencies = build_nameserver_inconsistencies(results, &consensus);
        (consensus, inconsistencies)
    }

    async fn query_server(
        &self,
        domain: &str,
        record_type: RecordType,
        server: DnsServer,
    ) -> ServerResult {
        let start = Instant::now();

        match self
            .resolver
            .resolve(domain, record_type, Some(&server.ip))
            .await
        {
            Ok(records) => {
                let response_time_ms = start.elapsed().as_millis() as u64;
                debug!(
                    server = %server.name,
                    records = records.len(),
                    time_ms = response_time_ms,
                    "Server responded"
                );
                ServerResult {
                    server,
                    records,
                    response_time_ms,
                    success: true,
                    error: None,
                    nameserver_ips: HashMap::new(),
                }
            }
            Err(e) => {
                let response_time_ms = start.elapsed().as_millis() as u64;
                debug!(
                    server = %server.name,
                    error = %e,
                    "Server query failed"
                );
                ServerResult {
                    server,
                    records: vec![],
                    response_time_ms,
                    success: false,
                    error: Some(e.to_string()),
                    nameserver_ips: HashMap::new(),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_dns_servers() {
        let servers = default_dns_servers();
        assert!(
            servers.len() >= 20,
            "Should have at least 20 global DNS servers"
        );

        // Verify regions are covered
        let locations: Vec<&str> = servers.iter().map(|s| s.location.as_str()).collect();
        assert!(locations.contains(&"North America"));
        assert!(locations.contains(&"Europe"));
        assert!(locations.contains(&"Asia Pacific"));
        assert!(locations.contains(&"Latin America"));
        assert!(locations.contains(&"Africa"));
        assert!(locations.contains(&"Middle East"));
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
                    data: crate::dns::RecordData::A {
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

        let (_pct, _consensus, inconsistencies, unreachable) =
            analyze_results(&results, RecordType::A);

        assert!(
            inconsistencies.is_empty(),
            "timeout must not produce an inconsistency, got: {:?}",
            inconsistencies
        );
        assert_eq!(unreachable.len(), 1);
        assert_eq!(unreachable[0].name, "Bad");
        assert_eq!(unreachable[0].error.as_deref(), Some("timed out"));
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
    fn test_analyze_empty_results() {
        // No servers at all → no consensus, no inconsistencies (a missing
        // answer is reported via unreachable_servers / servers_responding,
        // not as a fake "no servers responded" inconsistency).
        let results: Vec<ServerResult> = vec![];
        let (pct, consensus, issues, unreachable) = analyze_results(&results, RecordType::A);
        assert_eq!(pct, 0.0);
        assert!(consensus.is_empty());
        assert!(issues.is_empty());
        assert!(unreachable.is_empty());
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
                    data: crate::dns::RecordData::A {
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
                    data: crate::dns::RecordData::A {
                        address: "1.2.3.4".to_string(),
                    },
                }],
                response_time_ms: 15,
                success: true,
                error: None,
                nameserver_ips: HashMap::new(),
            },
        ];
        let (pct, consensus, issues, unreachable) = analyze_results(&results, RecordType::A);
        assert_eq!(pct, 100.0);
        assert_eq!(
            consensus,
            vec![ConsensusValue::new(RecordType::A, "1.2.3.4")]
        );
        assert!(issues.is_empty());
        assert!(unreachable.is_empty());
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

/// Compute the cross-server consensus IP set for each nameserver hostname.
///
/// For each hostname, picks the value set (sorted+deduped IPs) that the largest
/// number of *successfully-responding* propagation servers agree on. Ties are
/// broken by `HashMap` iteration order — fine in practice because ties only
/// occur during active flux, which is exactly when the propagation report is
/// meant to be ambiguous. Servers without an entry for a hostname (e.g. the
/// per-vantage A/AAAA lookup wasn't issued) are skipped, not counted as empty.
fn build_nameserver_consensus(
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
fn build_nameserver_inconsistencies(
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

fn analyze_results(
    results: &[ServerResult],
    record_type: RecordType,
) -> (
    f64,
    Vec<ConsensusValue>,
    Vec<Inconsistency>,
    Vec<UnreachableServer>,
) {
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
        return (0.0, vec![], vec![], unreachable_servers);
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
        return (0.0, vec![], vec![], unreachable_servers);
    };

    // Calculate propagation percentage based on ALL servers checked (not just
    // responding ones) so unreachable servers count as non-propagated.
    let propagation_percentage = (consensus_count as f64 / results.len() as f64) * 100.0;

    // Find inconsistencies (reuse pre-computed sorted value sets).
    // We emit structured records carrying the record type and raw value sets;
    // formatters can render however they like via `Display`.
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

    // Note: failed/unreachable servers are NOT merged into `inconsistencies`.
    // They are reported separately via the `unreachable_servers` return value
    // so that `has_inconsistencies()` reflects only genuine answer conflicts.

    // For record types where empty result is valid, adjust messaging
    if consensus_values.is_empty()
        && record_type != RecordType::A
        && record_type != RecordType::AAAA
    {
        // No records is a valid state for optional record types
    }

    // Tag each consensus value with the queried record type so downstream
    // consumers don't have to cross-reference `PropagationResult.record_type`.
    let tagged_consensus: Vec<ConsensusValue> = consensus_values
        .iter()
        .map(|v| ConsensusValue::new(record_type, v.clone()))
        .collect();

    (
        propagation_percentage,
        tagged_consensus,
        inconsistencies,
        unreachable_servers,
    )
}
