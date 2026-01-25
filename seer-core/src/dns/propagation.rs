use std::collections::HashMap;
use std::time::{Duration, Instant};

use futures::future::join_all;
use serde::{Deserialize, Serialize};
use tracing::{debug, instrument};

use super::records::{DnsRecord, RecordType};
use super::resolver::DnsResolver;
use crate::error::Result;

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

/// Returns the default list of global DNS servers for propagation checking.
pub fn default_dns_servers() -> Vec<DnsServer> {
    vec![
        // North America
        DnsServer::new("Google", "8.8.8.8", "North America", "Google"),
        DnsServer::new("Cloudflare", "1.1.1.1", "North America", "Cloudflare"),
        DnsServer::new("OpenDNS", "208.67.222.222", "North America", "Cisco OpenDNS"),
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
        DnsServer::new("Telefonica Brasil", "200.176.2.10", "Latin America", "Telefonica"),
        DnsServer::new("Antel Uruguay", "200.40.30.245", "Latin America", "Antel"),
        DnsServer::new("Telmex Mexico", "200.33.146.217", "Latin America", "Telmex"),
        DnsServer::new("CenturyLink LATAM", "200.75.51.132", "Latin America", "CenturyLink"),
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
        DnsServer::new("Turk Telekom", "195.175.39.39", "Middle East", "Turk Telekom"),
        DnsServer::new("Ooredoo Qatar", "212.77.192.10", "Middle East", "Ooredoo"),
    ]
}

/// Result from querying a single DNS server during propagation check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerResult {
    pub server: DnsServer,
    pub records: Vec<DnsRecord>,
    pub response_time_ms: u64,
    pub success: bool,
    pub error: Option<String>,
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
    pub consensus_values: Vec<String>,
    pub inconsistencies: Vec<String>,
}

impl PropagationResult {
    pub fn is_fully_propagated(&self) -> bool {
        self.propagation_percentage >= 100.0
    }

    pub fn has_inconsistencies(&self) -> bool {
        !self.inconsistencies.is_empty()
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
            servers: default_dns_servers(),
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

    #[instrument(skip(self), fields(domain = %domain, record_type = %record_type))]
    pub async fn check(
        &self,
        domain: &str,
        record_type: RecordType,
    ) -> Result<PropagationResult> {
        debug!(servers = self.servers.len(), "Starting propagation check");

        let futures: Vec<_> = self
            .servers
            .iter()
            .map(|server| self.query_server(domain, record_type, server.clone()))
            .collect();

        let results = join_all(futures).await;

        let servers_checked = results.len();
        let servers_responding = results.iter().filter(|r| r.success).count();

        // Calculate propagation and find consensus
        let (propagation_percentage, consensus_values, inconsistencies) =
            analyze_results(&results, record_type);

        Ok(PropagationResult {
            domain: domain.to_string(),
            record_type,
            servers_checked,
            servers_responding,
            propagation_percentage,
            results,
            consensus_values,
            inconsistencies,
        })
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
                }
            }
        }
    }
}

fn analyze_results(
    results: &[ServerResult],
    record_type: RecordType,
) -> (f64, Vec<String>, Vec<String>) {
    let successful: Vec<_> = results.iter().filter(|r| r.success).collect();

    if successful.is_empty() {
        return (0.0, vec![], vec!["No servers responded".to_string()]);
    }

    // Count occurrences of each value set
    let mut value_counts: HashMap<Vec<String>, usize> = HashMap::new();

    for result in &successful {
        let mut values: Vec<String> = result
            .records
            .iter()
            .map(|r| r.format_short())
            .collect();
        values.sort();
        *value_counts.entry(values).or_insert(0) += 1;
    }

    // Find the most common value set (consensus)
    let (consensus_values, consensus_count) = value_counts
        .iter()
        .max_by_key(|(_, count)| *count)
        .map(|(values, count)| (values.clone(), *count))
        .unwrap_or((vec![], 0));

    // Calculate propagation percentage based on consensus
    let propagation_percentage = if successful.is_empty() {
        0.0
    } else {
        (consensus_count as f64 / successful.len() as f64) * 100.0
    };

    // Find inconsistencies
    let mut inconsistencies = Vec::new();
    for result in &successful {
        let mut values: Vec<String> = result
            .records
            .iter()
            .map(|r| r.format_short())
            .collect();
        values.sort();

        if values != consensus_values {
            let inconsistency = format!(
                "{} ({}): {} vs consensus: {}",
                result.server.name,
                result.server.ip,
                if values.is_empty() {
                    "NXDOMAIN".to_string()
                } else {
                    values.join(", ")
                },
                if consensus_values.is_empty() {
                    "NXDOMAIN".to_string()
                } else {
                    consensus_values.join(", ")
                }
            );
            inconsistencies.push(inconsistency);
        }
    }

    // Add failed servers to inconsistencies
    for result in results.iter().filter(|r| !r.success) {
        let error_msg = result.error.as_deref().unwrap_or("Unknown error");
        inconsistencies.push(format!(
            "{} ({}): {}",
            result.server.name, result.server.ip, error_msg
        ));
    }

    // For record types where empty result is valid, adjust messaging
    if consensus_values.is_empty() && record_type != RecordType::A && record_type != RecordType::AAAA {
        // No records is a valid state for optional record types
    }

    (propagation_percentage, consensus_values, inconsistencies)
}
