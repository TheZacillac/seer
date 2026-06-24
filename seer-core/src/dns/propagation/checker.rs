use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::future::join_all;
use tokio::sync::Semaphore;
use tracing::{debug, instrument, warn};

use super::analysis::{
    analyze_results, build_nameserver_consensus, build_nameserver_inconsistencies, PerVantage,
};
use super::servers::default_dns_servers;
use super::types::{DnsServer, NameserverDetails, PropagationResult, ServerResult};
use crate::dns::records::{RecordData, RecordType};
use crate::dns::resolver::DnsResolver;
use crate::error::{Result, SeerError};

/// Caps concurrent A/AAAA lookups during nameserver-IP enrichment so a large
/// custom server list can't trigger an unbounded burst of DNS queries (#61).
const MAX_CONCURRENT_NS_LOOKUPS: usize = 50;

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

        let servers_checked = results.len();
        let servers_responding = results.iter().filter(|r| r.success).count();

        let outcome = analyze_results(&results, record_type);

        // For NS lookups, ask each responding propagation server what A/AAAA
        // it returns for every nameserver hostname observed in the NS answers.
        // This is the per-vantage view that surfaces glue-record propagation
        // lag — a regional recursor still serving the previous IP shows up as
        // a `NameserverIpInconsistency`. Bounded by NS_RESOLUTION_TIMEOUT so a
        // slow secondary lookup cannot extend total wall-clock beyond the
        // documented bound; on timeout we surface results without IP
        // annotations rather than failing the call.
        let nameserver_details = if record_type == RecordType::NS {
            match tokio::time::timeout(
                Self::NS_RESOLUTION_TIMEOUT,
                self.resolve_nameserver_details(&results),
            )
            .await
            {
                Ok(details) => details,
                Err(_) => {
                    warn!(
                        domain = %domain,
                        timeout_secs = Self::NS_RESOLUTION_TIMEOUT.as_secs(),
                        "Per-vantage nameserver IP enrichment timed out; returning results without IP annotations"
                    );
                    None
                }
            }
        } else {
            None
        };

        Ok(PropagationResult {
            domain: domain.to_string(),
            record_type,
            servers_checked,
            servers_responding,
            propagation_percentage: outcome.propagation_percentage,
            results,
            consensus_values: outcome.consensus_values,
            inconsistencies: outcome.inconsistencies,
            unreachable_servers: outcome.unreachable_servers,
            // DNSSEC validation is not currently performed by the resolver.
            // This field exists so callers / formatters can disclose the
            // lack of authentication to users.
            dnssec_validated: false,
            nameserver_details,
        })
    }

    /// Per-vantage resolution: for every unique nameserver hostname returned
    /// across all NS answers, ask each successfully-responding propagation
    /// server (via its own IP) for that hostname's A/AAAA addresses.
    /// Returns `None` when there are no NS records to enrich; otherwise
    /// returns `Some(NameserverDetails { consensus, per_vantage, inconsistencies })`.
    ///
    /// Failed A/AAAA lookups from a given vantage produce an empty list —
    /// empty matches an NXDOMAIN/NODATA response, and either way the resolver
    /// couldn't provide an IP. If that empty differs from the consensus it
    /// surfaces as a `NameserverIpInconsistency`.
    ///
    /// Hostnames are lowercased for dedup so case-variant responses from
    /// different upstream resolvers do not trigger redundant lookups.
    /// Formatters must lowercase the record value before looking up the map.
    async fn resolve_nameserver_details(
        &self,
        results: &[ServerResult],
    ) -> Option<NameserverDetails> {
        let unique: HashSet<String> = results
            .iter()
            .flat_map(|sr| sr.records.iter())
            .filter_map(|r| match &r.data {
                RecordData::NS { nameserver } => Some(nameserver.to_ascii_lowercase()),
                _ => None,
            })
            .collect();

        if unique.is_empty() {
            return None;
        }

        // Build a flat (server_ip, nameserver) work list of A+AAAA lookups
        // and fan out in parallel. Only successful propagation servers — those
        // that already answered the NS query — are queried; an unreachable
        // server can't meaningfully report a per-vantage IP either.
        let unique_vec: Vec<String> = unique.into_iter().collect();
        // Bound the fan-out: this loop produces `responding_servers × unique_ns`
        // tasks, each doing 2 lookups. Harmless at the built-in 29-server list,
        // but a large custom `with_servers` list would otherwise spawn an
        // unbounded burst of concurrent DNS queries (#61).
        let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_NS_LOOKUPS));
        let mut tasks = Vec::new();
        for sr in results.iter().filter(|sr| sr.success) {
            for ns in &unique_vec {
                let resolver = self.resolver.clone();
                let server_ip = sr.server.ip.clone();
                let ns = ns.clone();
                let sem = sem.clone();
                tasks.push(async move {
                    // Held for the task's lifetime; caps concurrent lookups.
                    let _permit = sem.acquire().await.ok();
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
                    (server_ip, ns, ips)
                });
            }
        }

        let outputs = join_all(tasks).await;
        let mut per_vantage: PerVantage = HashMap::new();
        for (server_ip, ns, ips) in outputs {
            per_vantage.entry(server_ip).or_default().insert(ns, ips);
        }

        let consensus = build_nameserver_consensus(results, &per_vantage, &unique_vec);
        let inconsistencies = build_nameserver_inconsistencies(results, &per_vantage, &consensus);

        Some(NameserverDetails {
            consensus,
            per_vantage,
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
                    // Sanitized for external return; full detail logged above.
                    error: Some(e.sanitized_message()),
                }
            }
        }
    }
}
