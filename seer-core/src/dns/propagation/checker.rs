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
use crate::error::Result;

/// Caps concurrent A/AAAA lookups during nameserver-IP enrichment so a large
/// custom server list can't trigger an unbounded burst of DNS queries (#61).
const MAX_CONCURRENT_NS_LOOKUPS: usize = 50;

/// Per-server wall-clock budget derived from the resolver's per-query timeout.
///
/// A slow or unreachable vantage point is capped at this budget and reported as
/// a failed `ServerResult`, so it can never drag the whole fan-out out — nor, as
/// it once could under a single aggregate deadline, discard every server that
/// already answered. Allows the resolver its per-query timeout plus one retry
/// (2×) with a 1s margin so a responsive-but-distant resolver is not cut short.
fn per_server_budget(query_timeout: Duration) -> Duration {
    query_timeout
        .saturating_mul(2)
        .saturating_add(Duration::from_secs(1))
}

/// Checks DNS propagation across multiple global DNS servers.
#[derive(Debug, Clone)]
pub struct PropagationChecker {
    resolver: DnsResolver,
    servers: Vec<DnsServer>,
    /// The resolver's per-query timeout, mirrored here so the per-server
    /// wall-clock budget (see [`per_server_budget`]) can scale with it.
    query_timeout: Duration,
}

impl Default for PropagationChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl PropagationChecker {
    pub fn new() -> Self {
        let query_timeout = Duration::from_secs(5);
        Self {
            resolver: DnsResolver::new().with_timeout(query_timeout),
            servers: default_dns_servers().to_vec(),
            query_timeout,
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
        self.query_timeout = timeout;
        self
    }

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
        // Normalize once up front so the stored `domain` field agrees with what
        // every per-server query actually resolves, instead of echoing the raw
        // input and re-normalizing ~29 times lazily inside the resolver. (The
        // DNSSEC checker already normalizes this way.)
        let domain = crate::validation::normalize_domain(domain)?;

        // An SRV query needs a `_service._proto.name` query name. A bare domain
        // is a deterministic input error: without this guard it fails identically
        // on every one of the ~29 servers, and the aggregate result (0% / all
        // unreachable) is indistinguishable from a real network-wide outage.
        // Reject it once, up front, before any fan-out.
        if record_type == RecordType::SRV
            && crate::dns::resolver::parse_srv_query(&domain).is_none()
        {
            return Err(crate::dns::resolver::srv_format_error());
        }

        debug!(servers = self.servers.len(), "Starting propagation check");

        // Bound each vantage point independently rather than wrapping the whole
        // fan-out in one aggregate deadline. A single slow or unreachable
        // resolver (the default list includes regional ISP recursors that don't
        // answer external queries) exhausting its per-query retries used to push
        // the aggregate past the outer deadline and fail the ENTIRE check —
        // discarding every server that had already answered, so a domain that
        // resolves instantly on the major resolvers reported a spurious timeout.
        // With a per-server budget the stragglers come back as failed
        // `ServerResult`s (routed to `unreachable_servers` by `analyze_results`)
        // and the servers that answered are always preserved.
        let budget = per_server_budget(self.query_timeout);
        let futures: Vec<_> = self
            .servers
            .iter()
            .map(|server| self.query_server_bounded(&domain, record_type, server.clone(), budget))
            .collect();

        // Every future is individually capped at `budget`, so `join_all`
        // completes in at most `budget` no matter how many vantage points hang.
        let results = join_all(futures).await;

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

    #[cfg(test)]
    fn empty_for_tests() -> Self {
        Self {
            resolver: DnsResolver::new(),
            servers: Vec::new(),
            query_timeout: Duration::from_secs(5),
        }
    }

    /// [`query_server`](Self::query_server) wrapped in a per-server timeout.
    ///
    /// On expiry the vantage point is recorded as a failed `ServerResult`
    /// (`success: false`) rather than left to hang, so one unreachable resolver
    /// can neither hold up nor discard the whole propagation result. The
    /// resolver has its own per-query timeout/retries; this is the outer bound
    /// that also covers a resolver whose retries would otherwise run long.
    async fn query_server_bounded(
        &self,
        domain: &str,
        record_type: RecordType,
        server: DnsServer,
        budget: Duration,
    ) -> ServerResult {
        let start = Instant::now();
        match tokio::time::timeout(
            budget,
            self.query_server(domain, record_type, server.clone()),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                debug!(
                    server = %server.name,
                    budget_secs = budget.as_secs(),
                    "Server exceeded per-server budget; recording as unreachable"
                );
                ServerResult {
                    server,
                    records: vec![],
                    response_time_ms: start.elapsed().as_millis() as u64,
                    success: false,
                    error: Some("query timed out".to_string()),
                }
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::SeerError;

    /// `check()` must normalize the input domain ONCE at the top and store the
    /// normalized value, rather than echoing back the raw (messy) input. An
    /// empty server list keeps this hermetic — no live DNS is performed.
    #[tokio::test]
    async fn check_stores_normalized_domain() {
        let checker = PropagationChecker::empty_for_tests();
        let result = checker
            .check("HTTPS://WWW.Example.COM/some/path", RecordType::A)
            .await
            .expect("check with empty server list should succeed");
        assert_eq!(
            result.domain, "example.com",
            "stored domain must be the normalized form, not the raw input"
        );
        // Sanity: with no servers, nothing was queried.
        assert_eq!(result.servers_checked, 0);
        assert_eq!(result.servers_responding, 0);
    }

    /// An SRV query against a bare domain is a deterministic input error, not a
    /// network condition. `check()` must reject it up front with `InvalidInput`
    /// rather than fanning out and reporting every server as failed (which is
    /// indistinguishable from a real outage). Uses the empty-server seam, so the
    /// rejection must happen before any server fan-out for this to pass.
    #[tokio::test]
    async fn check_rejects_srv_against_bare_domain() {
        let checker = PropagationChecker::empty_for_tests();
        let err = checker
            .check("example.com", RecordType::SRV)
            .await
            .expect_err("bare-domain SRV must be rejected as an input error");
        assert!(
            matches!(err, SeerError::InvalidInput(_)),
            "expected InvalidInput, got: {err:?}"
        );
    }

    /// A properly-formed `_service._proto.name` SRV query must NOT be rejected
    /// by the upfront guard (it should proceed to the normal fan-out path).
    #[tokio::test]
    async fn check_allows_well_formed_srv_query() {
        let checker = PropagationChecker::empty_for_tests();
        let result = checker
            .check("_sip._tcp.example.com", RecordType::SRV)
            .await
            .expect("well-formed SRV query must pass the upfront guard");
        assert_eq!(result.servers_checked, 0);
    }

    /// The per-server budget must allow the resolver's per-query timeout plus a
    /// retry (2×) and never collapse to zero, so a responsive-but-distant
    /// resolver is not cut short.
    #[test]
    fn per_server_budget_allows_a_retry_plus_margin() {
        assert_eq!(
            per_server_budget(Duration::from_secs(5)),
            Duration::from_secs(11)
        );
        // Scales with a custom (e.g. config-driven) timeout.
        assert_eq!(
            per_server_budget(Duration::from_secs(2)),
            Duration::from_secs(5)
        );
        // Degenerate zero timeout still yields a usable, non-zero budget.
        assert_eq!(
            per_server_budget(Duration::from_secs(0)),
            Duration::from_secs(1)
        );
    }

    /// A vantage point that fails must NOT sink the whole check: the failing
    /// server is reported as unreachable and the overall call still returns
    /// `Ok` with partial results. This is the regression guard for the outer
    /// all-or-nothing timeout that used to discard every server's data when a
    /// slow minority ran long. Hermetic: reserved IPs are rejected by the SSRF
    /// guard before any network I/O, so each server fails fast without a live
    /// query.
    #[tokio::test]
    async fn check_returns_partial_results_when_servers_fail() {
        let servers = vec![
            DnsServer::new("Reserved-A", "10.0.0.1", "Test", "Test"),
            DnsServer::new("Reserved-B", "192.168.1.1", "Test", "Test"),
        ];
        let checker = PropagationChecker::new().with_servers(servers);
        let result = checker
            .check("example.com", RecordType::A)
            .await
            .expect("failing servers must yield Ok partial results, not a whole-check error");
        assert_eq!(result.servers_checked, 2);
        assert_eq!(result.servers_responding, 0);
        assert_eq!(result.unreachable_servers.len(), 2);
    }
}
