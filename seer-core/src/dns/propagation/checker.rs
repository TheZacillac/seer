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
use crate::dns::query::{DnsQueryResult, DnsStatus};
use crate::dns::records::{RecordData, RecordType};
use crate::dns::resolver::{DnsResolver, ServerReply};
use crate::error::Result;

/// Caps concurrent A/AAAA lookups during nameserver-IP enrichment so a large
/// custom server list can't trigger an unbounded burst of DNS queries (#61).
const MAX_CONCURRENT_NS_LOOKUPS: usize = 50;

/// Per-server wall-clock budget derived from the per-query timeout.
///
/// A slow or unreachable vantage point is capped at this budget and reported as
/// a failed `ServerResult`, so it can never drag the whole fan-out out — nor, as
/// it once could under a single aggregate deadline, discard every server that
/// already answered. The query itself stops at one timeout (plus a TCP repeat
/// of a truncated reply inside it); this outer bound, 2× with a 1s margin,
/// only backstops it.
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

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.resolver = DnsResolver::new().with_timeout(timeout);
        self.query_timeout = timeout;
        self
    }

    /// Hard cap on the post-check nameserver-IP enrichment step for NS lookups.
    /// If it expires, propagation results are returned without IP annotations
    /// rather than failing the whole call — enrichment is best-effort.
    /// Bumped from the single-vantage version (5s) because per-vantage
    /// resolution fans out every responding server × N nameservers; even fully parallel,
    /// the slowest single A/AAAA query gates completion and DNS-over-WAN to
    /// distant resolvers can exceed the per-query timeout.
    const NS_RESOLUTION_TIMEOUT: Duration = Duration::from_secs(8);

    #[instrument(skip(self), fields(domain = %domain, record_type = %record_type))]
    pub async fn check(&self, domain: &str, record_type: RecordType) -> Result<PropagationResult> {
        // Normalize once up front so the stored `domain` field agrees with what
        // every per-server query actually resolves, instead of echoing the raw
        // input and re-normalizing once per server inside the resolver. Uses
        // the resolver's own per-name rule (`prepare_query`): `www.` is kept
        // (it is a distinct name with its own records) and an IPv6 PTR literal
        // passes through instead of being mangled as `host:port`.
        let domain = crate::dns::resolver::prepare_query(domain, record_type)?;

        // An SRV query needs a `_service._proto.name` query name. A bare domain
        // is a deterministic input error: without this guard it fails identically
        // on every server, and the aggregate result (0% / all
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
        // resolver exhausting its per-query retries used to push
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
                    // A failed lookup contributes no addresses.
                    let mut ips: Vec<String> = [a_res, aaaa_res]
                        .into_iter()
                        .flatten()
                        .flatten()
                        .filter_map(|r| r.data.address().map(str::to_string))
                        .collect();
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

    /// Test-only: query through `resolver` (a mock-wired one) with its
    /// per-query `timeout`.
    #[cfg(test)]
    fn with_resolver(mut self, resolver: DnsResolver, timeout: Duration) -> Self {
        self.resolver = resolver;
        self.query_timeout = timeout;
        self
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
                    error: Some("timed out".to_string()),
                    status: None,
                }
            }
        }
    }

    /// Asks `server` for the records, directly and once
    /// ([`DnsResolver::query_server`]), and reads its reply into a
    /// `ServerResult` (see [`read_reply`]).
    async fn query_server(
        &self,
        domain: &str,
        record_type: RecordType,
        server: DnsServer,
    ) -> ServerResult {
        let start = Instant::now();
        let reply = self
            .resolver
            .query_server(domain, record_type, &server.ip)
            .await;
        let response_time_ms = start.elapsed().as_millis() as u64;
        let (records, status, error) = match reply {
            Ok(ServerReply::Response(response)) => read_reply(response, record_type),
            Ok(ServerReply::Silent(reason)) => (vec![], None, Some(reason)),
            Err(e) => {
                debug!(server = %server.name, error = %e, "Server query failed");
                // Sanitized for external return; full detail logged above.
                (vec![], None, Some(e.sanitized_message()))
            }
        };
        debug!(
            server = %server.name,
            records = records.len(),
            status = ?status,
            error = ?error,
            time_ms = response_time_ms,
            "Server replied"
        );
        ServerResult {
            server,
            success: error.is_none(),
            records,
            response_time_ms,
            error,
            status,
        }
    }
}

/// Reads one server's response: a definitive answer (NOERROR or NXDOMAIN)
/// yields its records of the queried type (for ANY, every answer) and no
/// error; any other status, or a referral from a server that is not
/// recursive, yields the reason as the error.
fn read_reply(
    response: DnsQueryResult,
    record_type: RecordType,
) -> (
    Vec<crate::dns::DnsRecord>,
    Option<DnsStatus>,
    Option<String>,
) {
    let status = Some(response.status);
    if response.referral_zone().is_some() {
        return (
            vec![],
            status,
            Some("referral only (not a recursive resolver)".into()),
        );
    }
    match response.status {
        DnsStatus::NoError | DnsStatus::NxDomain => {
            let records = if record_type == RecordType::ANY {
                response.answers
            } else {
                response
                    .records()
                    .filter(|r| r.record_type == record_type)
                    .cloned()
                    .collect()
            };
            (records, status, None)
        }
        other => (vec![], status, Some(other.to_string())),
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
        // `www.` is kept: it is a distinct DNS name (commonly a CNAME), and
        // stripping it checked propagation of the apex instead.
        assert_eq!(
            result.domain, "www.example.com",
            "stored domain must be the normalized form, not the raw input"
        );
        // Sanity: with no servers, nothing was queried.
        assert_eq!(result.servers_checked, 0);
        assert_eq!(result.servers_responding, 0);
    }

    /// An IPv6 PTR literal must be accepted (it used to fail
    /// `normalize_domain`, whose `:port` strip ate the last hextet).
    #[tokio::test]
    async fn check_accepts_ipv6_ptr_literal() {
        let checker = PropagationChecker::empty_for_tests();
        let result = checker
            .check("2606:4700:4700::1111", RecordType::PTR)
            .await
            .expect("IPv6 PTR literal must pass normalization");
        assert_eq!(result.domain, "2606:4700:4700::1111");
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

    /// Each kind of reply a server can give reads as it should: a definitive
    /// answer (records, NXDOMAIN, NODATA — the last two told apart by
    /// `status`) is a success, and REFUSED, SERVFAIL, a referral or silence
    /// is a failure whose `error` names why, instead of the old catch-all
    /// "DNS resolution failed".
    #[tokio::test]
    async fn server_replies_are_classified_with_their_reason() {
        use crate::dns::test_support::{
            a_rdata, cname_rdata, mock_dns_resolver, record, spawn_mock_dns_fn, MockReply,
        };

        let port = spawn_mock_dns_fn(|name, _| match name {
            "answer.seer.test" => MockReply::Answer(vec![a_rdata([192, 0, 2, 1])]),
            "www.seer.test" => MockReply::Records(vec![
                record("www.seer.test", 300, cname_rdata("answer.seer.test")),
                record("answer.seer.test", 300, a_rdata([192, 0, 2, 1])),
            ]),
            "nx.seer.test" => MockReply::NxDomainWithSoa("seer.test"),
            "nodata.seer.test" => MockReply::NoDataWithSoa("seer.test"),
            "refused.seer.test" => MockReply::Refused,
            "servfail.seer.test" => MockReply::ServFail,
            "referral.seer.test" => MockReply::Delegation {
                zone: "referral.seer.test".into(),
                servers: vec![("ns1.elsewhere.test".into(), vec![])],
            },
            _ => MockReply::NoReply,
        })
        .await;
        let timeout = Duration::from_millis(300);
        let checker = PropagationChecker::new()
            .with_servers(vec![DnsServer::new("Mock", "127.0.0.1", "Test", "Test")])
            .with_resolver(mock_dns_resolver(port).with_timeout(timeout), timeout);

        /// (name, success, status, error, record values)
        type Case<'a> = (
            &'a str,
            bool,
            Option<DnsStatus>,
            Option<&'a str>,
            &'a [&'a str],
        );
        let cases: [Case; 8] = [
            (
                "answer.seer.test",
                true,
                Some(DnsStatus::NoError),
                None,
                &["192.0.2.1"],
            ),
            // The CNAME is followed by the resolver; only the A is compared.
            (
                "www.seer.test",
                true,
                Some(DnsStatus::NoError),
                None,
                &["192.0.2.1"],
            ),
            ("nx.seer.test", true, Some(DnsStatus::NxDomain), None, &[]),
            (
                "nodata.seer.test",
                true,
                Some(DnsStatus::NoError),
                None,
                &[],
            ),
            (
                "refused.seer.test",
                false,
                Some(DnsStatus::Refused),
                Some("REFUSED"),
                &[],
            ),
            (
                "servfail.seer.test",
                false,
                Some(DnsStatus::ServFail),
                Some("SERVFAIL"),
                &[],
            ),
            (
                "referral.seer.test",
                false,
                Some(DnsStatus::NoError),
                Some("referral only (not a recursive resolver)"),
                &[],
            ),
            ("silent.seer.test", false, None, Some("timed out"), &[]),
        ];
        for (name, success, status, error, values) in cases {
            let result = checker.check(name, RecordType::A).await.expect(name);
            let server = &result.results[0];
            assert_eq!(server.success, success, "{name}");
            assert_eq!(server.status, status, "{name}");
            assert_eq!(server.error.as_deref(), error, "{name}");
            let got: Vec<String> = server.records.iter().map(|r| r.format_short()).collect();
            assert_eq!(got, values, "{name}");
            assert_eq!(result.servers_responding, usize::from(success), "{name}");
        }

        let nx = checker.check("nx.seer.test", RecordType::A).await.unwrap();
        assert_eq!(nx.results[0].empty_answer_label(), "NXDOMAIN");
        assert_eq!(nx.empty_consensus_label(), Some("NXDOMAIN"));
        let nodata = checker
            .check("nodata.seer.test", RecordType::A)
            .await
            .unwrap();
        assert_eq!(nodata.empty_consensus_label(), Some("NODATA"));
    }
}
