use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::future::join_all;
use tokio::sync::Semaphore;
use tracing::{debug, instrument};

use super::analysis::{
    analyze_results, build_nameserver_consensus, build_nameserver_inconsistencies, PerVantage,
};
use super::servers::default_dns_servers;
use super::types::{DnsServer, NameserverDetails, PropagationResult, ServerResult};
use crate::dns::query::{DnsQueryResult, DnsStatus};
use crate::dns::records::{RecordData, RecordType};
use crate::dns::resolver::{DnsResolver, ServerReply};
use crate::dns::DEFAULT_DNS_TIMEOUT;
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
        Self {
            resolver: DnsResolver::new(),
            servers: default_dns_servers().to_vec(),
            query_timeout: DEFAULT_DNS_TIMEOUT,
        }
    }

    /// Builds a checker honoring `~/.seer/config.toml` (`timeouts.dns_secs`).
    /// The configured nameserver does not apply: a propagation check asks its
    /// own list of public resolvers.
    pub fn from_config(config: &crate::config::SeerConfig) -> Self {
        Self::new().with_timeout(config.dns_timeout())
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
        // a `NameserverIpInconsistency`. Each lookup is bounded on its own,
        // so a slow one costs only its own entry.
        let nameserver_details = if record_type == RecordType::NS {
            self.resolve_nameserver_details(&results, budget).await
        } else {
            None
        };

        Ok(PropagationResult {
            domain,
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
    /// Each vantage's A and AAAA lookups for one hostname run under
    /// `budget` (the per-server budget) and count only when both answered: an
    /// empty set is a negative answer (NXDOMAIN/NODATA), which may surface as
    /// a `NameserverIpInconsistency`; a failed or timed-out lookup leaves the
    /// entry out — no data, never a partial or empty set that would read as
    /// a disagreement.
    ///
    /// Hostnames are lowercased for dedup so case-variant responses from
    /// different upstream resolvers do not trigger redundant lookups.
    /// Formatters must lowercase the record value before looking up the map.
    async fn resolve_nameserver_details(
        &self,
        results: &[ServerResult],
        budget: Duration,
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
        // tasks, each doing 2 lookups. Harmless at the built-in 20-server list,
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
                    let lookups = async {
                        tokio::join!(
                            resolver.resolve(&ns, RecordType::A, Some(&server_ip)),
                            resolver.resolve(&ns, RecordType::AAAA, Some(&server_ip)),
                        )
                    };
                    let ips = match tokio::time::timeout(budget, lookups).await {
                        Ok((a, aaaa)) => vantage_addresses(a, aaaa),
                        Err(_) => None,
                    };
                    (server_ip, ns, ips)
                });
            }
        }

        let outputs = join_all(tasks).await;
        let mut per_vantage: PerVantage = HashMap::new();
        for (server_ip, ns, ips) in outputs {
            if let Some(ips) = ips {
                per_vantage.entry(server_ip).or_default().insert(ns, ips);
            }
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
        Self::new().with_servers(Vec::new())
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

/// One vantage's addresses for a nameserver host, from its A and AAAA
/// lookups: sorted and deduplicated, empty for a negative answer to both, and
/// `None` — no data — when either lookup failed, since the addresses it
/// would have added are unknown.
fn vantage_addresses(
    a: Result<Vec<crate::dns::DnsRecord>>,
    aaaa: Result<Vec<crate::dns::DnsRecord>>,
) -> Option<Vec<String>> {
    let (a, aaaa) = (a.ok()?, aaaa.ok()?);
    let mut ips: Vec<String> = a
        .iter()
        .chain(&aaaa)
        .filter_map(|r| r.data.address().map(str::to_string))
        .collect();
    ips.sort();
    ips.dedup();
    Some(ips)
}

/// Reads one server's response: a definitive answer (NOERROR or NXDOMAIN)
/// yields its records of the queried type (for ANY, every answer) and no
/// error; any other status, a referral from a server that is not recursive,
/// or an `ANY` answer missing a type that got no reply, yields the reason as
/// the error. Shared with the DNS comparison,
/// so both read a server's reply the same way.
pub(in crate::dns) fn read_reply(
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
        // An ANY fan-out with a type that got no reply is an incomplete
        // answer: its missing records are no data, not a disagreement, so
        // the server stays out of the consensus (its records still show).
        DnsStatus::NoError | DnsStatus::NxDomain if !response.failed_types.is_empty() => {
            let missing: Vec<String> = response
                .failed_types
                .iter()
                .map(|f| format!("{} ({})", f.record_type, f.error))
                .collect();
            (
                response.answers,
                status,
                Some(format!(
                    "incomplete answer, no reply for {}",
                    missing.join(", ")
                )),
            )
        }
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
        use hickory_resolver::proto::op::ResponseCode;

        let port = spawn_mock_dns_fn(|name, _| match name {
            "answer.seer.test" => MockReply::Answer(vec![a_rdata([192, 0, 2, 1])]),
            "www.seer.test" => MockReply::Records(vec![
                record("www.seer.test", 300, cname_rdata("answer.seer.test")),
                record("answer.seer.test", 300, a_rdata([192, 0, 2, 1])),
            ]),
            "nx.seer.test" => MockReply::NxDomainWithSoa("seer.test"),
            "nodata.seer.test" => MockReply::NoDataWithSoa("seer.test"),
            "refused.seer.test" => MockReply::Rcode(ResponseCode::Refused),
            "servfail.seer.test" => MockReply::Rcode(ResponseCode::ServFail),
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

    #[test]
    fn from_config_applies_dns_timeout() {
        let mut config = crate::config::SeerConfig::default();
        config.timeouts.dns_secs = 9;
        let checker = PropagationChecker::from_config(&config);
        assert_eq!(checker.query_timeout, Duration::from_secs(9));
        assert_eq!(checker.resolver.timeout(), Duration::from_secs(9));
        assert_eq!(checker.servers.len(), default_dns_servers().len());
    }

    /// Regression: a failed A or AAAA lookup was dropped and the other's
    /// addresses kept (a partial set), and a vantage whose lookups both
    /// failed became an empty set — each read as a
    /// `NameserverIpInconsistency` against the consensus.
    #[test]
    fn failed_vantage_lookup_is_no_data() {
        use crate::dns::{DnsRecord, RecordData};
        let a = |ip: &str| DnsRecord {
            name: "ns1.example.com".into(),
            record_type: RecordType::A,
            ttl: 300,
            data: RecordData::A { address: ip.into() },
        };
        let failed = || Err(SeerError::DnsError("SERVFAIL".into()));
        assert_eq!(
            vantage_addresses(Ok(vec![a("192.0.2.2"), a("192.0.2.1")]), Ok(vec![])),
            Some(vec!["192.0.2.1".to_string(), "192.0.2.2".to_string()])
        );
        assert_eq!(vantage_addresses(Ok(vec![]), Ok(vec![])), Some(vec![]));
        assert_eq!(vantage_addresses(Ok(vec![a("192.0.2.1")]), failed()), None);
        assert_eq!(vantage_addresses(failed(), failed()), None);
    }

    /// Regression: the whole per-vantage enrichment ran under one 8s cap and
    /// was discarded when any lookup ran long. Each vantage's lookups are
    /// bounded on their own: a hostname whose lookups never answer is left
    /// out, and the one that answered is kept.
    #[tokio::test]
    async fn slow_vantage_lookup_keeps_the_answers_that_arrived() {
        use crate::dns::test_support::{a_rdata, mock_dns_resolver, spawn_mock_dns_fn, MockReply};
        use hickory_resolver::proto::rr::rdata as wire;
        use hickory_resolver::proto::rr::{Name, RData};

        let ns = |host: &str| RData::NS(wire::NS(Name::from_ascii(host).unwrap()));
        let port = spawn_mock_dns_fn(
            move |name, qtype| match (name, qtype.to_string().as_str()) {
                ("seer.test", "NS") => {
                    MockReply::Answer(vec![ns("ns1.seer.test."), ns("ns2.seer.test.")])
                }
                ("ns1.seer.test", "A") => MockReply::Answer(vec![a_rdata([192, 0, 2, 1])]),
                ("ns1.seer.test", _) => MockReply::NoData,
                _ => MockReply::NoReply,
            },
        )
        .await;
        let timeout = Duration::from_millis(200);
        let checker = PropagationChecker::new()
            .with_servers(vec![DnsServer::new("Mock", "127.0.0.1", "Test", "Test")])
            .with_resolver(mock_dns_resolver(port).with_timeout(timeout), timeout);

        let result = checker
            .check("seer.test", RecordType::NS)
            .await
            .expect("check");
        let details = result.nameserver_details.expect("NS details");
        let vantage = &details.per_vantage["127.0.0.1"];
        assert_eq!(vantage["ns1.seer.test."], vec!["192.0.2.1".to_string()]);
        assert!(!vantage.contains_key("ns2.seer.test."), "{vantage:?}");
        assert!(details.inconsistencies.is_empty());
    }

    /// Regression: an ANY fan-out whose TXT sub-query timed out read as a
    /// complete answer, so the server "disagreed" with the consensus on TXT.
    #[test]
    fn read_reply_keeps_an_incomplete_any_answer_out_of_the_consensus() {
        let record = crate::dns::DnsRecord {
            name: "example.com".into(),
            record_type: RecordType::A,
            ttl: 300,
            data: RecordData::A {
                address: "192.0.2.1".into(),
            },
        };
        let mut response = DnsQueryResult {
            name: "example.com".into(),
            record_type: RecordType::ANY,
            server: Some("8.8.8.8".into()),
            answered_locally: false,
            status: DnsStatus::NoError,
            flags: vec![],
            answers: vec![record],
            authority: vec![],
            failed_types: vec![crate::dns::FailedType {
                record_type: RecordType::TXT,
                error: "8.8.8.8: timed out".into(),
            }],
            wildcard: None,
            query_time_ms: 5,
        };
        let (records, status, error) = read_reply(response.clone(), RecordType::ANY);
        assert_eq!(records.len(), 1, "the records that arrived still show");
        assert_eq!(status, Some(DnsStatus::NoError));
        let error = error.expect("an incomplete answer is not a success");
        assert!(error.contains("TXT (8.8.8.8: timed out)"), "{error}");

        response.failed_types.clear();
        assert_eq!(read_reply(response, RecordType::ANY).2, None);
    }
}
