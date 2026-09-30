//! Iterative resolution from the root servers down to the answer, one hop
//! per delegation level — what `dig +trace` shows.
//!
//! Flow (see [`DnsTracer::trace`]):
//! 1. Start at the root zone (`.`) with the built-in root hints
//!    ([`ROOT_SERVERS`], IANA's `named.root`).
//! 2. Ask one server of the current zone for the query name and type,
//!    directly and with recursion disabled (RD=0). A server that does not
//!    respond, answers with an error RCODE (SERVFAIL, REFUSED, …), or gives a
//!    lame server's reply — AA clear, no answer, no SOA and no referral — is
//!    noted in the hop's `failed_servers` and the next server of the zone is
//!    asked — up to [`MAX_SERVERS_PER_LEVEL`] servers per level. A server is
//!    asked on one address, IPv4 first: an address this host has no route to
//!    (IPv4 on an IPv6-only host, or the reverse) or cannot open a socket
//!    for (IPv6 when the kernel has IPv6 disabled) fails at once, is noted,
//!    and the server's next address is tried instead, without counting
//!    toward the limit, since no query left the host.
//! 3. A referral — NOERROR, AA clear, no answer, no SOA, NS records in
//!    AUTHORITY — names the next zone, which must lie strictly below the
//!    current zone and at or above the query name (bailiwick); an upward or
//!    sideways referral is unusable, like a lame reply: it is noted and the
//!    zone's next server asked, and only when no server of the zone does
//!    better does the walk stop with an error. The next servers'
//!    addresses are the referral's glue: ADDITIONAL A/AAAA records for the
//!    NS names, trusted only for names inside the current zone, as a
//!    resolver would. Glueless NS names are resolved through the recursive
//!    resolver (Google Public DNS), at most [`MAX_GLUELESS_PER_LEVEL`] per
//!    level.
//! 4. The walk stops at the first answer — authoritative or not; a CNAME is
//!    reported, not chased, as `dig +trace` does — at NXDOMAIN or NODATA
//!    (authoritative, or carrying the zone's SOA), or on an error, which
//!    [`DnsTrace::error`] reports with the hops so far.
//!
//! **One raw exchange per hop.** Each query goes to one server address over
//! UDP (repeated over TCP when the reply is truncated) through the same
//! transport as [`DnsResolver::query`](crate::dns::DnsResolver::query)
//! (`dns::transport`), not through a resolver lookup, because the resolver
//! cannot report a hop as the server sent it (verified against hickory
//! 0.26): its name-server layer (`DnsError::from_response`) turns every
//! referral, NXDOMAIN and NODATA into a `NoRecordsFound` error, which drops
//! the response header (the AA bit) and all of ADDITIONAL but the glue it
//! matched itself, and its caching layer chases a CNAME by sending a
//! follow-up query to the same server. Unlike `query`, a hop asks with
//! recursion off, of the one vetted address the walk chose — the walk, not
//! the transport, decides which server and address to ask next.
//! ([`crate::dns::DelegationChecker`] reads only NS sets, so the resolver
//! serves it.)
//!
//! **SSRF:** every server address — root hint, glue or resolved — passes
//! [`crate::validation::describe_reserved_ip`] (via
//! `delegation::partition_reserved`) before a query is sent; a reserved one
//! is skipped and noted in the hop's `failed_servers`. Tests reach loopback
//! fixtures only through `#[cfg(test)]` seams (`allowing_private_hosts`,
//! `with_root_hints`, `with_port_map`, `with_recursive_upstream`, and
//! `with_unroutable` to simulate a local routing failure); the production
//! validation path is never weakened.
//!
//! **Retry boundary (deliberate):** like the rest of `dns/`, no
//! [`crate::retry::RetryPolicy`]. hickory retransmits a UDP query within the
//! per-query timeout; asking the next server of a zone after one fails is
//! how iterative resolution proceeds, not a retry of the same query.
//!
//! **Bounded work:** at most [`MAX_HOPS`] delegation levels and, per level,
//! at most [`MAX_SERVERS_PER_LEVEL`] queries and [`MAX_GLUELESS_PER_LEVEL`]
//! glueless lookups, each query and each lookup under the per-query timeout
//! (the config file's DNS timeout); an address with no local route fails
//! without waiting. The walk as a whole has one deadline of
//! [`TRACE_BUDGET_TIMEOUTS`] per-query timeouts (30s at the default 5s), as
//! long as a single level may take at worst. The levels run one after
//! another, and every level below a zone its owner controls is theirs to
//! slow down, so without the deadline a chain of levels each answered only
//! by its last server, after timed-out glueless lookups, would hold the
//! caller for `MAX_HOPS × (MAX_SERVERS_PER_LEVEL + MAX_GLUELESS_PER_LEVEL)`
//! = 96 timeouts (8 minutes at the default). A walk that runs out of time
//! stops with the hops so far, and [`DnsTrace::error`] says so. Each
//! referral must descend toward the query name, so the walk cannot loop.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use hickory_resolver::config::ConnectionConfig;
use hickory_resolver::net::NetError;
use hickory_resolver::proto::op::{Message, ResponseCode};
use hickory_resolver::proto::rr::{Name, RData as HickoryRData, RecordType as HickoryRecordType};
use hickory_resolver::TokioResolver;
use serde::{Deserialize, Serialize};
use tracing::{debug, instrument};

use super::delegation::{build_recursive_resolver, is_local_no_route, partition_reserved};
use super::query::{duration_ms, DnsStatus};
use super::records::{DnsRecord, RecordType};
use super::resolver::{fqdn, prepare_query, to_dns_record, wire_query_name, wire_type};
use super::transport::{transport_reason, Transport};
use super::DEFAULT_DNS_TIMEOUT;
use crate::error::{Result, SeerError};

/// Most delegation levels walked (root included) before giving up. Real
/// names resolve in 3–5; the bound matters only for pathological chains.
const MAX_HOPS: usize = 16;

/// Servers queried per delegation level before the level is given up.
const MAX_SERVERS_PER_LEVEL: usize = 3;

/// Glueless nameserver names resolved (through the recursive resolver) per
/// delegation level.
const MAX_GLUELESS_PER_LEVEL: usize = 3;

/// The whole walk's deadline, in per-query timeouts: as long as a single
/// level may take at worst (every query and glueless lookup of it timing
/// out). Any one slow level can still finish; a chain of them cannot hold
/// the caller for [`MAX_HOPS`] times that.
const TRACE_BUDGET_TIMEOUTS: u32 = (MAX_SERVERS_PER_LEVEL + MAX_GLUELESS_PER_LEVEL) as u32;

/// The root zone's servers — name, IPv4, IPv6 — from IANA's root hints
/// (`https://www.internic.net/domain/named.root`, last updated 2026-09-24;
/// b.root-servers.net's addresses changed on 2023-11-27). The one copy: the
/// walk starts here. Literals, parsed by [`root_hints`]; a test proves
/// every entry parses and is public.
const ROOT_SERVERS: [(&str, &str, &str); 13] = [
    ("a.root-servers.net.", "198.41.0.4", "2001:503:ba3e::2:30"),
    ("b.root-servers.net.", "170.247.170.2", "2801:1b8:10::b"),
    ("c.root-servers.net.", "192.33.4.12", "2001:500:2::c"),
    ("d.root-servers.net.", "199.7.91.13", "2001:500:2d::d"),
    ("e.root-servers.net.", "192.203.230.10", "2001:500:a8::e"),
    ("f.root-servers.net.", "192.5.5.241", "2001:500:2f::f"),
    ("g.root-servers.net.", "192.112.36.4", "2001:500:12::d0d"),
    ("h.root-servers.net.", "198.97.190.53", "2001:500:1::53"),
    ("i.root-servers.net.", "192.36.148.17", "2001:7fe::53"),
    ("j.root-servers.net.", "192.58.128.30", "2001:503:c27::2:30"),
    ("k.root-servers.net.", "193.0.14.129", "2001:7fd::1"),
    ("l.root-servers.net.", "199.7.83.42", "2001:500:9f::42"),
    ("m.root-servers.net.", "202.12.27.33", "2001:dc3::35"),
];

/// One delegation level of a [`DnsTrace`]: the server that answered for
/// `zone`, and what it said.
///
/// Zone and server names are fully qualified, lowercase ASCII (IDNs as
/// `xn--` A-labels), as `dig +trace` prints them: `"."` is the root, then
/// e.g. `"com."` and `"example.com."`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceHop {
    /// The zone this server was asked as an authority for (`"."` = root).
    pub zone: String,
    /// The nameserver's host name, e.g. `"a.root-servers.net."`.
    pub server: String,
    /// The address actually queried.
    pub address: String,
    /// Round-trip time of the query, in milliseconds.
    pub query_time_ms: u64,
    /// The response code.
    pub status: DnsStatus,
    /// The response's AA (authoritative answer) bit.
    pub authoritative: bool,
    /// The zone the server delegated to — the next hop's `zone` — or `None`
    /// when it did not refer onward. A referral the walk refused (upward or
    /// sideways) is recorded here too when it ends the trace, with an error.
    pub referral_zone: Option<String>,
    /// The NS names delegated to, sorted; empty when there is no referral.
    pub referral: Vec<String>,
    /// This response's ANSWER section, every record under its real owner
    /// name (normally only the final hop has one).
    pub answers: Vec<DnsRecord>,
    /// Servers of this zone — or single addresses of one — that were skipped
    /// or failed before this one answered, as `"host (ip): reason"`, or
    /// `"host: reason"` when no address was found for the host.
    pub failed_servers: Vec<String>,
}

/// The result of [`DnsTracer::trace`]: every hop from the root down.
///
/// ```json
/// {
///   "name": "www.example.com",
///   "record_type": "A",
///   "hops": [
///     { "zone": ".", "server": "a.root-servers.net.", "address": "198.41.0.4",
///       "query_time_ms": 21, "status": "NOERROR", "authoritative": false,
///       "referral_zone": "com.", "referral": ["a.gtld-servers.net.", "…"],
///       "answers": [], "failed_servers": [] },
///     { "zone": "com.", "…": "…" },
///     { "zone": "example.com.", "server": "a.iana-servers.net.",
///       "address": "199.43.135.53", "query_time_ms": 88, "status": "NOERROR",
///       "authoritative": true, "referral_zone": null, "referral": [],
///       "answers": [{ "name": "www.example.com", "record_type": "A",
///                     "ttl": 300, "data": { "…": "…" } }],
///       "failed_servers": [] }
///   ],
///   "status": "NOERROR",
///   "answers": [{ "name": "www.example.com", "…": "…" }],
///   "error": null
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsTrace {
    /// The queried name, exactly as [`DnsQueryResult::name`] reports it: a
    /// PTR query for an IP literal is named by its reverse-DNS name.
    ///
    /// [`DnsQueryResult::name`]: crate::dns::DnsQueryResult::name
    pub name: String,
    /// The queried record type.
    pub record_type: RecordType,
    /// The hops walked, root first.
    pub hops: Vec<TraceHop>,
    /// The final status: the last hop's response code.
    pub status: DnsStatus,
    /// The final ANSWER section (the last hop's), every record under its real
    /// owner name. A CNAME answer is reported as-is, not chased. The server
    /// may have followed an in-zone chain itself, though: beside NXDOMAIN
    /// the chain leads to the name that does not exist, since the response
    /// code is about the chain's last name (RFC 6604 §2).
    pub answers: Vec<DnsRecord>,
    /// Why the walk stopped before a final response, if it did: every server
    /// of a zone failed (a referral upward or sideways counts as a failure),
    /// the chain was too long, or the walk ran out of time.
    pub error: Option<String>,
}

/// Walks a name's delegation chain from the root servers down, the way
/// `dig +trace` does.
///
/// Construct with [`DnsTracer::new`] (defaults) or
/// [`DnsTracer::from_config`] (honors `~/.seer/config.toml`
/// `timeouts.dns_secs`), then call [`trace`](DnsTracer::trace).
pub struct DnsTracer {
    /// Per-query timeout, for direct queries and glueless lookups alike.
    timeout: Duration,
    /// The direct queries' transport, under the same timeout.
    transport: Transport,
    /// Recursive resolver for glueless nameserver names.
    recursive: TokioResolver,
    /// Test-only: pin the recursive resolver to a loopback mock.
    #[cfg(test)]
    recursive_upstream: Option<(IpAddr, u16)>,
    /// Test-only: root servers to start from instead of [`ROOT_SERVERS`].
    #[cfg(test)]
    root_hints: Option<Vec<NsCandidate>>,
    /// Test-only: per-host port override for direct queries, so each mock
    /// "server" can live on its own ephemeral loopback port.
    #[cfg(test)]
    port_map: Option<std::collections::HashMap<String, u16>>,
    /// Test-only: skip the SSRF/reserved-IP validation on server addresses.
    #[cfg(test)]
    allow_private_hosts: bool,
    /// Test-only: addresses a direct query fails for at once, before
    /// anything is sent, each with the local socket error its function makes
    /// (see `with_unroutable`).
    #[cfg(test)]
    unroutable: Vec<(IpAddr, fn() -> std::io::Error)>,
}

impl std::fmt::Debug for DnsTracer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsTracer")
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl Default for DnsTracer {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsTracer {
    /// Creates a tracer with default settings (5s per-query timeout, Google
    /// DNS for glueless nameserver lookups).
    pub fn new() -> Self {
        Self {
            timeout: DEFAULT_DNS_TIMEOUT,
            transport: Transport::new(DEFAULT_DNS_TIMEOUT),
            recursive: build_recursive_resolver(DEFAULT_DNS_TIMEOUT, None),
            #[cfg(test)]
            recursive_upstream: None,
            #[cfg(test)]
            root_hints: None,
            #[cfg(test)]
            port_map: None,
            #[cfg(test)]
            allow_private_hosts: false,
            #[cfg(test)]
            unroutable: Vec::new(),
        }
    }

    /// Builds a tracer honoring `~/.seer/config.toml` settings.
    ///
    /// Reads `timeouts.dns_secs` (already clamped to 1–60s by
    /// [`crate::config::SeerConfig::load`]). Sugar over
    /// [`DnsTracer::with_timeout`].
    pub fn from_config(config: &crate::config::SeerConfig) -> Self {
        Self::new().with_timeout(config.dns_timeout())
    }

    /// Sets the per-query timeout (each hop's query, including a TCP retry
    /// of a truncated reply, and each glueless nameserver lookup).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self.transport = Transport::new(timeout);
        self.recursive = build_recursive_resolver(timeout, self.recursive_upstream());
        self
    }

    /// Test-only: point the recursive resolver at a loopback mock server.
    #[cfg(test)]
    fn with_recursive_upstream(mut self, ip: IpAddr, port: u16) -> Self {
        self.recursive_upstream = Some((ip, port));
        self.recursive = build_recursive_resolver(self.timeout, self.recursive_upstream);
        self
    }

    /// Test-only: start the walk at these `(host, address)` root servers.
    #[cfg(test)]
    fn with_root_hints(mut self, hints: &[(&str, IpAddr)]) -> Self {
        self.root_hints = Some(
            hints
                .iter()
                .map(|(host, ip)| NsCandidate {
                    host: Name::from_ascii(fqdn(host)).expect("valid test root name"),
                    addrs: vec![*ip],
                })
                .collect(),
        );
        self
    }

    /// Test-only: route direct queries for the given host names (with or
    /// without the trailing dot) to per-host mock ports instead of port 53.
    #[cfg(test)]
    fn with_port_map(mut self, map: std::collections::HashMap<String, u16>) -> Self {
        self.port_map = Some(
            map.into_iter()
                .map(|(host, port)| (host.trim_end_matches('.').to_ascii_lowercase(), port))
                .collect(),
        );
        self
    }

    /// Test-only: allow queries to loopback/private addresses (mock servers).
    #[cfg(test)]
    fn allowing_private_hosts(mut self) -> Self {
        self.allow_private_hosts = true;
        self
    }

    /// Test-only: fail every direct query to these addresses locally, before
    /// anything is sent, with the socket error `error` makes — "network
    /// unreachable" is what an IPv4 server address gives on an IPv6-only
    /// host, "address family not supported" what an IPv6 one gives when the
    /// kernel has IPv6 disabled.
    #[cfg(test)]
    fn with_unroutable(mut self, addrs: &[IpAddr], error: fn() -> std::io::Error) -> Self {
        self.unroutable.extend(addrs.iter().map(|&ip| (ip, error)));
        self
    }

    #[cfg(test)]
    fn recursive_upstream(&self) -> Option<(IpAddr, u16)> {
        self.recursive_upstream
    }

    #[cfg(not(test))]
    fn recursive_upstream(&self) -> Option<(IpAddr, u16)> {
        None
    }

    #[cfg(test)]
    fn allow_private(&self) -> bool {
        self.allow_private_hosts
    }

    #[cfg(not(test))]
    fn allow_private(&self) -> bool {
        false
    }

    /// The servers the walk starts from: the root hints, or the test seam's
    /// override.
    #[cfg(test)]
    fn root_servers(&self) -> Vec<NsCandidate> {
        self.root_hints.clone().unwrap_or_else(root_hints)
    }

    #[cfg(not(test))]
    fn root_servers(&self) -> Vec<NsCandidate> {
        root_hints()
    }

    /// Port used for a direct query to `host`. Always 53 in production; the
    /// `#[cfg(test)]` port map lets each mock server bind its own ephemeral
    /// loopback port.
    #[cfg(test)]
    fn direct_port(&self, host: &Name) -> u16 {
        let key = name_text(host);
        self.port_map
            .as_ref()
            .and_then(|map| map.get(key.trim_end_matches('.')).copied())
            .unwrap_or(53)
    }

    #[cfg(not(test))]
    fn direct_port(&self, _host: &Name) -> u16 {
        53
    }

    /// The local routing failure the `#[cfg(test)]` seam simulates for `ip`,
    /// if any. Never one in production: there the socket reports it.
    #[cfg(test)]
    fn simulated_no_route(&self, ip: IpAddr) -> Option<NetError> {
        self.unroutable
            .iter()
            .find(|(addr, _)| *addr == ip)
            .map(|(_, error)| NetError::from(error()))
    }

    #[cfg(not(test))]
    fn simulated_no_route(&self, _ip: IpAddr) -> Option<NetError> {
        None
    }

    /// Traces the resolution of `name` from the root servers down.
    ///
    /// Each hop asks one server of the current zone directly, with recursion
    /// disabled, and follows its referral to the next zone, until a server
    /// answers (a CNAME is reported, not chased), returns NXDOMAIN or NODATA,
    /// or the walk fails. A server that does not respond, returns an error
    /// RCODE or gives a lame server's empty non-authoritative reply is passed
    /// over for the zone's next one. A referral must lead toward `name`; an
    /// upward or sideways one is passed over the same way. Server addresses
    /// come from the root hints, the referral's glue, or a recursive lookup
    /// for glueless nameservers, and each one is refused when it is private
    /// or reserved.
    /// Up to 16 delegation levels are walked and up to 3 servers asked per
    /// level, each query and glueless lookup under the configured DNS
    /// timeout, and the whole walk under six times that timeout: a walk that
    /// runs out of time returns the hops so far with an error.
    ///
    /// # Arguments
    /// * `name` - The name to trace, prepared exactly as
    ///   [`DnsResolver::query`](crate::dns::DnsResolver::query) prepares it
    ///   (`www.` is kept, a leading `*` label is accepted, SRV needs the
    ///   `_service._proto.name` form, and a PTR query may name an IP literal)
    /// * `record_type` - The type to ask for: any single type (not `ANY`)
    ///
    /// # Returns
    /// * `Ok(DnsTrace)` - the hops walked; a walk that stopped before a final
    ///   response carries the reason in [`DnsTrace::error`]
    /// * `Err(SeerError)` - invalid input, `ANY`, or no root server answered
    #[instrument(skip(self), fields(name = %name, record_type = %record_type))]
    pub async fn trace(&self, name: &str, record_type: RecordType) -> Result<DnsTrace> {
        let qtype = trace_wire_type(record_type)?;
        let (name, qname) = query_target(name, record_type)?;

        let mut zone = Name::root();
        let mut servers = self.root_servers();
        let mut hops: Vec<TraceHop> = Vec::new();
        let mut error = None;
        // One deadline for the whole walk: each level is bounded on its own,
        // but the levels run one after another.
        let budget = self.timeout.saturating_mul(TRACE_BUDGET_TIMEOUTS);
        let started = Instant::now();

        loop {
            let remaining = budget.saturating_sub(started.elapsed());
            let level = self.ask_level(&zone, &servers, &qname, qtype);
            let Ok(outcome) = tokio::time::timeout(remaining, level).await else {
                let why = format!(
                    "gave up after {budget:?} without a final response, while asking the \
                     nameservers of {}",
                    name_text(&zone)
                );
                if hops.is_empty() {
                    return Err(SeerError::DnsError(format!(
                        "trace of {name} failed: {why}"
                    )));
                }
                error = Some(why);
                break;
            };
            let (hop, step) = match outcome {
                LevelOutcome::Answered { hop, step } => (hop, step),
                LevelOutcome::Failed { final_hop, reason } => {
                    let why = format!(
                        "no nameserver for {} gave a usable response: {}",
                        name_text(&zone),
                        reason
                    );
                    match final_hop {
                        Some(hop) => hops.push(hop),
                        // Without one root response there is nothing to trace.
                        None if hops.is_empty() => {
                            return Err(SeerError::DnsError(format!(
                                "trace of {name} failed: {why}"
                            )))
                        }
                        None => {}
                    }
                    error = Some(why);
                    break;
                }
            };

            // `ask_level` accepts only a referral inside the bailiwick.
            let referral = match step {
                Step::Final => {
                    hops.push(hop);
                    break;
                }
                Step::Referral(referral) => referral,
            };
            hops.push(hop);
            if hops.len() >= MAX_HOPS {
                error = Some(format!(
                    "gave up after {MAX_HOPS} delegation levels without a final response"
                ));
                break;
            }
            zone = referral.zone;
            servers = referral.servers;
        }

        let (status, answers) = match hops.last() {
            Some(last) => (last.status, last.answers.clone()),
            // Unreachable: a walk that recorded no hop returned early above.
            None => {
                return Err(SeerError::DnsError(format!(
                    "trace of {name} produced no response"
                )))
            }
        };
        Ok(DnsTrace {
            name,
            record_type,
            hops,
            status,
            answers,
            error,
        })
    }

    /// Asks the servers of `zone` in turn until one gives a usable response
    /// (a final one or a referral), recording every skipped or failed server.
    async fn ask_level(
        &self,
        zone: &Name,
        servers: &[NsCandidate],
        qname: &Name,
        qtype: HickoryRecordType,
    ) -> LevelOutcome {
        let (picks, mut failures) = plan_servers(servers, self.allow_private());
        let mut queried = 0;
        let mut resolved = 0;
        // The last unusable response (an error RCODE or a lame reply), and
        // the index of its own note in `failures`: it becomes the final hop
        // if no server does better.
        let mut unusable_hop: Option<(TraceHop, usize)> = None;

        for pick in picks {
            if queried == MAX_SERVERS_PER_LEVEL {
                break;
            }
            let (host, addrs) = match pick {
                ServerPick::Addrs(host, addrs) => (host, addrs),
                ServerPick::Glueless(host) => {
                    // Glueless picks come last, so none remain to try.
                    if resolved == MAX_GLUELESS_PER_LEVEL {
                        break;
                    }
                    resolved += 1;
                    let (addrs, notes) = self.resolve_glueless(&host).await;
                    failures.extend(notes);
                    (host, addrs)
                }
            };
            let Some((ip, elapsed, result)) = self
                .ask_server(&host, &addrs, qname, qtype, &mut failures)
                .await
            else {
                continue;
            };
            queried += 1;
            match result {
                Ok(response) => {
                    let mut hop = hop_from_response(zone, &host, ip, elapsed, &response);
                    let reason = match classify_response(&response, zone) {
                        Ok(Step::Referral(referral)) => {
                            hop.referral_zone = Some(name_text(&referral.zone));
                            hop.referral = referral
                                .servers
                                .iter()
                                .map(|s| name_text(&s.host))
                                .collect();
                            // A referral off the path to the name — one lame
                            // server's upward or sideways pointer — is as
                            // unusable as a lame reply: the next server of
                            // the zone may still refer correctly.
                            match check_bailiwick(zone, &referral.zone, qname) {
                                Ok(()) => {
                                    hop.failed_servers = failures;
                                    let step = Step::Referral(referral);
                                    return LevelOutcome::Answered { hop, step };
                                }
                                Err(fault) => format!(
                                    "referred {fault} to {} (not toward the name)",
                                    name_text(&referral.zone)
                                ),
                            }
                        }
                        Ok(step) => {
                            hop.failed_servers = failures;
                            return LevelOutcome::Answered { hop, step };
                        }
                        Err(reason) => reason,
                    };
                    unusable_hop = Some((hop, failures.len()));
                    failures.push(server_note(&host, ip, &reason));
                }
                Err(e) => failures.push(server_note(&host, ip, &transport_reason(&e))),
            }
        }

        let reason = if failures.is_empty() {
            "no nameserver address to query".to_string()
        } else {
            failures.join("; ")
        };
        let final_hop = unusable_hop.map(|(mut hop, own_note)| {
            failures.remove(own_note);
            hop.failed_servers = failures;
            hop
        });
        LevelOutcome::Failed { final_hop, reason }
    }

    /// Queries one server on its addresses in turn until a query leaves this
    /// host: an address with no local route fails at once, is noted in
    /// `failures`, and the next one is tried. Returns the address queried,
    /// the round-trip time and the exchange's result, or `None` when no
    /// address could be reached.
    async fn ask_server(
        &self,
        host: &Name,
        addrs: &[IpAddr],
        qname: &Name,
        qtype: HickoryRecordType,
        failures: &mut Vec<String>,
    ) -> Option<(IpAddr, Duration, std::result::Result<Message, NetError>)> {
        for &ip in addrs {
            debug!(server = %name_text(host), %ip, "trace: querying");
            let started = Instant::now();
            match self.exchange(host, ip, qname, qtype).await {
                Err(e) if is_no_route(&e) => {
                    failures.push(server_note(host, ip, &transport_reason(&e)));
                }
                result => return Some((ip, started.elapsed(), result)),
            }
        }
        None
    }

    /// Resolves a glueless nameserver's addresses through the recursive
    /// resolver, under the per-query timeout, vetting every address it
    /// returns. Returns the addresses to query, IPv4 first (none when the
    /// lookup failed or every address was refused), and notes for the failed
    /// lookup or the refused addresses.
    async fn resolve_glueless(&self, host: &Name) -> (Vec<IpAddr>, Vec<String>) {
        let text = name_text(host);
        // The resolver re-sends a query that timed out (`attempts`), so only
        // this deadline holds the lookup to one per-query timeout.
        let lookup = tokio::time::timeout(self.timeout, self.recursive.lookup_ip(text.as_str()))
            .await
            .unwrap_or(Err(NetError::Timeout));
        let ips: Vec<IpAddr> = match lookup {
            Ok(lookup) => lookup.iter().collect(),
            Err(e) if e.is_no_records_found() => Vec::new(),
            Err(e) => {
                return (
                    Vec::new(),
                    vec![format!(
                        "{text}: glueless nameserver lookup failed: {}",
                        transport_reason(&e)
                    )],
                )
            }
        };
        let (usable, refused) = partition_reserved(&ips, self.allow_private());
        let mut notes: Vec<String> = refused
            .iter()
            .map(|(ip, reason)| server_note(host, *ip, &format!("refused, {reason}")))
            .collect();
        if usable.is_empty() && notes.is_empty() {
            notes.push(format!("{text}: glueless nameserver has no address"));
        }
        let mut usable = usable;
        crate::net::ipv4_first(&mut usable, |ip| *ip);
        (usable, notes)
    }

    /// Sends one non-recursive query to `ip` and returns the response as the
    /// server sent it (see [`Transport::exchange`]): over UDP, then once more
    /// over TCP when the UDP reply is truncated, the whole exchange under one
    /// per-query deadline.
    async fn exchange(
        &self,
        host: &Name,
        ip: IpAddr,
        qname: &Name,
        qtype: HickoryRecordType,
    ) -> std::result::Result<Message, NetError> {
        if let Some(no_route) = self.simulated_no_route(ip) {
            return Err(no_route);
        }
        let mut udp = ConnectionConfig::udp();
        udp.port = self.direct_port(host);
        // Delegation data must come from each server's own authority, not
        // from recursion or a forwarder's cache.
        let request = self.transport.request(qname.clone(), qtype, false);
        self.transport.exchange(ip, &udp, &request).await
    }
}

/// A nameserver of the zone being asked, and the addresses known for it
/// (glue or root hint). No addresses means glueless.
#[derive(Debug, Clone, PartialEq)]
struct NsCandidate {
    host: Name,
    addrs: Vec<IpAddr>,
}

/// A referral: the child zone and its nameservers (sorted by name).
#[derive(Debug, PartialEq)]
struct Referral {
    zone: Name,
    servers: Vec<NsCandidate>,
}

/// What a usable response means for the walk.
#[derive(Debug, PartialEq)]
enum Step {
    /// A final response: an answer, NXDOMAIN, or NODATA.
    Final,
    /// A referral to follow (once its bailiwick is checked).
    Referral(Referral),
}

/// The outcome of asking one delegation level.
enum LevelOutcome {
    /// A server gave a usable response: a final one or a referral.
    Answered { hop: TraceHop, step: Step },
    /// No server did. `final_hop` is the last unusable response (an error
    /// RCODE or a lame reply), if any server responded at all; `reason`
    /// lists every failure.
    Failed {
        final_hop: Option<TraceHop>,
        reason: String,
    },
}

/// Where to send a level's queries, in order.
#[derive(Debug, PartialEq)]
enum ServerPick {
    /// A server with vetted addresses (glue or root hints), IPv4 first.
    Addrs(Name, Vec<IpAddr>),
    /// A glueless server, whose address must be looked up first.
    Glueless(Name),
}

/// Why a referral was refused.
#[derive(Debug, Clone, Copy, PartialEq)]
enum ReferralFault {
    /// The referred zone is the current zone or one of its ancestors.
    Upward,
    /// The referred zone is not on the path from the current zone to the
    /// query name.
    Sideways,
}

impl std::fmt::Display for ReferralFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ReferralFault::Upward => "upward",
            ReferralFault::Sideways => "sideways",
        })
    }
}

/// The root hints as query candidates.
///
/// The `expect`s are invariants over literals, like a compiled regex:
/// `root_hints_are_complete_and_public` parses every entry.
fn root_hints() -> Vec<NsCandidate> {
    ROOT_SERVERS
        .iter()
        .map(|(host, v4, v6)| NsCandidate {
            host: Name::from_ascii(host).expect("root hint names are valid"),
            addrs: [v4, v6]
                .iter()
                .map(|addr| addr.parse().expect("root hint addresses are valid"))
                .collect(),
        })
        .collect()
}

/// The wire type a trace asks for: that of any single type. ANY — the one
/// type without a wire type — is a fan-out over several queries that no
/// single walk can follow.
fn trace_wire_type(record_type: RecordType) -> Result<HickoryRecordType> {
    wire_type(record_type).ok_or_else(|| {
        SeerError::InvalidInput(
            "trace needs a single record type; ANY is a fan-out over several queries".to_string(),
        )
    })
}

/// The query name, prepared by the resolver's own steps (`prepare_query`,
/// then `wire_query_name`'s SRV and PTR rules) so a trace asks for — and
/// reports — exactly the name `DnsResolver::query` would. Returned as
/// reported (no trailing dot) and as the wire name; a PTR query for an IP
/// literal is its reverse-DNS name.
fn query_target(name: &str, record_type: RecordType) -> Result<(String, Name)> {
    let reported = wire_query_name(&prepare_query(name, record_type)?, record_type)?;
    let qname = Name::from_ascii(fqdn(&reported))
        .map_err(|e| SeerError::InvalidDomain(format!("{reported}: {e}")))?;
    Ok((reported, qname))
}

/// Orders a level's servers for querying — every server with a known
/// address first, then the glueless ones — and vets every known address,
/// keeping a server's usable ones IPv4 first. Returns the picks and a note
/// per refused address; a server whose addresses are all refused is dropped
/// rather than looked up again, since the zone itself pointed it at
/// reserved space.
fn plan_servers(servers: &[NsCandidate], allow_private: bool) -> (Vec<ServerPick>, Vec<String>) {
    let mut picks = Vec::new();
    let mut glueless = Vec::new();
    let mut notes = Vec::new();
    for server in servers {
        if server.addrs.is_empty() {
            glueless.push(ServerPick::Glueless(server.host.clone()));
            continue;
        }
        let (usable, refused) = partition_reserved(&server.addrs, allow_private);
        notes.extend(
            refused
                .iter()
                .map(|(ip, reason)| server_note(&server.host, *ip, &format!("refused, {reason}"))),
        );
        if !usable.is_empty() {
            let mut usable = usable;
            crate::net::ipv4_first(&mut usable, |ip| *ip);
            picks.push(ServerPick::Addrs(server.host.clone(), usable));
        }
    }
    picks.extend(glueless);
    (picks, notes)
}

/// Classifies a server's response for the walk, or says why it is unusable.
///
/// Any answer, an authoritative response or an SOA in AUTHORITY is final —
/// an answer, NXDOMAIN or NODATA (a referral never carries the AA bit, and a
/// negative answer carries the zone's SOA, RFC 2308); otherwise NS records
/// in AUTHORITY are a referral. An error RCODE is unusable, and so is what
/// remains — AA clear, no answer, no SOA, no referral: a lame server's
/// reply, which proves nothing about the name, so the zone's next server is
/// asked.
fn classify_response(response: &Message, zone: &Name) -> std::result::Result<Step, String> {
    let code = response.metadata.response_code;
    if !matches!(code, ResponseCode::NoError | ResponseCode::NXDomain) {
        return Err(DnsStatus::from(code).to_string());
    }
    if !response.answers.is_empty()
        || response.metadata.authoritative
        || response
            .authorities
            .iter()
            .any(|record| record.record_type() == HickoryRecordType::SOA)
    {
        return Ok(Step::Final);
    }
    if code == ResponseCode::NXDomain {
        return Err("non-authoritative NXDOMAIN without an SOA".to_string());
    }
    extract_referral(response, zone)
        .map(Step::Referral)
        .ok_or_else(|| "empty non-authoritative response (no answer, referral or SOA)".to_string())
}

/// Reads a referral from AUTHORITY: the child zone is the owner of the
/// first NS record, and its nameservers are every NS target under that
/// owner, deduplicated and sorted by name. Glue is taken from ADDITIONAL for
/// NS names inside `zone` (the responding server's own zone) only — glue for
/// a name elsewhere is not the server's to vouch for, so such a nameserver
/// is treated as glueless, as a resolver would.
fn extract_referral(response: &Message, zone: &Name) -> Option<Referral> {
    let child = response
        .authorities
        .iter()
        .find(|record| matches!(record.data, HickoryRData::NS(_)))?
        .name
        .to_lowercase();
    let targets: BTreeMap<String, Name> = response
        .authorities
        .iter()
        .filter(|record| record.name == child)
        .filter_map(|record| match &record.data {
            HickoryRData::NS(ns) => {
                let host = ns.0.to_lowercase();
                Some((name_text(&host), host))
            }
            _ => None,
        })
        .collect();
    let servers = targets
        .into_values()
        .map(|host| {
            let mut addrs: Vec<IpAddr> = Vec::new();
            if zone.zone_of(&host) {
                for record in response.additionals.iter().filter(|r| r.name == host) {
                    let ip = match &record.data {
                        HickoryRData::A(a) => IpAddr::V4(a.0),
                        HickoryRData::AAAA(aaaa) => IpAddr::V6(aaaa.0),
                        _ => continue,
                    };
                    if !addrs.contains(&ip) {
                        addrs.push(ip);
                    }
                }
            }
            NsCandidate { host, addrs }
        })
        .collect();
    Some(Referral {
        zone: child,
        servers,
    })
}

/// Checks a referral from `zone` to `child` against the bailiwick rule: the
/// child must lie strictly below `zone` (anything else could loop) and at or
/// above `qname` (anything else leads away from the answer).
fn check_bailiwick(
    zone: &Name,
    child: &Name,
    qname: &Name,
) -> std::result::Result<(), ReferralFault> {
    if child.zone_of(zone) {
        return Err(ReferralFault::Upward);
    }
    if !zone.zone_of(child) || !child.zone_of(qname) {
        return Err(ReferralFault::Sideways);
    }
    Ok(())
}

/// Builds a hop from a server's response (referral fields are filled in by
/// the caller once the response is classified).
fn hop_from_response(
    zone: &Name,
    host: &Name,
    ip: IpAddr,
    elapsed: Duration,
    response: &Message,
) -> TraceHop {
    TraceHop {
        zone: name_text(zone),
        server: name_text(host),
        address: ip.to_string(),
        query_time_ms: duration_ms(elapsed),
        status: DnsStatus::from(response.metadata.response_code),
        authoritative: response.metadata.authoritative,
        referral_zone: None,
        referral: Vec::new(),
        answers: response.answers.iter().filter_map(to_dns_record).collect(),
        failed_servers: Vec::new(),
    }
}

/// A `failed_servers` entry: `"host (ip): reason"`.
fn server_note(host: &Name, ip: IpAddr, reason: &str) -> String {
    format!("{} ({}): {}", name_text(host), ip, reason)
}

/// True when an exchange failed before its query left this host: the
/// kernel had no route to the server, or no socket of its address family
/// (see `delegation::is_local_no_route`).
fn is_no_route(err: &NetError) -> bool {
    matches!(err, NetError::Io(io) if is_local_no_route(io))
}

/// A name as the trace reports zones and servers: fully qualified,
/// lowercase ASCII (A-labels); the root is `"."`.
fn name_text(name: &Name) -> String {
    name.to_ascii().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    //! Hermetic tests: every server of a scenario (each zone's nameserver,
    //! and the recursive resolver for glueless names) is a loopback mock on
    //! its own ephemeral port from the shared [`crate::dns::test_support`]
    //! fixture, reached through the `#[cfg(test)]` seams (`with_root_hints`,
    //! `with_port_map`, `allowing_private_hosts`, `with_recursive_upstream`).

    use std::collections::HashMap;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::{Arc, Mutex};

    use hickory_resolver::proto::op::OpCode;
    use hickory_resolver::proto::rr::rdata as wire;
    use hickory_resolver::proto::rr::Record;

    use super::*;
    use crate::dns::delegation::ADDRESS_FAMILY_UNSUPPORTED;
    use crate::dns::records::RecordData;
    use crate::dns::test_support::{
        a_rdata, cname_rdata, fq_name, record, soa_rdata, spawn_mock_dns, spawn_mock_dns_fn,
        spawn_mock_dns_fn_with_tcp, MockMode, MockReply,
    };

    const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    /// The local failure an IPv4 address gives on an IPv6-only host.
    fn network_unreachable() -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::NetworkUnreachable,
            "Network is unreachable",
        )
    }

    /// The local failure an IPv6 address gives when the kernel has IPv6
    /// disabled: EAFNOSUPPORT, by its raw OS code, as the socket call
    /// reports it.
    fn address_family_unsupported() -> std::io::Error {
        let code = ADDRESS_FAMILY_UNSUPPORTED.expect("a Unix or Windows target");
        std::io::Error::from_raw_os_error(code)
    }

    // --- pure helpers ----------------------------------------------------

    #[test]
    fn root_hints_are_complete_and_public() {
        let hints = root_hints();
        assert_eq!(hints.len(), 13);
        // One entry per root server, a through m.
        for (letter, hint) in ('a'..='m').zip(&hints) {
            assert_eq!(name_text(&hint.host), format!("{letter}.root-servers.net."));
            assert_eq!(hint.addrs.len(), 2);
            assert!(hint.addrs[0].is_ipv4() && hint.addrs[1].is_ipv6());
            // The production vetting must never refuse a root server.
            let (usable, refused) = partition_reserved(&hint.addrs, false);
            assert_eq!(usable, hint.addrs);
            assert!(refused.is_empty(), "{refused:?}");
        }
    }

    #[test]
    fn name_text_is_fully_qualified_lowercase_ascii() {
        assert_eq!(name_text(&Name::root()), ".");
        assert_eq!(name_text(&fq_name("Example.COM")), "example.com.");
        assert_eq!(
            name_text(&Name::from_utf8("münchen.de.").unwrap()),
            "xn--mnchen-3ya.de."
        );
    }

    #[test]
    fn bailiwick_accepts_only_strict_descendants_on_the_path() {
        let qname = fq_name("www.example.com");
        // Root → com → example.com: each step descends toward the name.
        assert_eq!(
            check_bailiwick(&Name::root(), &fq_name("com"), &qname),
            Ok(())
        );
        assert_eq!(
            check_bailiwick(&fq_name("com"), &fq_name("example.com"), &qname),
            Ok(())
        );
        // A zone cut at the name itself is on the path.
        assert_eq!(
            check_bailiwick(&fq_name("example.com"), &fq_name("www.example.com"), &qname),
            Ok(())
        );
        // Skipping levels is fine (a parent may serve several cuts).
        assert_eq!(
            check_bailiwick(&Name::root(), &fq_name("example.com"), &qname),
            Ok(())
        );
        // Case differences are not a new zone.
        assert_eq!(
            check_bailiwick(&fq_name("com"), &fq_name("EXAMPLE.com"), &qname),
            Ok(())
        );

        // Back to the root, to the same zone, or to an ancestor: upward.
        assert_eq!(
            check_bailiwick(&fq_name("com"), &Name::root(), &qname),
            Err(ReferralFault::Upward)
        );
        assert_eq!(
            check_bailiwick(&fq_name("com"), &fq_name("com"), &qname),
            Err(ReferralFault::Upward)
        );
        assert_eq!(
            check_bailiwick(&fq_name("example.com"), &fq_name("com"), &qname),
            Err(ReferralFault::Upward)
        );
        // Below the zone but off the path, or outside the zone: sideways.
        assert_eq!(
            check_bailiwick(&fq_name("com"), &fq_name("other.com"), &qname),
            Err(ReferralFault::Sideways)
        );
        assert_eq!(
            check_bailiwick(&fq_name("com"), &fq_name("example.net"), &qname),
            Err(ReferralFault::Sideways)
        );
        // Below the query name is past the answer.
        assert_eq!(
            check_bailiwick(
                &fq_name("example.com"),
                &fq_name("a.www.example.com"),
                &qname
            ),
            Err(ReferralFault::Sideways)
        );
    }

    fn message() -> Message {
        Message::response(1, OpCode::Query)
    }

    fn ns(owner: &str, target: &str) -> Record {
        record(owner, 300, HickoryRData::NS(wire::NS(fq_name(target))))
    }

    fn a(owner: &str, ip: Ipv4Addr) -> Record {
        record(owner, 300, a_rdata(ip))
    }

    fn aaaa(owner: &str, ip: Ipv6Addr) -> Record {
        record(owner, 300, HickoryRData::AAAA(wire::AAAA(ip)))
    }

    #[test]
    fn referral_extraction_reads_ns_and_in_bailiwick_glue() {
        let mut response = message();
        // Out of order and mixed case, with a duplicate: sorted and deduped.
        response.add_authority(ns("Example.COM", "ns2.example.com"));
        response.add_authority(ns("example.com", "NS1.example.com"));
        response.add_authority(ns("example.com", "ns1.example.com"));
        response.add_authority(ns("example.com", "ns.dns-host.net"));
        // An NS record for another owner is not part of this referral.
        response.add_authority(ns("other.com", "ns.other.com"));
        let v4 = Ipv4Addr::new(192, 0, 2, 1);
        let v6 = "2001:db8::1".parse().unwrap();
        response.add_additional(aaaa("ns1.example.com", v6));
        response.add_additional(a("ns1.example.com", v4));
        response.add_additional(a("ns1.example.com", v4));
        // Glue for a name outside the responding server's zone (`com`) is
        // not trusted: that nameserver counts as glueless.
        response.add_additional(a("ns.dns-host.net", Ipv4Addr::new(198, 51, 100, 7)));
        // Additional records for names that are not NS targets are ignored.
        response.add_additional(a("unrelated.example.com", v4));

        let referral = extract_referral(&response, &fq_name("com")).expect("a referral");
        assert_eq!(referral.zone, fq_name("example.com"));
        assert_eq!(name_text(&referral.zone), "example.com.");
        let servers: Vec<(String, Vec<IpAddr>)> = referral
            .servers
            .iter()
            .map(|s| (name_text(&s.host), s.addrs.clone()))
            .collect();
        assert_eq!(
            servers,
            vec![
                ("ns.dns-host.net.".to_string(), vec![]),
                (
                    "ns1.example.com.".to_string(),
                    vec![IpAddr::V6(v6), IpAddr::V4(v4)]
                ),
                ("ns2.example.com.".to_string(), vec![]),
            ]
        );
        // The root may vouch for any glue.
        let from_root = extract_referral(&response, &Name::root()).expect("a referral");
        assert_eq!(from_root.servers[0].addrs.len(), 1);

        // No NS in AUTHORITY: no referral.
        assert_eq!(extract_referral(&message(), &fq_name("com")), None);
    }

    #[test]
    fn classification_separates_answers_negatives_referrals_and_lame_replies() {
        let zone = fq_name("com");
        let mut referral = message();
        referral.add_authority(ns("example.com", "ns1.example.com"));
        assert!(matches!(
            classify_response(&referral, &zone),
            Ok(Step::Referral(_))
        ));

        // The same NS set with the AA bit is an authoritative NODATA.
        let mut authoritative = referral.clone();
        authoritative.metadata.authoritative = true;
        assert_eq!(classify_response(&authoritative, &zone), Ok(Step::Final));

        // An SOA in AUTHORITY is a negative answer, NS records or not.
        let mut nodata = referral.clone();
        nodata.add_authority(record("com", 300, soa_rdata("com")));
        assert_eq!(classify_response(&nodata, &zone), Ok(Step::Final));
        let mut nxdomain = nodata.clone();
        nxdomain.metadata.response_code = ResponseCode::NXDomain;
        assert_eq!(classify_response(&nxdomain, &zone), Ok(Step::Final));
        // An authoritative NXDOMAIN is final even without its SOA.
        let mut aa_nxdomain = message();
        aa_nxdomain.metadata.authoritative = true;
        aa_nxdomain.metadata.response_code = ResponseCode::NXDomain;
        assert_eq!(classify_response(&aa_nxdomain, &zone), Ok(Step::Final));

        // Any answer is final, authoritative or not (a CNAME included).
        let mut answer = referral.clone();
        answer.add_answer(record("www.example.com", 300, cname_rdata("edge.cdn.net")));
        assert_eq!(classify_response(&answer, &zone), Ok(Step::Final));

        // An error RCODE is unusable, whatever it carries.
        let mut servfail = answer;
        servfail.metadata.response_code = ResponseCode::ServFail;
        assert_eq!(
            classify_response(&servfail, &zone),
            Err("SERVFAIL".to_string())
        );

        // Nothing at all from a server that is not authoritative: a lame
        // reply, not NODATA — it proves nothing about the name.
        let lame = classify_response(&message(), &zone).expect_err("a lame reply");
        assert!(lame.contains("empty non-authoritative"), "{lame}");
        // Nor is a non-authoritative NXDOMAIN without the zone's SOA a
        // negative answer, even beside NS records.
        let mut bare_nxdomain = referral;
        bare_nxdomain.metadata.response_code = ResponseCode::NXDomain;
        let lame = classify_response(&bare_nxdomain, &zone).expect_err("a lame reply");
        assert!(lame.contains("NXDOMAIN without an SOA"), "{lame}");
    }

    #[test]
    fn server_plan_orders_glued_first_prefers_ipv4_and_refuses_reserved() {
        let public_v4: IpAddr = "192.5.6.30".parse().unwrap();
        let public_v6: IpAddr = "2001:503:a83e::2:30".parse().unwrap();
        let private: IpAddr = "10.0.0.53".parse().unwrap();
        let metadata: IpAddr = "169.254.169.254".parse().unwrap();
        let servers = vec![
            NsCandidate {
                host: fq_name("glueless.example.net"),
                addrs: vec![],
            },
            // AAAA listed first: the IPv4 address is still the one asked.
            NsCandidate {
                host: fq_name("ns1.example.com"),
                addrs: vec![public_v6, public_v4],
            },
            // Reserved glue beside a public address: the public one is used
            // and the reserved one is noted.
            NsCandidate {
                host: fq_name("ns2.example.com"),
                addrs: vec![private, public_v6],
            },
            // Only reserved glue: dropped, not looked up again.
            NsCandidate {
                host: fq_name("ns3.example.com"),
                addrs: vec![metadata],
            },
        ];

        let (picks, notes) = plan_servers(&servers, false);
        assert_eq!(
            picks,
            vec![
                // Both addresses are kept, IPv4 first: the IPv6 one is the
                // fallback on a host with no IPv4 route.
                ServerPick::Addrs(fq_name("ns1.example.com"), vec![public_v4, public_v6]),
                ServerPick::Addrs(fq_name("ns2.example.com"), vec![public_v6]),
                ServerPick::Glueless(fq_name("glueless.example.net")),
            ]
        );
        assert_eq!(
            notes,
            vec![
                "ns2.example.com. (10.0.0.53): refused, private network (RFC 1918)",
                "ns3.example.com. (169.254.169.254): refused, cloud metadata endpoint (169.254.169.254)",
            ]
        );

        // The test seam's flag is the only way past the vetting.
        let (picks, notes) = plan_servers(&servers, true);
        assert!(picks.contains(&ServerPick::Addrs(
            fq_name("ns3.example.com"),
            vec![metadata]
        )));
        assert!(notes.is_empty());
    }

    #[test]
    fn query_target_follows_record_query_normalization() {
        // `www.` is kept and the name lowercased, as for every record query.
        let (name, qname) = query_target("WWW.Example.com", RecordType::A).unwrap();
        assert_eq!(name, "www.example.com");
        assert_eq!(qname, fq_name("www.example.com"));
        assert!(qname.is_fqdn());
        // A PTR query for an IP literal is named by the reverse-DNS name,
        // exactly as the resolver reports it.
        let (name, qname) = query_target("192.0.2.1", RecordType::PTR).unwrap();
        assert_eq!(name, "1.2.0.192.in-addr.arpa");
        assert_eq!(qname, fq_name("1.2.0.192.in-addr.arpa"));
        let (name, _) = query_target("2606:4700:4700::1111", RecordType::PTR).unwrap();
        assert_eq!(
            name,
            "1.1.1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.4.0.0.7.4.6.0.6.2.ip6.arpa"
        );
        // SRV keeps the resolver's `_service._proto.name` rule.
        assert!(query_target("_sip._tcp.example.com", RecordType::SRV).is_ok());
        assert!(matches!(
            query_target("example.com", RecordType::SRV),
            Err(SeerError::InvalidInput(_))
        ));
        assert!(query_target("not a name", RecordType::A).is_err());
    }

    #[test]
    fn query_target_applies_the_resolvers_srv_label_rule() {
        // `sip_x` passes the name normalizer but is no valid service label:
        // the trace refuses it exactly as `DnsResolver::query` does.
        let err = query_target("_sip_x._tcp.example.com", RecordType::SRV).unwrap_err();
        assert!(
            matches!(&err, SeerError::InvalidInput(m) if m.contains("invalid SRV service")),
            "{err:?}"
        );
    }

    #[test]
    fn any_is_not_traceable() {
        assert!(matches!(
            trace_wire_type(RecordType::ANY),
            Err(SeerError::InvalidInput(_))
        ));
        assert_eq!(
            trace_wire_type(RecordType::SRV).unwrap(),
            HickoryRecordType::SRV
        );
        assert_eq!(
            trace_wire_type(RecordType::MX).unwrap(),
            HickoryRecordType::MX
        );
    }

    #[test]
    fn trace_serializes_to_the_documented_shape() {
        let hop = TraceHop {
            zone: ".".to_string(),
            server: "a.root-servers.net.".to_string(),
            address: "198.41.0.4".to_string(),
            query_time_ms: 21,
            status: DnsStatus::NoError,
            authoritative: false,
            referral_zone: Some("com.".to_string()),
            referral: vec!["a.gtld-servers.net.".to_string()],
            answers: vec![],
            failed_servers: vec![],
        };
        let trace = DnsTrace {
            name: "www.example.com".to_string(),
            record_type: RecordType::A,
            hops: vec![hop],
            status: DnsStatus::NxDomain,
            answers: vec![],
            error: None,
        };
        let json = serde_json::to_value(&trace).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "name": "www.example.com",
                "record_type": "A",
                "hops": [{
                    "zone": ".",
                    "server": "a.root-servers.net.",
                    "address": "198.41.0.4",
                    "query_time_ms": 21,
                    "status": "NOERROR",
                    "authoritative": false,
                    "referral_zone": "com.",
                    "referral": ["a.gtld-servers.net."],
                    "answers": [],
                    "failed_servers": []
                }],
                "status": "NXDOMAIN",
                "answers": [],
                "error": null
            })
        );
        // And it reads back.
        let back: DnsTrace = serde_json::from_value(json).unwrap();
        assert_eq!(back.hops[0].referral_zone.as_deref(), Some("com."));
        assert_eq!(back.status, DnsStatus::NxDomain);
    }

    #[test]
    fn transport_reasons_are_short_and_name_local_routing_failures() {
        assert_eq!(transport_reason(&NetError::Timeout), "timed out");
        // An IPv6-only server asked from an IPv4-only host: the packet never
        // left, which the note must not blame on the server.
        let no_route = NetError::from(network_unreachable());
        assert!(is_no_route(&no_route));
        assert_eq!(
            transport_reason(&no_route),
            "no route from this host (Network is unreachable)"
        );
        // Nor when no socket of the server's address family can be opened
        // (IPv6 disabled in the kernel), whatever the OS calls it.
        let no_socket = NetError::from(address_family_unsupported());
        assert!(is_no_route(&no_socket));
        assert_eq!(
            transport_reason(&no_socket),
            format!("no route from this host ({})", address_family_unsupported())
        );
        let refused = NetError::from(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "refused",
        ));
        assert!(transport_reason(&refused).contains("refused"));
    }

    #[test]
    fn from_config_applies_dns_timeout() {
        let mut config = crate::config::SeerConfig::default();
        config.timeouts.dns_secs = 9;
        let tracer = DnsTracer::from_config(&config);
        assert_eq!(tracer.timeout, Duration::from_secs(9));
    }

    // --- end-to-end walks over loopback mocks ------------------------------

    /// A referral to `zone` served by the given nameservers, each glued to
    /// the loopback address.
    fn delegation(zone: &str, servers: &[&str]) -> MockReply {
        MockReply::Delegation {
            zone: zone.to_string(),
            servers: servers
                .iter()
                .map(|s| (s.to_string(), vec![LOOPBACK]))
                .collect(),
        }
    }

    /// A tracer over loopback mocks: `roots` are the root servers and
    /// `ports` maps every nameserver host to its mock.
    fn tracer(roots: &[&str], ports: &[(&str, u16)]) -> DnsTracer {
        let hints: Vec<(&str, IpAddr)> = roots.iter().map(|root| (*root, LOOPBACK)).collect();
        DnsTracer::new()
            .with_timeout(Duration::from_millis(500))
            .allowing_private_hosts()
            .with_root_hints(&hints)
            .with_port_map(
                ports
                    .iter()
                    .map(|(host, port)| (host.to_string(), *port))
                    .collect(),
            )
    }

    /// Root → `test` → `example.test`, whose server answers with `answer`.
    async fn three_level_tracer(answer: fn(&str) -> MockReply) -> DnsTracer {
        let root = spawn_mock_dns_fn(|_, _| delegation("test", &["ns1.nic.test"])).await;
        let tld = spawn_mock_dns_fn(|_, _| {
            delegation("example.test", &["ns2.example.test", "ns1.example.test"])
        })
        .await;
        let auth = spawn_mock_dns_fn(move |qname, _| answer(qname)).await;
        tracer(
            &["a.root.test"],
            &[
                ("a.root.test", root),
                ("ns1.nic.test", tld),
                ("ns1.example.test", auth),
                ("ns2.example.test", auth),
            ],
        )
    }

    #[tokio::test]
    async fn walks_root_tld_and_authoritative_server() {
        let tracer = three_level_tracer(|_| {
            MockReply::AuthoritativeAnswer(vec![a_rdata(Ipv4Addr::new(192, 0, 2, 10))])
        })
        .await;
        let trace = tracer
            .trace("WWW.example.test", RecordType::A)
            .await
            .unwrap();

        assert_eq!(trace.name, "www.example.test");
        assert_eq!(trace.record_type, RecordType::A);
        assert_eq!(trace.hops.len(), 3, "{trace:#?}");
        assert!(trace.error.is_none(), "{trace:#?}");

        let root = &trace.hops[0];
        assert_eq!(root.zone, ".");
        assert_eq!(root.server, "a.root.test.");
        assert_eq!(root.address, "127.0.0.1");
        assert_eq!(root.status, DnsStatus::NoError);
        assert!(!root.authoritative);
        assert_eq!(root.referral_zone.as_deref(), Some("test."));
        assert_eq!(root.referral, vec!["ns1.nic.test."]);
        assert!(root.answers.is_empty());

        let tld = &trace.hops[1];
        assert_eq!(tld.zone, "test.");
        assert_eq!(tld.server, "ns1.nic.test.");
        assert_eq!(tld.referral_zone.as_deref(), Some("example.test."));
        assert_eq!(tld.referral, vec!["ns1.example.test.", "ns2.example.test."]);

        let auth = &trace.hops[2];
        assert_eq!(auth.zone, "example.test.");
        // Sorted referral: ns1 is asked first.
        assert_eq!(auth.server, "ns1.example.test.");
        assert!(auth.authoritative);
        assert_eq!(auth.status, DnsStatus::NoError);
        assert_eq!(auth.referral_zone, None);
        assert!(auth.referral.is_empty());
        assert!(auth.failed_servers.is_empty());

        assert_eq!(trace.status, DnsStatus::NoError);
        assert_eq!(trace.answers.len(), 1);
        assert_eq!(trace.answers[0].name, "www.example.test");
        assert_eq!(trace.answers[0].record_type, RecordType::A);
        assert!(matches!(
            &trace.answers[0].data,
            RecordData::A { address } if address == "192.0.2.10"
        ));
    }

    #[tokio::test]
    async fn nxdomain_at_the_authoritative_level_ends_the_walk() {
        let tracer = three_level_tracer(|_| MockReply::AuthoritativeNxDomain("example.test")).await;
        let trace = tracer
            .trace("gone.example.test", RecordType::A)
            .await
            .unwrap();

        assert_eq!(trace.hops.len(), 3);
        assert_eq!(trace.status, DnsStatus::NxDomain);
        assert!(trace.answers.is_empty());
        assert!(trace.error.is_none(), "a negative answer is not an error");
        let last = &trace.hops[2];
        assert_eq!(last.status, DnsStatus::NxDomain);
        assert!(last.authoritative, "the AA bit survives a negative answer");
        assert_eq!(last.referral_zone, None);
    }

    #[tokio::test]
    async fn nodata_at_the_authoritative_level_ends_the_walk() {
        let tracer = three_level_tracer(|_| MockReply::AuthoritativeAnswer(vec![])).await;
        let trace = tracer
            .trace("www.example.test", RecordType::MX)
            .await
            .unwrap();

        assert_eq!(trace.hops.len(), 3);
        assert_eq!(trace.status, DnsStatus::NoError);
        assert!(trace.answers.is_empty());
        assert!(trace.hops[2].authoritative);
        assert!(trace.error.is_none());
    }

    #[tokio::test]
    async fn cname_answer_is_reported_not_chased() {
        let root = spawn_mock_dns_fn(|_, _| delegation("test", &["ns1.nic.test"])).await;
        let tld = spawn_mock_dns_fn(|_, _| delegation("example.test", &["ns1.example.test"])).await;
        let asked = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&asked);
        let auth = spawn_mock_dns_fn(move |qname, qtype| {
            log.lock().unwrap().push((qname.to_string(), qtype));
            MockReply::AuthoritativeAnswer(vec![cname_rdata("edge.cdn.test")])
        })
        .await;
        let trace = tracer(
            &["a.root.test"],
            &[
                ("a.root.test", root),
                ("ns1.nic.test", tld),
                ("ns1.example.test", auth),
            ],
        )
        .trace("www.example.test", RecordType::A)
        .await
        .unwrap();

        assert_eq!(trace.hops.len(), 3);
        assert!(trace.error.is_none());
        assert_eq!(trace.answers.len(), 1);
        let cname = &trace.answers[0];
        assert_eq!(cname.name, "www.example.test");
        assert_eq!(cname.record_type, RecordType::CNAME);
        assert!(matches!(
            &cname.data,
            RecordData::CNAME { target } if target == "edge.cdn.test."
        ));
        // The server was only ever asked the original question — the
        // target was never looked up (UDP retransmits may repeat it).
        let asked = asked.lock().unwrap();
        assert!(!asked.is_empty());
        assert!(
            asked
                .iter()
                .all(|q| *q == ("www.example.test".to_string(), HickoryRecordType::A)),
            "{asked:?}"
        );
    }

    #[tokio::test]
    async fn glueless_referral_is_resolved_through_the_recursive_resolver() {
        let root = spawn_mock_dns_fn(|_, _| delegation("test", &["ns1.nic.test"])).await;
        // `example.test` is served by a nameserver the referral gives no
        // glue for.
        let tld = spawn_mock_dns_fn(|_, _| MockReply::Delegation {
            zone: "example.test".to_string(),
            servers: vec![("ns.dns-host.test".to_string(), vec![])],
        })
        .await;
        let auth = spawn_mock_dns_fn(|_, _| {
            MockReply::AuthoritativeAnswer(vec![a_rdata(Ipv4Addr::new(192, 0, 2, 20))])
        })
        .await;
        let recursive = spawn_mock_dns_fn(|qname, qtype| match (qname, qtype) {
            ("ns.dns-host.test", HickoryRecordType::A) => {
                MockReply::Answer(vec![a_rdata(Ipv4Addr::LOCALHOST)])
            }
            _ => MockReply::NoData,
        })
        .await;
        let trace = tracer(
            &["a.root.test"],
            &[
                ("a.root.test", root),
                ("ns1.nic.test", tld),
                ("ns.dns-host.test", auth),
            ],
        )
        .with_recursive_upstream(LOOPBACK, recursive)
        .trace("www.example.test", RecordType::A)
        .await
        .unwrap();

        assert_eq!(trace.hops.len(), 3, "{trace:#?}");
        assert_eq!(trace.hops[1].referral, vec!["ns.dns-host.test."]);
        assert_eq!(trace.hops[2].server, "ns.dns-host.test.");
        assert_eq!(trace.hops[2].address, "127.0.0.1");
        assert_eq!(trace.answers.len(), 1);
        assert!(trace.error.is_none());
    }

    #[tokio::test]
    async fn unresolvable_glueless_nameserver_ends_the_walk_with_an_error() {
        let root = spawn_mock_dns_fn(|_, _| MockReply::Delegation {
            zone: "test".to_string(),
            servers: vec![("ns.nowhere.test".to_string(), vec![])],
        })
        .await;
        let recursive = spawn_mock_dns(MockMode::Nxdomain).await;
        let trace = tracer(&["a.root.test"], &[("a.root.test", root)])
            .with_recursive_upstream(LOOPBACK, recursive)
            .trace("www.example.test", RecordType::A)
            .await
            .unwrap();

        assert_eq!(trace.hops.len(), 1);
        let error = trace.error.expect("the walk must stop with an error");
        assert!(error.contains("test."), "{error}");
        assert!(error.contains("ns.nowhere.test."), "{error}");
    }

    #[tokio::test]
    async fn reserved_root_hints_are_refused_without_the_test_seam() {
        // Production vetting end to end: nothing may be sent to a loopback
        // server, so the walk has no root to start from.
        let asked = Arc::new(Mutex::new(0usize));
        let count = Arc::clone(&asked);
        let root = spawn_mock_dns_fn(move |_, _| {
            *count.lock().unwrap() += 1;
            MockReply::AuthoritativeAnswer(vec![])
        })
        .await;
        let err = DnsTracer::new()
            .with_timeout(Duration::from_millis(500))
            .with_root_hints(&[("a.root.test", LOOPBACK)])
            .with_port_map(HashMap::from([("a.root.test".to_string(), root)]))
            .trace("www.example.test", RecordType::A)
            .await
            .expect_err("a loopback root must be refused");
        assert!(matches!(err, SeerError::DnsError(_)), "{err:?}");
        assert!(err.to_string().contains("loopback"), "{err}");
        assert_eq!(*asked.lock().unwrap(), 0, "no query may reach the server");
    }

    #[tokio::test]
    async fn glueless_addresses_are_vetted_without_the_test_seam() {
        // Production vetting of what a glueless NS name resolves to. The
        // recursive upstream is a test seam the walk never sends a direct
        // query to; the addresses it returns come from the (attacker's) zone.
        let public_v4 = Ipv4Addr::new(9, 9, 9, 9);
        let public_v6: Ipv6Addr = "2620:fe::fe".parse().unwrap();
        let private = Ipv4Addr::new(10, 0, 0, 53);
        let recursive = spawn_mock_dns_fn(move |qname, qtype| match (qname, qtype) {
            ("ns.evil.test", HickoryRecordType::A) => MockReply::Answer(vec![
                a_rdata(private),
                a_rdata(Ipv4Addr::new(169, 254, 169, 254)),
            ]),
            ("ns.evil.test", HickoryRecordType::AAAA) => {
                MockReply::Answer(vec![HickoryRData::AAAA(wire::AAAA(Ipv6Addr::LOCALHOST))])
            }
            ("ns.mixed.test", HickoryRecordType::A) => {
                MockReply::Answer(vec![a_rdata(private), a_rdata(public_v4)])
            }
            ("ns.mixed.test", HickoryRecordType::AAAA) => {
                MockReply::Answer(vec![HickoryRData::AAAA(wire::AAAA(public_v6))])
            }
            _ => MockReply::NoData,
        })
        .await;
        let tracer = DnsTracer::new()
            .with_timeout(Duration::from_millis(500))
            .with_recursive_upstream(LOOPBACK, recursive);

        // Only reserved addresses: nothing to query, each refusal noted.
        let (addrs, mut notes) = tracer.resolve_glueless(&fq_name("ns.evil.test")).await;
        assert!(addrs.is_empty(), "{addrs:?}");
        notes.sort();
        assert_eq!(
            notes,
            vec![
                "ns.evil.test. (10.0.0.53): refused, private network (RFC 1918)",
                "ns.evil.test. (169.254.169.254): refused, cloud metadata endpoint (169.254.169.254)",
                "ns.evil.test. (::1): refused, IPv6 loopback (::1)",
            ]
        );

        // Reserved beside public: only the public ones are kept, IPv4 first.
        let (addrs, notes) = tracer.resolve_glueless(&fq_name("ns.mixed.test")).await;
        assert_eq!(addrs, vec![IpAddr::V4(public_v4), IpAddr::V6(public_v6)]);
        assert_eq!(
            notes,
            vec!["ns.mixed.test. (10.0.0.53): refused, private network (RFC 1918)"]
        );
    }

    #[tokio::test]
    async fn a_glueless_lookup_takes_at_most_one_timeout() {
        // The recursive resolver re-sends a query that timed out, so an
        // unanswered lookup took several timeouts; it must end within one.
        let recursive = spawn_mock_dns(MockMode::Ignore).await;
        let timeout = Duration::from_millis(300);
        let tracer = DnsTracer::new()
            .with_timeout(timeout)
            .with_recursive_upstream(LOOPBACK, recursive);

        let started = Instant::now();
        let (addrs, notes) = tracer.resolve_glueless(&fq_name("ns.dark.test")).await;
        let elapsed = started.elapsed();
        assert!(addrs.is_empty(), "{addrs:?}");
        assert_eq!(
            notes,
            vec!["ns.dark.test.: glueless nameserver lookup failed: timed out"]
        );
        assert!(elapsed < timeout * 2, "took {elapsed:?}");
    }

    #[tokio::test]
    async fn addresses_with_no_route_are_skipped_without_using_up_the_level() {
        // As on an IPv6-only host, where every IPv4 address fails locally at
        // once: no query left the host, so the server's next address is
        // tried, and the failure does not count toward the servers asked per
        // level (three here, before the fourth root answers).
        let unroutable: Vec<IpAddr> = (1..=4)
            .map(|i| IpAddr::V4(Ipv4Addr::new(192, 0, 2, i)))
            .collect();
        let first_glue = unroutable[3];
        let root = spawn_mock_dns_fn(move |_, _| MockReply::Delegation {
            zone: "example.test".to_string(),
            servers: vec![("ns1.example.test".to_string(), vec![first_glue, LOOPBACK])],
        })
        .await;
        let auth = spawn_mock_dns_fn(|_, _| {
            MockReply::AuthoritativeAnswer(vec![a_rdata(Ipv4Addr::new(192, 0, 2, 50))])
        })
        .await;
        let trace = DnsTracer::new()
            .with_timeout(Duration::from_millis(500))
            .allowing_private_hosts()
            .with_root_hints(&[
                ("a.root.test", unroutable[0]),
                ("b.root.test", unroutable[1]),
                ("c.root.test", unroutable[2]),
                ("d.root.test", LOOPBACK),
            ])
            .with_port_map(HashMap::from([
                ("d.root.test".to_string(), root),
                ("ns1.example.test".to_string(), auth),
            ]))
            .with_unroutable(&unroutable, network_unreachable)
            .trace("www.example.test", RecordType::A)
            .await
            .unwrap();

        assert!(trace.error.is_none(), "{trace:#?}");
        assert_eq!(trace.hops.len(), 2, "{trace:#?}");
        let no_route = "no route from this host (Network is unreachable)";
        let root = &trace.hops[0];
        assert_eq!(root.server, "d.root.test.");
        assert_eq!(
            root.failed_servers,
            vec![
                format!("a.root.test. (192.0.2.1): {no_route}"),
                format!("b.root.test. (192.0.2.2): {no_route}"),
                format!("c.root.test. (192.0.2.3): {no_route}"),
            ]
        );
        let auth = &trace.hops[1];
        assert_eq!(auth.server, "ns1.example.test.");
        assert_eq!(auth.address, "127.0.0.1", "the server's next address");
        assert_eq!(
            auth.failed_servers,
            vec![format!("ns1.example.test. (192.0.2.4): {no_route}")]
        );
        assert_eq!(trace.answers.len(), 1);
    }

    #[tokio::test]
    async fn ipv6_only_servers_without_local_ipv6_do_not_use_up_the_level() {
        // As on a host whose kernel has IPv6 disabled, where no IPv6 socket
        // can be opened (EAFNOSUPPORT): three IPv6-only roots fail locally
        // without sending anything, so none of them counts toward the three
        // servers asked per level, and the fourth root still answers.
        let v6_only: Vec<IpAddr> = (1..=3)
            .map(|i| IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i)))
            .collect();
        let root =
            spawn_mock_dns_fn(|_, _| delegation("example.test", &["ns1.example.test"])).await;
        let auth = spawn_mock_dns_fn(|_, _| {
            MockReply::AuthoritativeAnswer(vec![a_rdata(Ipv4Addr::new(192, 0, 2, 50))])
        })
        .await;
        let trace = DnsTracer::new()
            .with_timeout(Duration::from_millis(500))
            .allowing_private_hosts()
            .with_root_hints(&[
                ("a.root.test", v6_only[0]),
                ("b.root.test", v6_only[1]),
                ("c.root.test", v6_only[2]),
                ("d.root.test", LOOPBACK),
            ])
            .with_port_map(HashMap::from([
                ("d.root.test".to_string(), root),
                ("ns1.example.test".to_string(), auth),
            ]))
            .with_unroutable(&v6_only, address_family_unsupported)
            .trace("www.example.test", RecordType::A)
            .await
            .unwrap();

        assert!(trace.error.is_none(), "{trace:#?}");
        assert_eq!(trace.hops.len(), 2, "{trace:#?}");
        let no_socket = format!("no route from this host ({})", address_family_unsupported());
        let root = &trace.hops[0];
        assert_eq!(root.server, "d.root.test.");
        assert_eq!(
            root.failed_servers,
            vec![
                format!("a.root.test. (2001:db8::1): {no_socket}"),
                format!("b.root.test. (2001:db8::2): {no_socket}"),
                format!("c.root.test. (2001:db8::3): {no_socket}"),
            ]
        );
        assert_eq!(trace.answers.len(), 1);
    }

    #[tokio::test]
    async fn a_lame_servers_empty_reply_falls_back_to_the_next_server() {
        let root = spawn_mock_dns_fn(|_, _| {
            delegation("example.test", &["ns1.example.test", "ns2.example.test"])
        })
        .await;
        // ns1 is lame: NOERROR, AA clear, every section empty — not NODATA.
        let lame = spawn_mock_dns_fn(|_, _| MockReply::NoData).await;
        let auth = spawn_mock_dns_fn(|_, _| {
            MockReply::AuthoritativeAnswer(vec![a_rdata(Ipv4Addr::new(192, 0, 2, 60))])
        })
        .await;
        let trace = tracer(
            &["a.root.test"],
            &[
                ("a.root.test", root),
                ("ns1.example.test", lame),
                ("ns2.example.test", auth),
            ],
        )
        .trace("www.example.test", RecordType::A)
        .await
        .unwrap();

        assert!(trace.error.is_none(), "{trace:#?}");
        assert_eq!(trace.hops.len(), 2);
        let last = &trace.hops[1];
        assert_eq!(last.server, "ns2.example.test.");
        assert!(last.authoritative);
        assert_eq!(
            last.failed_servers,
            vec![
                "ns1.example.test. (127.0.0.1): empty non-authoritative response (no answer, referral or SOA)"
            ]
        );
        assert_eq!(trace.status, DnsStatus::NoError);
        assert_eq!(trace.answers.len(), 1);
    }

    #[tokio::test]
    async fn a_zone_of_lame_servers_is_an_error_not_a_negative_answer() {
        let root = spawn_mock_dns_fn(|_, _| {
            delegation("example.test", &["ns1.example.test", "ns2.example.test"])
        })
        .await;
        let empty = spawn_mock_dns_fn(|_, _| MockReply::NoData).await;
        // NXDOMAIN with AA clear and no SOA: no authority said so.
        let bare_nxdomain = spawn_mock_dns_fn(|_, _| MockReply::NxDomain).await;
        let trace = tracer(
            &["a.root.test"],
            &[
                ("a.root.test", root),
                ("ns1.example.test", empty),
                ("ns2.example.test", bare_nxdomain),
            ],
        )
        .trace("www.example.test", RecordType::A)
        .await
        .unwrap();

        assert_eq!(trace.hops.len(), 2);
        let last = &trace.hops[1];
        assert_eq!(last.server, "ns2.example.test.");
        assert_eq!(last.status, DnsStatus::NxDomain);
        assert_eq!(
            last.failed_servers,
            vec![
                "ns1.example.test. (127.0.0.1): empty non-authoritative response (no answer, referral or SOA)"
            ]
        );
        let error = trace
            .error
            .expect("a lame zone proves nothing about the name");
        assert!(error.contains("example.test."), "{error}");
        assert!(error.contains("NXDOMAIN without an SOA"), "{error}");
    }

    #[tokio::test]
    async fn upward_referral_from_every_server_stops_the_walk() {
        let root = spawn_mock_dns_fn(|_, _| delegation("test", &["ns1.nic.test"])).await;
        // The zone's only server is lame and sends the resolver back to the root.
        let tld = spawn_mock_dns_fn(|_, _| delegation(".", &["a.root.test"])).await;
        let trace = tracer(
            &["a.root.test"],
            &[("a.root.test", root), ("ns1.nic.test", tld)],
        )
        .trace("www.example.test", RecordType::A)
        .await
        .unwrap();

        assert_eq!(trace.hops.len(), 2);
        assert_eq!(trace.hops[1].referral_zone.as_deref(), Some("."));
        assert_eq!(trace.status, DnsStatus::NoError);
        assert!(trace.answers.is_empty());
        let error = trace.error.expect("an upward referral is an error");
        assert!(error.contains("upward"), "{error}");
        assert!(error.contains("ns1.nic.test."), "{error}");
    }

    /// Regression: one lame server's upward referral ended the trace,
    /// although the zone's next server would have referred correctly. It
    /// is passed over like any other unusable reply.
    #[tokio::test]
    async fn upward_referral_from_a_lame_server_asks_the_next() {
        let root =
            spawn_mock_dns_fn(|_, _| delegation("test", &["ns1.nic.test", "ns2.nic.test"])).await;
        let lame = spawn_mock_dns_fn(|_, _| delegation(".", &["a.root.test"])).await;
        let healthy =
            spawn_mock_dns_fn(|_, _| delegation("example.test", &["ns1.example.test"])).await;
        let auth =
            spawn_mock_dns_fn(|_, _| MockReply::AuthoritativeAnswer(vec![a_rdata([192, 0, 2, 1])]))
                .await;
        let trace = tracer(
            &["a.root.test"],
            &[
                ("a.root.test", root),
                ("ns1.nic.test", lame),
                ("ns2.nic.test", healthy),
                ("ns1.example.test", auth),
            ],
        )
        .trace("www.example.test", RecordType::A)
        .await
        .unwrap();

        assert!(trace.error.is_none(), "{:?}", trace.error);
        assert_eq!(trace.hops.len(), 3);
        let tld_hop = &trace.hops[1];
        assert_eq!(tld_hop.server, "ns2.nic.test.");
        assert_eq!(tld_hop.referral_zone.as_deref(), Some("example.test."));
        assert!(
            tld_hop
                .failed_servers
                .iter()
                .any(|f| f.starts_with("ns1.nic.test.") && f.contains("referred upward")),
            "{:?}",
            tld_hop.failed_servers
        );
        assert_eq!(trace.answers.len(), 1);
    }

    #[tokio::test]
    async fn sideways_referral_stops_the_walk() {
        let root = spawn_mock_dns_fn(|_, _| delegation("test", &["ns1.nic.test"])).await;
        let tld = spawn_mock_dns_fn(|_, _| delegation("other.test", &["ns1.other.test"])).await;
        let trace = tracer(
            &["a.root.test"],
            &[("a.root.test", root), ("ns1.nic.test", tld)],
        )
        .trace("www.example.test", RecordType::A)
        .await
        .unwrap();

        assert_eq!(trace.hops.len(), 2);
        assert_eq!(trace.hops[1].referral_zone.as_deref(), Some("other.test."));
        let error = trace.error.expect("a sideways referral is an error");
        assert!(error.contains("sideways"), "{error}");
    }

    #[tokio::test]
    async fn walk_gives_up_after_the_hop_limit() {
        // A 21-label name and one server that refers one label deeper on
        // every query: a legitimate-looking chain longer than MAX_HOPS.
        let labels: Vec<String> = (1..=20)
            .map(|i| format!("l{i}"))
            .chain(["test".into()])
            .collect();
        let qname = labels.join(".");
        let zone_at = |depth: usize| labels[labels.len() - depth..].join(".");
        let zones: Vec<String> = (1..=labels.len()).map(zone_at).collect();

        let mut depth = 0;
        let chain = zones.clone();
        let server = spawn_mock_dns_fn(move |_, _| {
            let zone = chain[depth.min(chain.len() - 1)].clone();
            depth += 1;
            MockReply::Delegation {
                servers: vec![(format!("ns.{zone}"), vec![LOOPBACK])],
                zone,
            }
        })
        .await;
        let ns_hosts: Vec<String> = zones.iter().map(|zone| format!("ns.{zone}")).collect();
        let mut ports: Vec<(&str, u16)> = ns_hosts.iter().map(|h| (h.as_str(), server)).collect();
        ports.push(("a.root.test", server));

        let trace = tracer(&["a.root.test"], &ports)
            .trace(&qname, RecordType::A)
            .await
            .unwrap();

        assert_eq!(trace.hops.len(), MAX_HOPS);
        let error = trace.error.expect("the walk must give up");
        assert!(error.contains(&MAX_HOPS.to_string()), "{error}");
        // Every hop descended one level.
        assert_eq!(trace.hops[0].zone, ".");
        assert_eq!(trace.hops[1].zone, "test.");
        assert_eq!(trace.hops[2].zone, "l20.test.");
    }

    #[tokio::test]
    async fn the_whole_walk_is_held_to_one_deadline() {
        // A chain delegated one label at a time, every level answered only
        // by its second server after the first times out: each level costs
        // one timeout, and the chain is longer than the walk's budget.
        // Without the deadline the walk ran on to the answer.
        let timeout = Duration::from_millis(100);
        let depth = TRACE_BUDGET_TIMEOUTS as usize + 2;
        let labels: Vec<String> = (1..=depth)
            .map(|i| format!("l{i}"))
            .chain(["test".into()])
            .collect();
        let qname = labels.join(".");
        let zones: Vec<String> = (1..=labels.len())
            .map(|n| labels[labels.len() - n..].join("."))
            .collect();

        let dark = spawn_mock_dns(MockMode::Ignore).await;
        let mut asked = 0;
        let chain = zones.clone();
        let live = spawn_mock_dns_fn(move |_, _| {
            let reply = match chain.get(asked) {
                Some(zone) => MockReply::Delegation {
                    zone: zone.clone(),
                    servers: vec![
                        (format!("ns1.{zone}"), vec![LOOPBACK]),
                        (format!("ns2.{zone}"), vec![LOOPBACK]),
                    ],
                },
                None => MockReply::AuthoritativeAnswer(vec![a_rdata(Ipv4Addr::new(192, 0, 2, 40))]),
            };
            asked += 1;
            reply
        })
        .await;
        let ns_hosts: Vec<(String, u16)> = zones
            .iter()
            .flat_map(|zone| [(format!("ns1.{zone}"), dark), (format!("ns2.{zone}"), live)])
            .collect();
        let mut ports: Vec<(&str, u16)> = ns_hosts.iter().map(|(h, p)| (h.as_str(), *p)).collect();
        ports.extend([("a.root.test", dark), ("b.root.test", live)]);

        let started = Instant::now();
        let trace = tracer(&["a.root.test", "b.root.test"], &ports)
            .with_timeout(timeout)
            .trace(&qname, RecordType::A)
            .await
            .unwrap();
        let elapsed = started.elapsed();

        let budget = timeout * TRACE_BUDGET_TIMEOUTS;
        assert!(elapsed < budget + timeout, "took {elapsed:?}");
        let error = trace.error.expect("the walk must run out of time");
        assert!(error.starts_with("gave up after 600ms"), "{error}");
        // The hops walked so far are kept, each one a referral that the
        // deadline cut short of the answer.
        assert!(!trace.hops.is_empty());
        assert!(trace.hops.iter().all(|hop| hop.referral_zone.is_some()));
        assert!(trace.answers.is_empty());
        let asking = zones[trace.hops.len() - 1].clone();
        assert!(
            error.ends_with(&format!("nameservers of {asking}.")),
            "{error}"
        );
    }

    #[tokio::test]
    async fn unresponsive_server_falls_back_to_the_next_one() {
        let dark = spawn_mock_dns(MockMode::Ignore).await;
        let live = spawn_mock_dns_fn(|_, _| {
            MockReply::AuthoritativeAnswer(vec![a_rdata(Ipv4Addr::new(192, 0, 2, 30))])
        })
        .await;
        let trace = tracer(
            &["a.root.test", "b.root.test"],
            &[("a.root.test", dark), ("b.root.test", live)],
        )
        .trace("example.test", RecordType::A)
        .await
        .unwrap();

        assert_eq!(trace.hops.len(), 1);
        let hop = &trace.hops[0];
        assert_eq!(hop.server, "b.root.test.");
        assert_eq!(
            hop.failed_servers,
            vec!["a.root.test. (127.0.0.1): timed out"]
        );
        assert_eq!(trace.answers.len(), 1);
        assert!(trace.error.is_none());
    }

    #[tokio::test]
    async fn every_server_refusing_ends_with_the_refusal_as_the_final_hop() {
        let root = spawn_mock_dns_fn(|_, _| {
            delegation("example.test", &["ns1.example.test", "ns2.example.test"])
        })
        .await;
        let refused = spawn_mock_dns_fn(|_, _| MockReply::Rcode(ResponseCode::Refused)).await;
        let servfail = spawn_mock_dns_fn(|_, _| MockReply::Rcode(ResponseCode::ServFail)).await;
        let trace = tracer(
            &["a.root.test"],
            &[
                ("a.root.test", root),
                ("ns1.example.test", servfail),
                ("ns2.example.test", refused),
            ],
        )
        .trace("www.example.test", RecordType::A)
        .await
        .unwrap();

        assert_eq!(trace.hops.len(), 2);
        let last = &trace.hops[1];
        assert_eq!(last.server, "ns2.example.test.");
        assert_eq!(last.status, DnsStatus::Refused);
        assert_eq!(
            last.failed_servers,
            vec!["ns1.example.test. (127.0.0.1): SERVFAIL"]
        );
        assert_eq!(trace.status, DnsStatus::Refused);
        let error = trace.error.expect("no usable response is an error");
        assert!(error.contains("example.test."), "{error}");
        assert!(
            error.contains("REFUSED") && error.contains("SERVFAIL"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn no_responsive_root_is_an_error() {
        let dark = spawn_mock_dns(MockMode::Ignore).await;
        let err = tracer(&["a.root.test"], &[("a.root.test", dark)])
            .trace("example.test", RecordType::A)
            .await
            .expect_err("nothing to trace without a root response");
        assert!(matches!(err, SeerError::DnsError(_)), "{err:?}");
        assert!(err.to_string().contains("timed out"), "{err}");
    }

    #[tokio::test]
    async fn ptr_trace_of_an_ip_literal_uses_the_reverse_name() {
        let asked = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&asked);
        let root = spawn_mock_dns_fn(move |qname, _| {
            log.lock().unwrap().push(qname.to_string());
            MockReply::AuthoritativeAnswer(vec![HickoryRData::PTR(wire::PTR(fq_name(
                "ptr.seer.test",
            )))])
        })
        .await;
        let trace = tracer(&["a.root.test"], &[("a.root.test", root)])
            .trace("192.0.2.1", RecordType::PTR)
            .await
            .unwrap();

        assert_eq!(trace.name, "1.2.0.192.in-addr.arpa");
        assert_eq!(trace.answers.len(), 1);
        assert_eq!(trace.answers[0].name, "1.2.0.192.in-addr.arpa");
        assert_eq!(trace.answers[0].record_type, RecordType::PTR);
        assert!(asked
            .lock()
            .unwrap()
            .iter()
            .all(|q| q == "1.2.0.192.in-addr.arpa"));
    }

    #[tokio::test]
    async fn truncated_reply_is_retried_over_tcp() {
        let mut served = 0;
        let root = spawn_mock_dns_fn_with_tcp(move |_, _| {
            served += 1;
            if served == 1 {
                MockReply::Truncated
            } else {
                MockReply::AuthoritativeAnswer(vec![a_rdata(Ipv4Addr::new(192, 0, 2, 40))])
            }
        })
        .await;
        let trace = tracer(&["a.root.test"], &[("a.root.test", root)])
            .trace("example.test", RecordType::A)
            .await
            .unwrap();

        assert_eq!(trace.hops.len(), 1);
        assert!(trace.hops[0].authoritative);
        assert_eq!(trace.answers.len(), 1, "{trace:#?}");
    }

    #[tokio::test]
    async fn answers_convert_the_service_binding_and_child_dnssec_types() {
        // Hops go through the resolver's one conversion table, so every
        // modeled type — HTTPS/SVCB and CDS/CDNSKEY included — comes through
        // under its owner.
        use hickory_resolver::proto::dnssec::rdata::{DNSSECRData, CDS};
        use hickory_resolver::proto::dnssec::{Algorithm, DigestType};
        use hickory_resolver::proto::rr::rdata::svcb::{Alpn, SvcParamKey, SvcParamValue, SVCB};

        let tracer = three_level_tracer(|qname| match qname {
            "www.example.test" => {
                MockReply::AuthoritativeAnswer(vec![HickoryRData::HTTPS(wire::HTTPS(SVCB::new(
                    1,
                    Name::root(),
                    vec![(
                        SvcParamKey::Alpn,
                        SvcParamValue::Alpn(Alpn(vec!["h2".to_string()])),
                    )],
                )))])
            }
            _ => MockReply::AuthoritativeAnswer(vec![HickoryRData::DNSSEC(DNSSECRData::CDS(
                CDS::new(
                    2371,
                    Some(Algorithm::ED25519),
                    DigestType::SHA256,
                    vec![0xAB],
                ),
            ))]),
        })
        .await;

        let https = tracer
            .trace("www.example.test", RecordType::HTTPS)
            .await
            .unwrap();
        assert_eq!(https.answers.len(), 1, "{https:#?}");
        assert_eq!(https.answers[0].name, "www.example.test");
        assert_eq!(https.answers[0].record_type, RecordType::HTTPS);
        assert_eq!(https.answers[0].data.to_string(), "1 . alpn=\"h2\"");
        assert_eq!(https.hops[2].answers, https.answers);

        let cds = tracer.trace("example.test", RecordType::CDS).await.unwrap();
        assert_eq!(cds.answers.len(), 1, "{cds:#?}");
        assert_eq!(cds.answers[0].record_type, RecordType::CDS);
        assert_eq!(cds.answers[0].data.to_string(), "2371 15 2 AB");
    }

    #[tokio::test]
    async fn at_most_three_servers_are_asked_per_level() {
        // Four silent roots: three are asked (and time out), the fourth is
        // never sent a packet.
        let roots = ["a.root.test", "b.root.test", "c.root.test", "d.root.test"];
        let mut ports = Vec::new();
        let mut hits = Vec::new();
        for _ in roots {
            let count = Arc::new(Mutex::new(0usize));
            let log = Arc::clone(&count);
            ports.push(
                spawn_mock_dns_fn(move |_, _| {
                    *log.lock().unwrap() += 1;
                    MockReply::NoReply
                })
                .await,
            );
            hits.push(count);
        }
        let map: Vec<(&str, u16)> = roots.iter().copied().zip(ports).collect();
        let err = tracer(&roots, &map)
            .with_timeout(Duration::from_millis(200))
            .trace("example.test", RecordType::A)
            .await
            .expect_err("no root answered");

        let message = err.to_string();
        for root in &roots[..3] {
            assert!(message.contains(root), "{message}");
        }
        assert!(!message.contains("d.root.test"), "{message}");
        let hits: Vec<usize> = hits.iter().map(|count| *count.lock().unwrap()).collect();
        assert!(hits[..3].iter().all(|&n| n > 0), "{hits:?}");
        assert_eq!(hits[3], 0, "the fourth server must not be asked: {hits:?}");
    }

    #[tokio::test]
    async fn at_most_three_glueless_nameservers_are_looked_up_per_level() {
        let root = spawn_mock_dns_fn(|_, _| MockReply::Delegation {
            zone: "test".to_string(),
            servers: (1..=4)
                .map(|i| (format!("ns{i}.nowhere.test"), vec![]))
                .collect(),
        })
        .await;
        let looked_up = Arc::new(Mutex::new(std::collections::BTreeSet::new()));
        let log = Arc::clone(&looked_up);
        let recursive = spawn_mock_dns_fn(move |qname, _| {
            log.lock().unwrap().insert(qname.to_string());
            MockReply::NxDomain
        })
        .await;
        let trace = tracer(&["a.root.test"], &[("a.root.test", root)])
            .with_recursive_upstream(LOOPBACK, recursive)
            .trace("www.example.test", RecordType::A)
            .await
            .unwrap();

        assert_eq!(trace.hops.len(), 1);
        let error = trace
            .error
            .expect("no nameserver of `test.` has an address");
        assert!(!error.contains("ns4.nowhere.test"), "{error}");
        let looked_up: Vec<String> = looked_up.lock().unwrap().iter().cloned().collect();
        assert_eq!(
            looked_up,
            ["ns1.nowhere.test", "ns2.nowhere.test", "ns3.nowhere.test"],
            "sorted referral order, capped at three"
        );
    }

    #[tokio::test]
    async fn trace_rejects_any_and_bad_names_before_sending() {
        let tracer = tracer(&["a.root.test"], &[]);
        assert!(matches!(
            tracer.trace("example.test", RecordType::ANY).await,
            Err(SeerError::InvalidInput(_))
        ));
        assert!(tracer.trace("not a name", RecordType::A).await.is_err());
    }

    #[tokio::test]
    #[ignore = "live network; run with --ignored or SEER_LIVE_TESTS=1"]
    async fn test_live_trace_example_com() {
        let trace = DnsTracer::new()
            .trace("example.com", RecordType::A)
            .await
            .unwrap();
        assert!(trace.error.is_none(), "{trace:#?}");
        assert!(trace.hops.len() >= 3, "{trace:#?}");
        assert_eq!(trace.hops[0].zone, ".");
        assert_eq!(trace.hops[1].zone, "com.");
        let last = trace.hops.last().unwrap();
        assert_eq!(last.zone, "example.com.");
        assert!(last.authoritative);
        assert_eq!(trace.status, DnsStatus::NoError);
        assert!(!trace.answers.is_empty());
    }
}
