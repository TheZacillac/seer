//! Iterative resolution from the root servers down to the answer, one hop
//! per delegation level — what `dig +trace` shows.
//!
//! Flow (see [`DnsTracer::trace`]):
//! 1. Start at the root zone (`.`) with the built-in root hints
//!    ([`ROOT_SERVERS`], IANA's `named.root`).
//! 2. Ask one server of the current zone for the query name and type,
//!    directly and with recursion disabled (RD=0). A server that does not
//!    respond, or answers with an error RCODE (SERVFAIL, REFUSED, …), is
//!    noted in the hop's `failed_servers` and the next server of the zone is
//!    asked — up to [`MAX_SERVERS_PER_LEVEL`] servers per level, each on one
//!    address (IPv4 preferred).
//! 3. A referral — NOERROR, AA clear, no answer, no SOA, NS records in
//!    AUTHORITY — names the next zone, which must lie strictly below the
//!    current zone and at or above the query name (bailiwick); an upward or
//!    sideways referral stops the walk with an error. The next servers'
//!    addresses are the referral's glue: ADDITIONAL A/AAAA records for the
//!    NS names, trusted only for names inside the current zone, as a
//!    resolver would. Glueless NS names are resolved through the recursive
//!    resolver (Google Public DNS), at most [`MAX_GLUELESS_PER_LEVEL`] per
//!    level.
//! 4. The walk stops at the first answer — authoritative or not; a CNAME is
//!    reported, not chased, as `dig +trace` does — at NXDOMAIN or NODATA, or
//!    on an error, which [`DnsTrace::error`] reports with the hops so far.
//!
//! **One raw exchange per hop.** Each query is a hickory-net UDP exchange
//! (repeated over TCP when the reply is truncated), not a resolver lookup,
//! because the resolver cannot report a hop as the server sent it (verified
//! against hickory 0.26): its name-server layer (`DnsError::from_response`)
//! turns every referral, NXDOMAIN and NODATA into a `NoRecordsFound` error,
//! which drops the response header (the AA bit) and all of ADDITIONAL but
//! the glue it matched itself, and its caching layer chases a CNAME by
//! sending a follow-up query to the same server.
//! ([`crate::dns::DelegationChecker`] reads only NS sets, so the resolver
//! serves it.)
//!
//! **SSRF:** every server address — root hint, glue or resolved — passes
//! [`crate::validation::describe_reserved_ip`] (via
//! `delegation::partition_reserved`) before a query is sent; a reserved one
//! is skipped and noted in the hop's `failed_servers`. Tests reach loopback
//! fixtures only through `#[cfg(test)]` seams (`allowing_private_hosts`,
//! `with_root_hints`, `with_port_map`, `with_recursive_upstream`); the
//! production validation path is never weakened.
//!
//! **Retry boundary (deliberate):** like the rest of `dns/`, no
//! [`crate::retry::RetryPolicy`]. hickory retransmits a UDP query within the
//! per-query timeout; asking the next server of a zone after one fails is
//! how iterative resolution proceeds, not a retry of the same query.
//!
//! **Bounded work:** at most [`MAX_HOPS`] delegation levels and, per level,
//! at most [`MAX_SERVERS_PER_LEVEL`] queries and [`MAX_GLUELESS_PER_LEVEL`]
//! glueless lookups, each under the per-query timeout (the config file's DNS
//! timeout). Each referral must descend toward the query name, so the walk
//! cannot loop.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::tcp::TcpClientStream;
use hickory_resolver::net::udp::UdpClientStream;
use hickory_resolver::net::xfer::{DnsHandle, FirstAnswer};
use hickory_resolver::net::NetError;
use hickory_resolver::proto::op::{DnsRequest, DnsRequestOptions, Message, Query, ResponseCode};
use hickory_resolver::proto::rr::{Name, RData as HickoryRData, RecordType as HickoryRecordType};
use hickory_resolver::TokioResolver;
use serde::{Deserialize, Serialize};
use tracing::{debug, instrument};

use super::delegation::{
    build_recursive_resolver, is_local_no_route, partition_reserved, prefer_ipv4,
};
use super::query::{duration_ms, DnsStatus};
use super::records::{DnsRecord, RecordType};
use super::resolver::{fqdn, prepare_query, to_dns_record, wire_query_name, wire_type};
use crate::error::{Result, SeerError};

/// Default per-query timeout, matching the DNS resolver default.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Most delegation levels walked (root included) before giving up. Real
/// names resolve in 3–5; the bound matters only for pathological chains.
const MAX_HOPS: usize = 16;

/// Servers queried per delegation level before the level is given up.
const MAX_SERVERS_PER_LEVEL: usize = 3;

/// Glueless nameserver names resolved (through the recursive resolver) per
/// delegation level.
const MAX_GLUELESS_PER_LEVEL: usize = 3;

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
    /// sideways) is recorded here too, and the trace stops with an error.
    pub referral_zone: Option<String>,
    /// The NS names delegated to, sorted; empty when there is no referral.
    pub referral: Vec<String>,
    /// This response's ANSWER section, every record under its real owner
    /// name (normally only the final hop has one).
    pub answers: Vec<DnsRecord>,
    /// Servers of this zone that were skipped or failed before this one
    /// answered, as `"host (ip): reason"` — or `"host: reason"` when no
    /// address was found for the host.
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
    /// owner name. A CNAME answer is reported as-is, not chased.
    pub answers: Vec<DnsRecord>,
    /// Why the walk stopped before a final response, if it did: every server
    /// of a zone failed, a server referred upward or sideways, or the chain
    /// was too long.
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
            timeout: DEFAULT_TIMEOUT,
            recursive: build_recursive_resolver(DEFAULT_TIMEOUT, None),
            #[cfg(test)]
            recursive_upstream: None,
            #[cfg(test)]
            root_hints: None,
            #[cfg(test)]
            port_map: None,
            #[cfg(test)]
            allow_private_hosts: false,
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

    /// Traces the resolution of `name` from the root servers down.
    ///
    /// Each hop asks one server of the current zone directly, with recursion
    /// disabled, and follows its referral to the next zone, until a server
    /// answers (a CNAME is reported, not chased), returns NXDOMAIN or NODATA,
    /// or the walk fails. A referral must lead toward `name`; an upward or
    /// sideways one stops the walk. Server addresses come from the root
    /// hints, the referral's glue, or a recursive lookup for glueless
    /// nameservers, and each one is refused when it is private or reserved.
    /// Up to 16 delegation levels are walked and up to 3 servers asked per
    /// level, each query under the configured DNS timeout.
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

        loop {
            let (mut hop, response) = match self.ask_level(&zone, &servers, &qname, qtype).await {
                LevelOutcome::Answered { hop, response } => (hop, response),
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

            let referral = match classify_response(&response, &zone) {
                Step::Final => {
                    hops.push(hop);
                    break;
                }
                Step::Referral(referral) => referral,
            };
            hop.referral_zone = Some(name_text(&referral.zone));
            hop.referral = referral
                .servers
                .iter()
                .map(|s| name_text(&s.host))
                .collect();
            if let Err(fault) = check_bailiwick(&zone, &referral.zone, &qname) {
                error = Some(format!(
                    "{} ({}) referred {} from {} to {} — stopped",
                    hop.server,
                    hop.address,
                    fault,
                    hop.zone,
                    name_text(&referral.zone)
                ));
                hops.push(hop);
                break;
            }
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
    /// (NOERROR or NXDOMAIN), recording every skipped or failed server.
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
        // The last error-RCODE response, and the index of its own note in
        // `failures`: it becomes the final hop if no server does better.
        let mut rcode_hop: Option<(TraceHop, usize)> = None;

        for pick in picks {
            if queried == MAX_SERVERS_PER_LEVEL {
                break;
            }
            let (host, ip) = match pick {
                ServerPick::Addr(host, ip) => (host, ip),
                ServerPick::Glueless(host) => {
                    // Glueless picks come last, so none remain to try.
                    if resolved == MAX_GLUELESS_PER_LEVEL {
                        break;
                    }
                    resolved += 1;
                    let (ip, notes) = self.resolve_glueless(&host).await;
                    failures.extend(notes);
                    match ip {
                        Some(ip) => (host, ip),
                        None => continue,
                    }
                }
            };
            queried += 1;
            debug!(zone = %name_text(zone), server = %name_text(&host), %ip, "trace: querying");
            let started = Instant::now();
            let result = self.exchange(&host, ip, qname, qtype).await;
            let elapsed = started.elapsed();
            match result {
                Ok(response) => {
                    let mut hop = hop_from_response(zone, &host, ip, elapsed, &response);
                    let code = response.metadata.response_code;
                    if matches!(code, ResponseCode::NoError | ResponseCode::NXDomain) {
                        hop.failed_servers = failures;
                        return LevelOutcome::Answered { hop, response };
                    }
                    rcode_hop = Some((hop, failures.len()));
                    failures.push(server_note(&host, ip, &DnsStatus::from(code).to_string()));
                }
                Err(e) => failures.push(server_note(&host, ip, &transport_reason(&e))),
            }
        }

        let reason = if failures.is_empty() {
            "no nameserver address to query".to_string()
        } else {
            failures.join("; ")
        };
        let final_hop = rcode_hop.map(|(mut hop, own_note)| {
            failures.remove(own_note);
            hop.failed_servers = failures;
            hop
        });
        LevelOutcome::Failed { final_hop, reason }
    }

    /// Resolves a glueless nameserver's address through the recursive
    /// resolver, vetting every address it returns. Returns the address to
    /// query (IPv4 preferred), if any, and notes for the failed lookup or
    /// the refused addresses.
    async fn resolve_glueless(&self, host: &Name) -> (Option<IpAddr>, Vec<String>) {
        let text = name_text(host);
        let ips: Vec<IpAddr> = match self.recursive.lookup_ip(text.as_str()).await {
            Ok(lookup) => lookup.iter().collect(),
            Err(e) if e.is_no_records_found() => Vec::new(),
            Err(e) => {
                return (
                    None,
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
        let pick = prefer_ipv4(&usable);
        if pick.is_none() && notes.is_empty() {
            notes.push(format!("{text}: glueless nameserver has no address"));
        }
        (pick, notes)
    }

    /// Sends one non-recursive query to `ip` and returns the response as the
    /// server sent it: over UDP, then once more over TCP when the UDP reply
    /// is truncated. The whole exchange shares one per-query deadline.
    async fn exchange(
        &self,
        host: &Name,
        ip: IpAddr,
        qname: &Name,
        qtype: HickoryRecordType,
    ) -> std::result::Result<Message, NetError> {
        let server = SocketAddr::new(ip, self.direct_port(host));
        let mut options = DnsRequestOptions::default();
        // Delegation data must come from each server's own authority, not
        // from recursion or a forwarder's cache.
        options.recursion_desired = false;
        let request = DnsRequest::from_query(Query::query(qname.clone(), qtype), options);
        let timeout = self.timeout;
        // Each exchange's I/O runs as a background task in the provider's
        // task set, which aborts its tasks once the last provider clone is
        // dropped. The UDP stream keeps a clone, but the TCP exchange does
        // not, so this one outlives the whole exchange — and ends it after.
        let provider = TokioRuntimeProvider::default();

        let exchange = async {
            let udp = UdpClientStream::builder(server, provider.clone())
                .with_timeout(Some(timeout))
                .exchange();
            let response = udp.send(request.clone()).first_answer().await?;
            if !response.metadata.truncation {
                return Ok::<_, NetError>(response.into_message());
            }
            debug!(%server, "trace: truncated UDP reply, retrying over TCP");
            let tcp =
                TcpClientStream::exchange(server, None, timeout, None, provider.clone()).await?;
            Ok(tcp.send(request).first_answer().await?.into_message())
        };
        tokio::time::timeout(timeout, exchange)
            .await
            .unwrap_or(Err(NetError::Timeout))
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

/// What a usable response (NOERROR / NXDOMAIN) means for the walk.
#[derive(Debug, PartialEq)]
enum Step {
    /// A final response: an answer, NXDOMAIN, or NODATA.
    Final,
    /// A referral to follow (once its bailiwick is checked).
    Referral(Referral),
}

/// The outcome of asking one delegation level.
enum LevelOutcome {
    /// A server gave a usable response (NOERROR or NXDOMAIN).
    Answered { hop: TraceHop, response: Message },
    /// No server did. `final_hop` is the last error-RCODE response, if any
    /// server responded at all; `reason` lists every failure.
    Failed {
        final_hop: Option<TraceHop>,
        reason: String,
    },
}

/// Where to send a level's queries, in order.
#[derive(Debug, PartialEq)]
enum ServerPick {
    /// A server with a vetted address (glue or root hint).
    Addr(Name, IpAddr),
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
/// address first (IPv4 preferred), then the glueless ones — and vets every
/// known address. Returns the picks and a note per refused address; a
/// server whose addresses are all refused is dropped rather than looked up
/// again, since the zone itself pointed it at reserved space.
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
        if let Some(ip) = prefer_ipv4(&usable) {
            picks.push(ServerPick::Addr(server.host.clone(), ip));
        }
    }
    picks.extend(glueless);
    (picks, notes)
}

/// Classifies a usable response. Any answer, NXDOMAIN, an authoritative
/// response or an SOA in AUTHORITY is final (a referral never carries the
/// AA bit, and a negative answer carries the zone's SOA); otherwise NS
/// records in AUTHORITY are a referral, and an empty response is NODATA.
fn classify_response(response: &Message, zone: &Name) -> Step {
    if !response.answers.is_empty()
        || response.metadata.response_code != ResponseCode::NoError
        || response.metadata.authoritative
        || response
            .authorities
            .iter()
            .any(|record| record.record_type() == HickoryRecordType::SOA)
    {
        return Step::Final;
    }
    extract_referral(response, zone).map_or(Step::Final, Step::Referral)
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

/// A short reason for a failed exchange.
fn transport_reason(err: &NetError) -> String {
    match err {
        NetError::Timeout => "timed out".to_string(),
        NetError::Io(io) if is_local_no_route(io) => format!("no route from this host ({io})"),
        other => other.to_string(),
    }
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
    use crate::dns::records::RecordData;
    use crate::dns::test_support::{
        a_rdata, cname_rdata, fq_name, record, soa_rdata, spawn_mock_dns, spawn_mock_dns_fn,
        spawn_mock_dns_fn_with_tcp, MockMode, MockReply,
    };

    const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

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
    fn classification_separates_answers_negatives_and_referrals() {
        let zone = fq_name("com");
        let mut referral = message();
        referral.add_authority(ns("example.com", "ns1.example.com"));
        assert!(matches!(
            classify_response(&referral, &zone),
            Step::Referral(_)
        ));

        // The same NS set with the AA bit is an authoritative NODATA.
        let mut authoritative = referral.clone();
        authoritative.metadata.authoritative = true;
        assert_eq!(classify_response(&authoritative, &zone), Step::Final);

        // An SOA in AUTHORITY is a negative answer, NS records or not.
        let mut nodata = referral.clone();
        nodata.add_authority(record("com", 300, soa_rdata("com")));
        assert_eq!(classify_response(&nodata, &zone), Step::Final);

        let mut nxdomain = referral.clone();
        nxdomain.metadata.response_code = ResponseCode::NXDomain;
        assert_eq!(classify_response(&nxdomain, &zone), Step::Final);

        // Any answer is final, authoritative or not (a CNAME included).
        let mut answer = referral;
        answer.add_answer(record("www.example.com", 300, cname_rdata("edge.cdn.net")));
        assert_eq!(classify_response(&answer, &zone), Step::Final);

        // Nothing at all: NODATA without an SOA.
        assert_eq!(classify_response(&message(), &zone), Step::Final);
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
                ServerPick::Addr(fq_name("ns1.example.com"), public_v4),
                ServerPick::Addr(fq_name("ns2.example.com"), public_v6),
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
        assert!(picks.contains(&ServerPick::Addr(fq_name("ns3.example.com"), metadata)));
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
        let no_route = NetError::from(std::io::Error::new(
            std::io::ErrorKind::NetworkUnreachable,
            "Network is unreachable",
        ));
        assert_eq!(
            transport_reason(&no_route),
            "no route from this host (Network is unreachable)"
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
    async fn upward_referral_stops_the_walk() {
        let root = spawn_mock_dns_fn(|_, _| delegation("test", &["ns1.nic.test"])).await;
        // A lame TLD server sends the resolver back to the root.
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
        let refused = spawn_mock_dns_fn(|_, _| MockReply::Refused).await;
        let servfail = spawn_mock_dns_fn(|_, _| MockReply::ServFail).await;
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
