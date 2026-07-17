//! NS delegation health: compares the parent zone's delegation NS set
//! against the zone's own authoritative NS RRset and probes each delegated
//! server for lameness.
//!
//! Flow (see [`DelegationChecker::check`]):
//! 1. Resolve the parent zone's NS set through the recursive resolver.
//! 2. Query up to two responsive parent servers directly with recursion
//!    disabled for the domain's NS — the delegation lives in the referral's
//!    AUTHORITY section (or the ANSWER section when the parent server also
//!    happens to be authoritative for the child). The union is `delegated_ns`.
//! 3. Query each delegated NS directly (RD=0) for the domain's own NS RRset.
//!    A server that fails to answer authoritatively for its own zone is lame
//!    (refused / timeout / non-authoritative / empty). The union of
//!    authoritative answers is `zone_ns`.
//! 4. Compare the two sets case-insensitively with trailing dots normalized.
//!
//! **Parent-zone simplification:** the parent zone is derived by stripping the
//! domain's leftmost label (`example.com` → `com`, `example.co.uk` → `co.uk`).
//! For multi-label public suffixes this is exactly the registrable parent, and
//! for registrable domains it is the TLD — the common cases. A PSL-aware
//! parent derivation (needed only for exotic zone cuts below private suffixes)
//! is future work; for a subdomain whose immediate parent is not a zone cut,
//! the NS lookup on the synthesized parent simply fails with a typed error.
//!
//! **Retry boundary (deliberate):** like [`crate::dns::resolver`], this module
//! does not wrap queries in [`crate::retry::RetryPolicy`]. hickory performs
//! its own retransmission (`opts.attempts = 2`) within the per-query timeout;
//! a lameness probe wrapped in an outer retry loop would only multiply
//! worst-case latency without changing the verdict.
//!
//! **SSRF:** delegated NS hostnames come from untrusted DNS data, so every
//! address they resolve to is checked against
//! [`crate::validation::describe_reserved_ip`] before a direct query is sent.
//! Servers that resolve only to reserved/private space are skipped with a
//! warning. Tests reach loopback fixtures through `#[cfg(test)]`-only seams
//! (`allowing_private_hosts` / `with_port_map` / `with_recursive_upstream`);
//! the production validation path is never weakened.
//!
//! **Bounded work:** at most [`MAX_PARENT_SERVERS_TRIED`] parent servers are
//! contacted (stopping after [`PARENT_SERVERS_WANTED`] respond), at most
//! [`MAX_NS_PROBED`] delegated servers are probed (concurrently), and each
//! server is probed on a single vetted address.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::time::Duration;

use hickory_resolver::config::{NameServerConfig, ResolveHosts, ResolverConfig, GOOGLE};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::{RData as HickoryRData, Record, RecordType as HickoryRecordType};
use hickory_resolver::TokioResolver;
use serde::{Deserialize, Serialize};
use tracing::{debug, instrument};

use crate::error::{Result, SeerError};
use crate::validation::normalize_domain;

/// Default per-query timeout, matching the DNS resolver default.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum delegated NS servers probed for lameness. Delegations larger than
/// this are unusual; the cap bounds total probe work and a warning notes the
/// truncation.
const MAX_NS_PROBED: usize = 6;

/// Maximum parent-zone servers contacted while hunting for responsive ones.
const MAX_PARENT_SERVERS_TRIED: usize = 4;

/// Stop querying parent servers once this many have answered.
const PARENT_SERVERS_WANTED: usize = 2;

/// A delegated nameserver that failed to answer authoritatively for its own
/// zone, with a human-readable reason (refused / timeout / non-authoritative /
/// empty).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LameNs {
    /// Nameserver host name (normalized: lowercase, no trailing dot).
    pub host: String,
    /// Why the server is considered lame.
    pub reason: String,
}

/// Result of an NS delegation health check.
///
/// All NS host names are normalized (lowercase, trailing dot stripped) and
/// sorted, so the report is deterministic and set comparisons are exact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationReport {
    /// The checked domain (normalized).
    pub domain: String,
    /// The parent zone the delegation was read from (domain minus its
    /// leftmost label — see the module docs for this simplification).
    pub parent_zone: String,
    /// Parent-zone servers that answered the delegation query.
    pub parent_server_queried: Vec<String>,
    /// The parent's view: NS names in the delegation (referral) for the domain.
    pub delegated_ns: Vec<String>,
    /// The authoritative view: union of NS RRsets returned (with the AA bit
    /// set) by the delegated servers themselves.
    pub zone_ns: Vec<String>,
    /// True when the parent and zone NS sets match exactly and no probed
    /// server is lame.
    pub in_sync: bool,
    /// NS names the parent lists but the zone's own RRset omits.
    pub missing_from_zone: Vec<String>,
    /// NS names the zone's RRset lists but the parent delegation omits.
    pub missing_from_parent: Vec<String>,
    /// Delegated servers that failed to answer authoritatively.
    pub lame: Vec<LameNs>,
    /// Non-fatal anomalies (unresolvable glue, skipped servers, truncated
    /// probe list, ...).
    pub warnings: Vec<String>,
}

/// Classified result of a single non-recursive NS query against one server.
///
/// hickory folds a referral for an NS query (empty ANSWER, matching NS
/// records in AUTHORITY) into a successful `Lookup` — `contains_answer`
/// scans all sections for the queried type — so both the `Ok` and the
/// `NoRecordsFound` paths are normalized into the same `Response` shape
/// here, keeping ANSWER and AUTHORITY NS sets separate.
#[derive(Debug)]
enum DirectNs {
    /// The server produced a DNS response (any RCODE except hard errors).
    Response {
        /// The response AA bit. `false` for the `NoRecordsFound` path, which
        /// does not carry the header — for this module's queries that path
        /// only occurs for NODATA/NXDOMAIN responses, which are never
        /// treated as authoritative NS answers anyway.
        authoritative: bool,
        response_code: ResponseCode,
        /// NS targets for the queried domain from the ANSWER section.
        answer_ns: Vec<String>,
        /// NS targets for the queried domain from the AUTHORITY section
        /// (where a parent publishes the delegation / referral).
        authority_ns: Vec<String>,
    },
    /// The server responded with an error RCODE (REFUSED, SERVFAIL, ...).
    Rcode(ResponseCode),
    /// No usable response (timeout / transport failure), with the reason.
    Unreachable(String),
}

/// Per-server outcome of a lameness probe.
#[derive(Debug)]
enum ProbeOutcome {
    /// Authoritative NS answer — contributes to `zone_ns`.
    Healthy(Vec<String>),
    /// The server is lame, with the reason.
    Lame(String),
    /// The server could not be probed at all (e.g. unresolvable glue);
    /// reported as a warning, not as lameness.
    Skipped(String),
}

/// Checks NS delegation health for a domain.
///
/// Construct with [`DelegationChecker::new`] (defaults) or
/// [`DelegationChecker::from_config`] (honors `~/.seer/config.toml`
/// `timeouts.dns_secs`), then call [`check`](DelegationChecker::check).
pub struct DelegationChecker {
    /// Per-query timeout for both recursive and direct queries.
    timeout: Duration,
    /// Recursive resolver used to discover the parent zone's NS set and to
    /// resolve nameserver host addresses ("glue", loosely — resolution goes
    /// through recursion rather than the parent's additional section).
    recursive: TokioResolver,
    /// Test-only: pin the recursive resolver to a loopback mock.
    #[cfg(test)]
    recursive_upstream: Option<(IpAddr, u16)>,
    /// Test-only: per-host port override for direct queries, so each mock
    /// "server" can live on its own ephemeral loopback port.
    #[cfg(test)]
    port_map: Option<std::collections::HashMap<String, u16>>,
    /// Test-only: skip the SSRF/reserved-IP validation on direct targets.
    #[cfg(test)]
    allow_private_hosts: bool,
}

impl std::fmt::Debug for DelegationChecker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DelegationChecker")
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl Default for DelegationChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl DelegationChecker {
    /// Creates a delegation checker with default settings (5s per-query
    /// timeout, Google DNS as the recursive resolver).
    pub fn new() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            recursive: build_recursive_resolver(DEFAULT_TIMEOUT, None),
            #[cfg(test)]
            recursive_upstream: None,
            #[cfg(test)]
            port_map: None,
            #[cfg(test)]
            allow_private_hosts: false,
        }
    }

    /// Builds a checker honoring `~/.seer/config.toml` settings.
    ///
    /// Reads `timeouts.dns_secs` (already clamped to 1–60s by
    /// [`crate::config::SeerConfig::load`]). Sugar over
    /// [`DelegationChecker::with_timeout`].
    pub fn from_config(config: &crate::config::SeerConfig) -> Self {
        Self::new().with_timeout(config.dns_timeout())
    }

    /// Sets the per-query timeout (applies to recursive lookups, parent
    /// delegation queries, and lameness probes alike).
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

    /// Test-only: route direct queries for the given (normalized) host names
    /// to per-host mock ports instead of port 53.
    #[cfg(test)]
    fn with_port_map(mut self, map: std::collections::HashMap<String, u16>) -> Self {
        self.port_map = Some(map);
        self
    }

    /// Test-only: allow direct queries to loopback/private hosts (mock servers).
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

    /// Port used for a direct query to `host`. Always 53 in production; the
    /// `#[cfg(test)]` port map lets each mock server bind its own ephemeral
    /// loopback port.
    #[cfg(test)]
    fn direct_port(&self, host: &str) -> u16 {
        self.port_map
            .as_ref()
            .and_then(|map| map.get(&normalize_ns_name(host)).copied())
            .unwrap_or(53)
    }

    #[cfg(not(test))]
    fn direct_port(&self, _host: &str) -> u16 {
        53
    }

    /// Runs the delegation health check for `domain`.
    ///
    /// # Arguments
    /// * `domain` - The domain to check (e.g. "example.com"); normalized first
    ///
    /// # Returns
    /// * `Ok(DelegationReport)` - the comparison + lameness report
    /// * `Err(SeerError)` - when the input is invalid, the parent zone's NS
    ///   set cannot be resolved, or no parent server answers the delegation
    ///   query (without parent data there is nothing to compare)
    #[instrument(skip(self), fields(domain = %domain))]
    pub async fn check(&self, domain: &str) -> Result<DelegationReport> {
        let domain = normalize_domain(domain)?;
        let parent_zone = parent_zone_of(&domain);
        let mut warnings = Vec::new();

        // 1. Parent zone NS set via the recursive resolver.
        let parent_hosts = self.recursive_ns_set(&parent_zone).await?;
        if parent_hosts.is_empty() {
            return Err(SeerError::DnsError(format!(
                "parent zone {} has no NS records — cannot locate the delegation for {}",
                parent_zone, domain
            )));
        }

        // 2. Ask up to PARENT_SERVERS_WANTED responsive parent servers for the
        //    delegation (RD=0). Referrals carry the NS set in AUTHORITY; a
        //    parent that is also authoritative for the child answers in ANSWER.
        let mut parent_server_queried = Vec::new();
        let mut delegated: BTreeSet<String> = BTreeSet::new();
        for host in parent_hosts.iter().take(MAX_PARENT_SERVERS_TRIED) {
            if parent_server_queried.len() >= PARENT_SERVERS_WANTED {
                break;
            }
            let ip = match self.resolve_host_ip(host).await {
                Ok(ip) => ip,
                Err(reason) => {
                    warnings.push(format!("skipped parent server {}: {}", host, reason));
                    continue;
                }
            };
            debug!(server = %host, %ip, "querying parent server for delegation");
            match self.direct_ns_query(host, ip, &domain).await {
                DirectNs::Response {
                    response_code,
                    answer_ns,
                    authority_ns,
                    ..
                } => {
                    if response_code == ResponseCode::NXDomain {
                        warnings.push(format!(
                            "parent server {} returned NXDOMAIN for {}",
                            host, domain
                        ));
                    }
                    // Referrals carry the delegation in AUTHORITY; a parent
                    // that is also authoritative for the child answers in
                    // ANSWER. Union both.
                    delegated.extend(answer_ns);
                    delegated.extend(authority_ns);
                    parent_server_queried.push(host.clone());
                }
                DirectNs::Rcode(code) => {
                    warnings.push(format!("parent server {} answered with {}", host, code));
                }
                DirectNs::Unreachable(reason) => {
                    warnings.push(format!(
                        "parent server {} did not respond: {}",
                        host, reason
                    ));
                }
            }
        }

        if parent_server_queried.is_empty() {
            return Err(SeerError::DnsError(format!(
                "no parent-zone ({}) nameserver answered the delegation query for {}",
                parent_zone, domain
            )));
        }
        if delegated.is_empty() {
            warnings.push(format!(
                "parent zone {} returned no NS delegation for {} — the domain may not be delegated",
                parent_zone, domain
            ));
        }

        // 3. Probe the delegated servers (bounded, concurrent) for lameness.
        let probe_hosts: Vec<String> = delegated.iter().take(MAX_NS_PROBED).cloned().collect();
        if delegated.len() > MAX_NS_PROBED {
            warnings.push(format!(
                "probing only {} of {} delegated nameservers",
                MAX_NS_PROBED,
                delegated.len()
            ));
        }
        let outcomes = futures::future::join_all(
            probe_hosts
                .iter()
                .map(|host| self.probe_delegated_ns(host, &domain)),
        )
        .await;

        let mut zone_ns: BTreeSet<String> = BTreeSet::new();
        let mut lame = Vec::new();
        for (host, outcome) in probe_hosts.iter().zip(outcomes) {
            match outcome {
                ProbeOutcome::Healthy(ns) => zone_ns.extend(ns),
                ProbeOutcome::Lame(reason) => lame.push(LameNs {
                    host: host.clone(),
                    reason,
                }),
                ProbeOutcome::Skipped(reason) => {
                    warnings.push(format!("could not probe {}: {}", host, reason));
                }
            }
        }

        // 4. Set comparison. When no server produced an authoritative answer
        //    there is no zone view to diff against — flag it instead of
        //    reporting every delegated NS as "missing from zone".
        let (missing_from_zone, missing_from_parent) = if zone_ns.is_empty() {
            if !delegated.is_empty() {
                warnings.push(
                    "no delegated nameserver returned an authoritative NS answer — \
                     parent/zone set comparison skipped"
                        .to_string(),
                );
            }
            (Vec::new(), Vec::new())
        } else {
            (
                delegated.difference(&zone_ns).cloned().collect(),
                zone_ns.difference(&delegated).cloned().collect(),
            )
        };

        let in_sync = !delegated.is_empty()
            && !zone_ns.is_empty()
            && missing_from_zone.is_empty()
            && missing_from_parent.is_empty()
            && lame.is_empty();

        lame.sort_by(|a, b| a.host.cmp(&b.host));

        Ok(DelegationReport {
            domain,
            parent_zone,
            parent_server_queried,
            delegated_ns: delegated.into_iter().collect(),
            zone_ns: zone_ns.into_iter().collect(),
            in_sync,
            missing_from_zone,
            missing_from_parent,
            lame,
            warnings,
        })
    }

    /// Resolves a zone's NS set through the recursive resolver, returning
    /// normalized host names (sorted, deduplicated). NXDOMAIN/NODATA fold to
    /// an empty set; transport failures surface as errors.
    async fn recursive_ns_set(&self, zone: &str) -> Result<Vec<String>> {
        match self
            .recursive
            .lookup(fqdn(zone), HickoryRecordType::NS)
            .await
        {
            Ok(lookup) => {
                let set: BTreeSet<String> =
                    ns_targets_for(lookup.answers(), zone).into_iter().collect();
                Ok(set.into_iter().collect())
            }
            Err(e) if e.is_no_records_found() => Ok(Vec::new()),
            Err(e) => Err(SeerError::DnsError(format!(
                "NS lookup for parent zone {} failed: {}",
                zone, e
            ))),
        }
    }

    /// Resolves one usable (public, unless the test seam allows private)
    /// address for a nameserver host. Errors carry a human-readable reason
    /// for the report's warnings.
    async fn resolve_host_ip(&self, host: &str) -> std::result::Result<IpAddr, String> {
        let response = self
            .recursive
            .lookup_ip(fqdn(host))
            .await
            .map_err(|e| format!("could not resolve {}: {}", host, e))?;
        let ips: Vec<IpAddr> = response.iter().collect();
        if ips.is_empty() {
            return Err(format!("{} did not resolve to any address", host));
        }
        let mut blocked_reason = None;
        let mut vetted = Vec::new();
        for ip in ips {
            // SSRF protection: NS host names come from untrusted DNS data,
            // so reserved/private targets are refused. The test seam is
            // `#[cfg(test)]`-only; production always validates.
            if !self.allow_private() {
                if let Some(reason) = crate::validation::describe_reserved_ip(&ip) {
                    blocked_reason.get_or_insert_with(|| {
                        format!("{} resolves to a blocked address ({})", host, reason)
                    });
                    continue;
                }
            }
            vetted.push(ip);
        }
        prefer_ipv4(&vetted).ok_or_else(|| {
            blocked_reason
                .unwrap_or_else(|| format!("{} did not resolve to a usable address", host))
        })
    }

    /// Sends a single non-recursive NS query for `domain` to the server at
    /// `ip` and classifies the outcome. Never fails hard: construction and
    /// transport errors fold into [`DirectNs::Unreachable`] so callers can
    /// record them per-server.
    async fn direct_ns_query(&self, host: &str, ip: IpAddr, domain: &str) -> DirectNs {
        let resolver = match self.build_direct_resolver(host, ip) {
            Ok(resolver) => resolver,
            Err(e) => return DirectNs::Unreachable(format!("resolver construction failed: {}", e)),
        };
        match resolver.lookup(fqdn(domain), HickoryRecordType::NS).await {
            // The Lookup preserves the raw response message, so the AA bit
            // is the server's own claim of authority, and a referral's NS
            // records are still sitting in the AUTHORITY section.
            Ok(lookup) => {
                let message = lookup.message();
                DirectNs::Response {
                    authoritative: message.metadata.authoritative,
                    response_code: message.metadata.response_code,
                    answer_ns: ns_targets_for(&message.answers, domain),
                    authority_ns: ns_targets_for(&message.authorities, domain),
                }
            }
            Err(e) => classify_net_error(e, domain),
        }
    }

    /// Builds a one-shot stub resolver pinned to `ip` with recursion
    /// disabled, mirroring the construction pattern in
    /// [`crate::dns::resolver`]. UDP with TCP fallback, so truncated NS sets
    /// retry over TCP.
    fn build_direct_resolver(&self, host: &str, ip: IpAddr) -> Result<TokioResolver> {
        let mut config = ResolverConfig::from_parts(None, vec![], vec![]);
        let mut ns = NameServerConfig::udp_and_tcp(ip);
        let port = self.direct_port(host);
        for connection in &mut ns.connections {
            connection.port = port;
        }
        config.add_name_server(ns);

        let mut builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        {
            let opts = builder.options_mut();
            opts.timeout = self.timeout;
            opts.attempts = 2;
            opts.use_hosts_file = ResolveHosts::Never;
            // Delegation data must come from the server's own authority, not
            // from recursion or a forwarder's cache.
            opts.recursion_desired = false;
        }
        builder
            .build()
            .map_err(|e| SeerError::DnsError(format!("failed to construct DNS resolver: {}", e)))
    }

    /// Probes one delegated nameserver: resolves an address, sends the RD=0
    /// NS query, and classifies the result.
    async fn probe_delegated_ns(&self, host: &str, domain: &str) -> ProbeOutcome {
        let ip = match self.resolve_host_ip(host).await {
            Ok(ip) => ip,
            // Unresolvable "glue" is a warning, not lameness: the server was
            // never reached, so nothing is known about its authority.
            Err(reason) => return ProbeOutcome::Skipped(reason),
        };
        debug!(server = %host, %ip, "probing delegated nameserver");
        match self.direct_ns_query(host, ip, domain).await {
            DirectNs::Response {
                response_code: ResponseCode::NXDomain,
                ..
            } => ProbeOutcome::Lame("returned NXDOMAIN for its own zone".to_string()),
            DirectNs::Response {
                authoritative: true,
                answer_ns,
                ..
            } if !answer_ns.is_empty() => ProbeOutcome::Healthy(answer_ns),
            DirectNs::Response {
                authoritative: true,
                ..
            } => ProbeOutcome::Lame("authoritative answer contained no NS records".to_string()),
            DirectNs::Response { answer_ns, .. } if !answer_ns.is_empty() => {
                ProbeOutcome::Lame("answered non-authoritatively (AA bit not set)".to_string())
            }
            DirectNs::Response { authority_ns, .. } if !authority_ns.is_empty() => {
                ProbeOutcome::Lame("not authoritative — referred the query elsewhere".to_string())
            }
            DirectNs::Response { .. } => {
                ProbeOutcome::Lame("returned an empty answer (no NS records)".to_string())
            }
            DirectNs::Rcode(code) => ProbeOutcome::Lame(format!("refused the query ({})", code)),
            DirectNs::Unreachable(reason) => {
                ProbeOutcome::Lame(format!("no usable response: {}", reason))
            }
        }
    }
}

/// Builds the recursive resolver: Google DNS (UDP+TCP) in production, or a
/// pinned loopback upstream for the `#[cfg(test)]` seam.
///
/// The `expect` expresses the same invariant as
/// `dns::resolver::build_default_resolver`: with plain UDP/TCP upstreams the
/// only fallible step (rustls TLS-context construction for DoT/DoH) never
/// runs, so construction cannot fail.
fn build_recursive_resolver(timeout: Duration, upstream: Option<(IpAddr, u16)>) -> TokioResolver {
    let config = match upstream {
        None => ResolverConfig::udp_and_tcp(&GOOGLE),
        Some((ip, port)) => {
            let mut config = ResolverConfig::from_parts(None, vec![], vec![]);
            let mut ns = NameServerConfig::udp(ip);
            for connection in &mut ns.connections {
                connection.port = port;
            }
            config.add_name_server(ns);
            config
        }
    };
    let mut builder = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
    {
        let opts = builder.options_mut();
        opts.timeout = timeout;
        opts.attempts = 2;
        opts.use_hosts_file = ResolveHosts::Never;
    }
    builder
        .build()
        .expect("plain UDP/TCP resolver build cannot fail with the bundled webpki root store")
}

/// Classifies a hickory lookup error into a [`DirectNs`] outcome, extracting
/// referral NS names for `domain` from the AUTHORITY section when present.
/// The `NoRecordsFound` path only occurs when no NS record for the domain
/// exists in any section (NODATA / NXDOMAIN) — see [`DirectNs`].
fn classify_net_error(err: NetError, domain: &str) -> DirectNs {
    match err {
        NetError::Dns(DnsError::NoRecordsFound(no_records)) => DirectNs::Response {
            authoritative: false,
            response_code: no_records.response_code,
            answer_ns: Vec::new(),
            authority_ns: no_records
                .authorities
                .as_deref()
                .map(|records| ns_targets_for(records, domain))
                .unwrap_or_default(),
        },
        NetError::Dns(DnsError::ResponseCode(code)) => DirectNs::Rcode(code),
        NetError::Timeout => DirectNs::Unreachable("timed out".to_string()),
        other => DirectNs::Unreachable(other.to_string()),
    }
}

/// The parent zone of a normalized domain: everything after the leftmost
/// label. `normalize_domain` guarantees at least one interior dot, so the
/// fallback branch is unreachable in practice (kept panic-free regardless).
fn parent_zone_of(domain: &str) -> String {
    domain
        .split_once('.')
        .map(|(_, rest)| rest.to_string())
        .unwrap_or_else(|| domain.to_string())
}

/// Picks the probe address from the vetted list, preferring IPv4. gTLD
/// servers commonly list AAAA records first, and blindly taking the first
/// vetted address made every direct parent query fail with "network
/// unreachable" on IPv4-only hosts. IPv6-only deployments still work: v6 is
/// used whenever no v4 address survives vetting.
fn prefer_ipv4(vetted: &[IpAddr]) -> Option<IpAddr> {
    vetted
        .iter()
        .find(|ip| ip.is_ipv4())
        .or_else(|| vetted.first())
        .copied()
}

/// Appends the root dot so hickory treats the name as fully qualified (no
/// search-list expansion).
fn fqdn(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{}.", name)
    }
}

/// Normalizes an NS host name for set comparison: lowercase, trailing dot
/// stripped.
fn normalize_ns_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// Extracts the normalized NS target names owned by `owner` from a record
/// slice (answer or authority section). Records for other owners — e.g. the
/// parent zone's own SOA in a NODATA response — are ignored.
fn ns_targets_for(records: &[Record], owner: &str) -> Vec<String> {
    let owner = normalize_ns_name(owner);
    records
        .iter()
        .filter_map(|record| {
            if normalize_ns_name(&record.name.to_string()) != owner {
                return None;
            }
            match &record.data {
                HickoryRData::NS(ns) => Some(normalize_ns_name(&ns.0.to_string())),
                _ => None,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    //! Hermetic tests: every DNS "server" in a scenario (the recursive
    //! resolver, the parent server, and each delegated NS) is a loopback UDP
    //! mock on its own ephemeral port, reached through the `#[cfg(test)]`
    //! seams (`with_recursive_upstream` / `with_port_map` /
    //! `allowing_private_hosts`). The mock encoder mirrors
    //! [`crate::dns::test_support`] but adds control over the AA bit,
    //! AUTHORITY-section referrals, and error RCODEs, which the shared
    //! fixture deliberately does not model. The shared fixture's
    //! `MockMode::Ignore` is reused for the timeout case.

    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use hickory_resolver::proto::op::{Message, OpCode};
    use hickory_resolver::proto::rr::rdata as wire;
    use hickory_resolver::proto::rr::Name;
    use tokio::net::UdpSocket;

    use super::*;
    use crate::dns::test_support::{spawn_mock_dns, MockMode};

    // --- pure helpers --------------------------------------------------

    #[test]
    fn parent_zone_strips_leftmost_label() {
        assert_eq!(parent_zone_of("example.com"), "com");
        assert_eq!(parent_zone_of("sub.example.co.uk"), "example.co.uk");
        assert_eq!(parent_zone_of("example.co.uk"), "co.uk");
    }

    #[test]
    fn ns_name_normalization_is_case_and_dot_insensitive() {
        assert_eq!(normalize_ns_name("NS1.Example.COM."), "ns1.example.com");
        assert_eq!(normalize_ns_name("ns1.example.com"), "ns1.example.com");
    }

    #[test]
    fn probe_ip_selection_prefers_ipv4_over_first_listed() {
        // gTLD servers often list AAAA first; an IPv4-only host must not be
        // handed an unreachable v6 address when a v4 one exists.
        let v6: IpAddr = "2001:503:a83e::2:30".parse().unwrap();
        let v4: IpAddr = "192.5.6.30".parse().unwrap();
        assert_eq!(prefer_ipv4(&[v6, v4]), Some(v4));
        assert_eq!(prefer_ipv4(&[v4, v6]), Some(v4));
        // IPv6-only deployments still get the v6 address.
        assert_eq!(prefer_ipv4(&[v6]), Some(v6));
        assert_eq!(prefer_ipv4(&[]), None);
    }

    #[test]
    fn fqdn_appends_root_dot_once() {
        assert_eq!(fqdn("example.com"), "example.com.");
        assert_eq!(fqdn("example.com."), "example.com.");
    }

    #[test]
    fn from_config_applies_dns_timeout() {
        let mut config = crate::config::SeerConfig::default();
        config.timeouts.dns_secs = 9;
        let checker = DelegationChecker::from_config(&config);
        assert_eq!(checker.timeout, Duration::from_secs(9));
    }

    // --- mock DNS server with AA / AUTHORITY / RCODE control ------------

    /// How a mock server answers one query.
    #[derive(Clone)]
    enum MockReply {
        /// NOERROR with answer records; `authoritative` sets the AA bit.
        Answers {
            records: Vec<HickoryRData>,
            authoritative: bool,
        },
        /// NOERROR, empty ANSWER, NS records for the queried name in
        /// AUTHORITY — a classic parent-side referral.
        Referral(Vec<HickoryRData>),
        /// NOERROR with all sections empty (NODATA).
        NoData,
        Refused,
    }

    type Handler = Arc<dyn Fn(&str, HickoryRecordType) -> MockReply + Send + Sync>;

    /// Binds a UDP socket on an ephemeral loopback port and answers each
    /// query via `handler` (qname is passed lowercased without the trailing
    /// dot). Returns the bound port.
    async fn spawn_mock(handler: Handler) -> u16 {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock DNS");
        let port = socket.local_addr().expect("mock DNS local addr").port();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                let Ok((len, src)) = socket.recv_from(&mut buf).await else {
                    return;
                };
                let Ok(request) = Message::from_vec(&buf[..len]) else {
                    continue;
                };
                let Some(query) = request.queries.first().cloned() else {
                    continue;
                };
                let mut response = Message::response(request.metadata.id, OpCode::Query);
                response.metadata.recursion_desired = request.metadata.recursion_desired;
                response.metadata.recursion_available = true;
                response.add_query(query.clone());
                let qname = query.name.to_string().to_ascii_lowercase();
                match handler(qname.trim_end_matches('.'), query.query_type) {
                    MockReply::Answers {
                        records,
                        authoritative,
                    } => {
                        response.metadata.authoritative = authoritative;
                        for rdata in records {
                            response.add_answer(Record::from_rdata(query.name.clone(), 300, rdata));
                        }
                    }
                    MockReply::Referral(records) => {
                        for rdata in records {
                            response.add_authority(Record::from_rdata(
                                query.name.clone(),
                                300,
                                rdata,
                            ));
                        }
                    }
                    MockReply::NoData => {}
                    MockReply::Refused => {
                        response.metadata.response_code = ResponseCode::Refused;
                    }
                }
                let Ok(bytes) = response.to_vec() else {
                    continue;
                };
                let _ = socket.send_to(&bytes, src).await;
            }
        });
        port
    }

    fn ns_rdata(target: &str) -> HickoryRData {
        HickoryRData::NS(wire::NS(
            Name::from_ascii(target).expect("valid test NS name"),
        ))
    }

    fn loopback_a() -> HickoryRData {
        HickoryRData::A(wire::A(Ipv4Addr::LOCALHOST))
    }

    /// Recursive-resolver mock for the standard scenario: parent zone `test`
    /// served by `a.parent.test`, and A records (→127.0.0.1) for every host
    /// in `resolvable`.
    async fn spawn_recursive_mock(resolvable: &[&str]) -> u16 {
        let resolvable: Vec<String> = resolvable.iter().map(|s| s.to_string()).collect();
        spawn_mock(Arc::new(move |qname, qtype| {
            match (qname, qtype) {
                ("test", HickoryRecordType::NS) => MockReply::Answers {
                    records: vec![ns_rdata("a.parent.test.")],
                    authoritative: false,
                },
                (host, HickoryRecordType::A)
                    if host == "a.parent.test" || resolvable.iter().any(|r| r == host) =>
                {
                    MockReply::Answers {
                        records: vec![loopback_a()],
                        authoritative: false,
                    }
                }
                // AAAA and unknown hosts: NODATA (lookup_ip falls back / fails).
                _ => MockReply::NoData,
            }
        }))
        .await
    }

    /// An authoritative zone server answering `domain NS` with `rrset`.
    async fn spawn_zone_server(rrset: &[&str]) -> u16 {
        let records: Vec<HickoryRData> = rrset.iter().map(|ns| ns_rdata(ns)).collect();
        spawn_mock(Arc::new(move |_qname, qtype| {
            if qtype == HickoryRecordType::NS {
                MockReply::Answers {
                    records: records.clone(),
                    authoritative: true,
                }
            } else {
                MockReply::NoData
            }
        }))
        .await
    }

    /// A parent server that refers `seer.test` to `referral`.
    async fn spawn_parent_server(referral: &[&str]) -> u16 {
        let records: Vec<HickoryRData> = referral.iter().map(|ns| ns_rdata(ns)).collect();
        spawn_mock(Arc::new(move |qname, qtype| {
            if qname == "seer.test" && qtype == HickoryRecordType::NS {
                MockReply::Referral(records.clone())
            } else {
                MockReply::NoData
            }
        }))
        .await
    }

    fn checker(recursive_port: u16, port_map: HashMap<String, u16>) -> DelegationChecker {
        DelegationChecker::new()
            .with_timeout(Duration::from_millis(500))
            .allowing_private_hosts()
            .with_recursive_upstream(Ipv4Addr::LOCALHOST.into(), recursive_port)
            .with_port_map(port_map)
    }

    // --- end-to-end scenarios -------------------------------------------

    #[tokio::test]
    async fn healthy_in_sync_delegation() {
        let recursive = spawn_recursive_mock(&["ns1.seer.test", "ns2.seer.test"]).await;
        let parent = spawn_parent_server(&["ns1.seer.test.", "ns2.seer.test."]).await;
        let ns1 = spawn_zone_server(&["ns1.seer.test.", "ns2.seer.test."]).await;
        let ns2 = spawn_zone_server(&["ns1.seer.test.", "ns2.seer.test."]).await;

        let report = checker(
            recursive,
            HashMap::from([
                ("a.parent.test".to_string(), parent),
                ("ns1.seer.test".to_string(), ns1),
                ("ns2.seer.test".to_string(), ns2),
            ]),
        )
        .check("seer.test")
        .await
        .expect("healthy delegation check must succeed");

        assert_eq!(report.domain, "seer.test");
        assert_eq!(report.parent_zone, "test");
        assert_eq!(report.parent_server_queried, vec!["a.parent.test"]);
        assert_eq!(report.delegated_ns, vec!["ns1.seer.test", "ns2.seer.test"]);
        assert_eq!(report.zone_ns, vec!["ns1.seer.test", "ns2.seer.test"]);
        assert!(report.in_sync, "report should be in sync: {report:?}");
        assert!(report.missing_from_zone.is_empty());
        assert!(report.missing_from_parent.is_empty());
        assert!(report.lame.is_empty());
    }

    #[tokio::test]
    async fn parent_lists_ns_the_zone_omits() {
        // Parent delegates to ns1 + ns3; both answer authoritatively but the
        // zone RRset only contains ns1 → ns3 is missing_from_zone.
        let recursive = spawn_recursive_mock(&["ns1.seer.test", "ns3.seer.test"]).await;
        let parent = spawn_parent_server(&["ns1.seer.test.", "ns3.seer.test."]).await;
        let zone = spawn_zone_server(&["ns1.seer.test."]).await;
        let zone2 = spawn_zone_server(&["ns1.seer.test."]).await;

        let report = checker(
            recursive,
            HashMap::from([
                ("a.parent.test".to_string(), parent),
                ("ns1.seer.test".to_string(), zone),
                ("ns3.seer.test".to_string(), zone2),
            ]),
        )
        .check("seer.test")
        .await
        .expect("check must succeed");

        assert_eq!(report.delegated_ns, vec!["ns1.seer.test", "ns3.seer.test"]);
        assert_eq!(report.zone_ns, vec!["ns1.seer.test"]);
        assert_eq!(report.missing_from_zone, vec!["ns3.seer.test"]);
        assert!(report.missing_from_parent.is_empty());
        assert!(!report.in_sync);
        assert!(report.lame.is_empty(), "set mismatch is not lameness");
    }

    #[tokio::test]
    async fn zone_lists_ns_the_parent_omits() {
        // Parent only delegates ns1, but the zone's RRset advertises ns1 +
        // ns2 → ns2 is missing_from_parent.
        let recursive = spawn_recursive_mock(&["ns1.seer.test"]).await;
        let parent = spawn_parent_server(&["ns1.seer.test."]).await;
        let zone = spawn_zone_server(&["ns1.seer.test.", "ns2.seer.test."]).await;

        let report = checker(
            recursive,
            HashMap::from([
                ("a.parent.test".to_string(), parent),
                ("ns1.seer.test".to_string(), zone),
            ]),
        )
        .check("seer.test")
        .await
        .expect("check must succeed");

        assert_eq!(report.delegated_ns, vec!["ns1.seer.test"]);
        assert_eq!(report.zone_ns, vec!["ns1.seer.test", "ns2.seer.test"]);
        assert_eq!(report.missing_from_parent, vec!["ns2.seer.test"]);
        assert!(report.missing_from_zone.is_empty());
        assert!(!report.in_sync);
    }

    #[tokio::test]
    async fn refusing_server_is_lame() {
        let recursive = spawn_recursive_mock(&["ns1.seer.test", "ns2.seer.test"]).await;
        let parent = spawn_parent_server(&["ns1.seer.test.", "ns2.seer.test."]).await;
        let ns1 = spawn_zone_server(&["ns1.seer.test.", "ns2.seer.test."]).await;
        let ns2 = spawn_mock(Arc::new(|_, _| MockReply::Refused)).await;

        let report = checker(
            recursive,
            HashMap::from([
                ("a.parent.test".to_string(), parent),
                ("ns1.seer.test".to_string(), ns1),
                ("ns2.seer.test".to_string(), ns2),
            ]),
        )
        .check("seer.test")
        .await
        .expect("check must succeed");

        // The sets still match (ns1 serves the full RRset), but the lame
        // server alone must break in_sync.
        assert!(report.missing_from_zone.is_empty());
        assert!(report.missing_from_parent.is_empty());
        assert_eq!(report.lame.len(), 1, "lame: {:?}", report.lame);
        assert_eq!(report.lame[0].host, "ns2.seer.test");
        assert!(
            report.lame[0].reason.to_lowercase().contains("refused"),
            "reason should mention the refusal: {}",
            report.lame[0].reason
        );
        assert!(!report.in_sync);
    }

    #[tokio::test]
    async fn non_authoritative_answer_is_lame() {
        let recursive = spawn_recursive_mock(&["ns1.seer.test", "ns2.seer.test"]).await;
        let parent = spawn_parent_server(&["ns1.seer.test.", "ns2.seer.test."]).await;
        let ns1 = spawn_zone_server(&["ns1.seer.test.", "ns2.seer.test."]).await;
        // ns2 answers the right RRset but without the AA bit — a cache, not
        // an authority.
        let ns2 = spawn_mock(Arc::new(|_, qtype| {
            if qtype == HickoryRecordType::NS {
                MockReply::Answers {
                    records: vec![ns_rdata("ns1.seer.test."), ns_rdata("ns2.seer.test.")],
                    authoritative: false,
                }
            } else {
                MockReply::NoData
            }
        }))
        .await;

        let report = checker(
            recursive,
            HashMap::from([
                ("a.parent.test".to_string(), parent),
                ("ns1.seer.test".to_string(), ns1),
                ("ns2.seer.test".to_string(), ns2),
            ]),
        )
        .check("seer.test")
        .await
        .expect("check must succeed");

        assert_eq!(report.lame.len(), 1, "lame: {:?}", report.lame);
        assert_eq!(report.lame[0].host, "ns2.seer.test");
        assert!(
            report.lame[0].reason.contains("non-authoritatively"),
            "reason: {}",
            report.lame[0].reason
        );
        assert!(!report.in_sync);
        // The healthy server still provides the zone view.
        assert_eq!(report.zone_ns, vec!["ns1.seer.test", "ns2.seer.test"]);
    }

    #[tokio::test]
    async fn unresponsive_server_is_lame_with_timeout_reason() {
        let recursive = spawn_recursive_mock(&["ns1.seer.test", "ns2.seer.test"]).await;
        let parent = spawn_parent_server(&["ns1.seer.test.", "ns2.seer.test."]).await;
        let ns1 = spawn_zone_server(&["ns1.seer.test.", "ns2.seer.test."]).await;
        // Reuse the shared fixture's black-hole mode for the no-response case.
        let ns2 = spawn_mock_dns(MockMode::Ignore).await;

        let report = checker(
            recursive,
            HashMap::from([
                ("a.parent.test".to_string(), parent),
                ("ns1.seer.test".to_string(), ns1),
                ("ns2.seer.test".to_string(), ns2),
            ]),
        )
        .check("seer.test")
        .await
        .expect("check must succeed");

        assert_eq!(report.lame.len(), 1, "lame: {:?}", report.lame);
        assert_eq!(report.lame[0].host, "ns2.seer.test");
        assert!(
            report.lame[0].reason.contains("no usable response"),
            "reason: {}",
            report.lame[0].reason
        );
        assert!(!report.in_sync);
    }

    #[tokio::test]
    async fn unresolvable_glue_is_warned_and_skipped_not_lame() {
        // ns2 has no A record at the recursive resolver → skipped with a
        // warning; the remaining server still proves the sets match.
        let recursive = spawn_recursive_mock(&["ns1.seer.test"]).await;
        let parent = spawn_parent_server(&["ns1.seer.test.", "ns2.seer.test."]).await;
        let ns1 = spawn_zone_server(&["ns1.seer.test.", "ns2.seer.test."]).await;

        let report = checker(
            recursive,
            HashMap::from([
                ("a.parent.test".to_string(), parent),
                ("ns1.seer.test".to_string(), ns1),
            ]),
        )
        .check("seer.test")
        .await
        .expect("check must succeed");

        assert!(report.lame.is_empty(), "skip must not be lame: {report:?}");
        assert!(
            report.warnings.iter().any(|w| w.contains("ns2.seer.test")),
            "warnings should mention the skipped host: {:?}",
            report.warnings
        );
        assert!(report.in_sync, "sets match and nothing is lame: {report:?}");
    }

    #[tokio::test]
    async fn no_responsive_parent_server_is_an_error() {
        // The parent host resolves but its server never answers.
        let recursive = spawn_recursive_mock(&[]).await;
        let parent = spawn_mock_dns(MockMode::Ignore).await;

        let err = checker(
            recursive,
            HashMap::from([("a.parent.test".to_string(), parent)]),
        )
        .check("seer.test")
        .await
        .expect_err("no parent answer must be an error");
        assert!(
            matches!(err, SeerError::DnsError(_)),
            "expected DnsError, got: {err:?}"
        );
        assert!(err.to_string().contains("parent"), "got: {err}");
    }
}
