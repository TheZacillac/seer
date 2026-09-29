//! DNS resolution over hickory-resolver.
//!
//! [`DnsResolver::resolve`] — and every feature built on it — looks records
//! up through hickory's resolver. [`DnsResolver::query`] reports the response
//! itself, as dig does, so it sends one query per record type straight to the
//! same upstream servers through `dns::transport` (which says why the
//! resolver cannot), except for the special-use names the resolver answers
//! without sending anything.
//!
//! Retry boundary (deliberate): unlike the WHOIS/RDAP clients, this module
//! does NOT wrap queries in [`crate::retry::RetryPolicy`]. hickory-resolver
//! already re-sends a lookup whose attempt timed out, up to `opts.attempts`
//! ([`RESOLVER_ATTEMPTS`]) attempts in all, each under its own full
//! per-query timeout — so a lookup against a silent server takes that many
//! timeouts. Stacking an outer retry loop on top would multiply worst-case
//! latency without improving resolution odds. If a retry knob is ever
//! needed here, tune [`RESOLVER_ATTEMPTS`] rather than adding a wrapper;
//! `query()`'s direct path derives its deadline from it
//! (`transport::QUERY_BUDGET_TIMEOUTS`).

use std::borrow::Cow;
use std::net::IpAddr;
use std::pin::pin;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::future::{self, Either};
use hickory_resolver::config::{
    NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts, ServerOrderingStrategy, GOOGLE,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::dnssec::PublicKey;
use hickory_resolver::proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue, SVCB};
use hickory_resolver::proto::rr::rdata::CAA;
use hickory_resolver::proto::rr::{
    Name, RData as HickoryRData, Record, RecordType as HickoryRecordType,
};
use hickory_resolver::proto::serialize::binary::BinEncodable;
use hickory_resolver::TokioResolver;
use tracing::{debug, instrument};

use super::nameserver::{NameserverProtocol, NameserverSpec};
use super::query::{
    answered_locally, dedupe_records, fold_any, merge_any, random_probe_label, wildcard_outcome,
    wildcard_probe_name, DnsQueryResult, Exchange, SubQuery, WildcardProbe,
};
use super::records::{DnsRecord, RecordData, RecordType, SvcParam};
use super::transport::{NoResponse, Transport};
use super::DEFAULT_DNS_TIMEOUT;
use crate::error::{Result, SeerError};
use crate::validation::{normalize_domain, normalize_query_name};

/// hickory's `attempts`: how many times a lookup is sent before it fails,
/// each attempt under a full per-query timeout. The one setting both query
/// paths' deadlines derive from (see the module docs).
pub(crate) const RESOLVER_ATTEMPTS: usize = 2;

/// How long a positive answer waits for its still-running wildcard probe,
/// as a fraction of the per-query timeout (1s at the 5s default). The probe
/// asks for a random, never-cached name, so it can trail a cached answer by
/// a full recursion — but never by more than this: it must not cost the
/// main query its answer time.
const PROBE_GRACE_DIVISOR: u32 = 5;

/// How debug logs name the upstream of a query that names no nameserver.
const DEFAULT_UPSTREAM: &str = "default (Google Public DNS)";

/// The record types an `ANY` query fans out to, in report order.
///
/// `ANY` is not sent on the wire: RFC 8482 lets servers answer it minimally
/// (typically one HINFO or a single RRset), so seer queries these types
/// concurrently instead. One list for [`DnsResolver::resolve`] and
/// [`DnsResolver::query`], so the two cannot drift.
const ANY_TYPES: [RecordType; 11] = [
    RecordType::A,
    RecordType::AAAA,
    RecordType::CNAME,
    RecordType::MX,
    RecordType::NS,
    RecordType::TXT,
    RecordType::SOA,
    RecordType::CAA,
    RecordType::HTTPS,
    RecordType::DS,
    RecordType::DNSKEY,
];

/// Apply seer's standard resolver options.
///
/// Extracted from [`build_resolver`] so the option set is assertable without
/// standing up a resolver (hickory exposes no getter for a built resolver's
/// options), and shared with `net.rs`'s SSRF fallback resolver so the two
/// cannot drift — they previously carried hand-copied option sets and the
/// server-ordering fix below would have landed in only one of them.
pub(crate) fn apply_standard_opts(opts: &mut ResolverOpts, timeout: Duration) {
    opts.timeout = timeout;
    opts.attempts = RESOLVER_ATTEMPTS;
    opts.use_hosts_file = ResolveHosts::Never;
    // Pin the query order to the configured list instead of hickory's default
    // `QueryStatistics`. The default orders servers by observed performance,
    // which is the right call for a long-lived process but meaningless in a
    // short-lived CLI run that has collected no statistics yet — leaving the
    // effective order arbitrary.
    //
    // That mattered because the default upstream group (`GOOGLE`) carries two
    // IPv4 and two IPv6 addresses, and hickory queries `num_concurrent_reqs`
    // (2) of them in parallel. On a host advertising an IPv6 default route
    // with no working IPv6 transit — RA-advertised IPv6 that black-holes,
    // common on consumer networks — a pair that happened to be both IPv6 sent
    // into the void and burned the full per-query timeout. Roughly one run in
    // six stalled 5s, and `seer doctor` reported an outright DNS failure
    // because its probe deadline equals that timeout, leaving no budget to
    // fail over.
    //
    // With the order pinned, the parallel pair is deterministically the two
    // IPv4 servers. IPv6 entries stay in the list and remain reachable as
    // fallback: on a genuinely IPv6-only host the IPv4 sends fail immediately
    // with ENETUNREACH rather than timing out, so failover stays fast.
    opts.server_ordering_strategy = ServerOrderingStrategy::UserProvidedOrder;
}

/// Build a TokioResolver pre-configured with the given upstream config and
/// our standard options (timeout, retries, no hosts-file consultation).
///
/// Build only fails when hickory cannot construct its rustls TLS context
/// (needed for DoT/DoH upstreams). With the `webpki-roots` feature supplying
/// the root store, that construction is infallible in practice, but the
/// fallible signature is kept honest so a future root-store change degrades
/// to a typed error instead of a panic.
fn build_resolver(config: ResolverConfig, timeout: Duration) -> Result<TokioResolver> {
    let mut builder = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
    apply_standard_opts(builder.options_mut(), timeout);
    builder
        .build()
        .map_err(|e| SeerError::DnsError(format!("failed to construct DNS resolver: {}", e)))
}

/// Build the default (Google DNS over UDP/TCP) resolver.
///
/// The `expect` expresses an invariant rather than laziness: with the
/// `webpki-roots` root store compiled in, hickory's TLS-context construction
/// (the only fallible step in [`build_resolver`]) cannot fail, and the
/// infallible `new()`/`with_timeout()` constructors predate DoT/DoH support.
fn build_default_resolver(timeout: Duration) -> TokioResolver {
    build_resolver(default_upstream_config(), timeout)
        .expect("default resolver build cannot fail with the bundled webpki root store")
}

/// The default upstream: Google Public DNS over UDP with TCP fallback, IPv4
/// servers first. The one definition for the default resolver and for
/// [`DnsResolver::query`]'s direct queries.
fn default_upstream_config() -> ResolverConfig {
    ResolverConfig::udp_and_tcp(&GOOGLE)
}

/// Upstream config pinned to the single server `ip:port` — UDP only, or UDP
/// with TCP fallback (for answers that may truncate).
pub(crate) fn single_server_config(ip: IpAddr, port: u16, tcp_fallback: bool) -> ResolverConfig {
    let mut ns = if tcp_fallback {
        NameServerConfig::udp_and_tcp(ip)
    } else {
        NameServerConfig::udp(ip)
    };
    for connection in &mut ns.connections {
        connection.port = port;
    }
    let mut config = ResolverConfig::from_parts(None, vec![], vec![]);
    config.add_name_server(ns);
    config
}

/// Google DNS (UDP+TCP), or the pinned UDP `upstream` that the DNSSEC and
/// delegation checkers' `#[cfg(test)]` seams point at a loopback mock.
pub(crate) fn google_or_pinned(upstream: Option<(IpAddr, u16)>) -> ResolverConfig {
    match upstream {
        None => default_upstream_config(),
        Some((ip, port)) => single_server_config(ip, port, false),
    }
}

/// Appends the root dot so hickory treats `name` as fully qualified (no
/// search-list expansion).
pub(crate) fn fqdn(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    }
}

/// Build the hickory upstream config for a parsed nameserver spec and its
/// resolved (and already SSRF-validated) addresses.
///
/// One `NameServerConfig` is added per IP (IPv4 first, see below), all
/// speaking the spec's protocol on the spec's port. For DoT/DoH the TLS
/// server name is the spec's host — the hostname when one was given, or the
/// IP literal itself (verified against the certificate's IP SANs, which the
/// major public resolvers carry). `port_override` is the `#[cfg(test)]`
/// mock-server seam and is always `None` in production.
fn build_upstream_config(
    spec: &NameserverSpec,
    ips: &[IpAddr],
    port_override: Option<u16>,
) -> ResolverConfig {
    let mut config = ResolverConfig::from_parts(None, vec![], vec![]);
    let port = port_override.unwrap_or(spec.port);
    // IPv4 before IPv6, each family keeping its resolved order — the same
    // shape as the default `GOOGLE` group. The pool is pinned to
    // `UserProvidedOrder` (see `apply_standard_opts`) and races its first
    // `num_concurrent_reqs` (2) entries under one deadline equal to the
    // per-query timeout, so list order decides which addresses get tried.
    // hickory's `lookup_ip` returns AAAA before A, so a dual-stack hostname
    // (`dns.google`, `https://cloudflare-dns.com/dns-query`) led with two
    // IPv6 entries; with black-holed IPv6 transit they spent the whole
    // deadline and the IPv4 entries were never reached. IPv6 stays as
    // fallback: on an IPv6-only host IPv4 sends fail fast (ENETUNREACH).
    let mut ordered = ips.to_vec();
    crate::net::ipv4_first(&mut ordered, |ip| *ip);
    for ip in ordered {
        let mut ns = match spec.protocol {
            NameserverProtocol::Udp => NameServerConfig::udp(ip),
            NameserverProtocol::Tls => NameServerConfig::tls(ip, Arc::from(spec.tls_name())),
            NameserverProtocol::Https => NameServerConfig::https(
                ip,
                Arc::from(spec.tls_name()),
                spec.path.as_deref().map(Arc::from),
            ),
        };
        for connection in &mut ns.connections {
            connection.port = port;
        }
        config.add_name_server(ns);
    }
    config
}

/// DNS resolver for querying various record types.
///
/// Uses Google DNS (8.8.8.8) by default, but supports custom nameservers
/// over plain UDP, DNS over TLS (`tls://`), and DNS over HTTPS (`https://`)
/// — see [`NameserverSpec`] for the accepted forms.
/// The default resolver is cached and reused across queries to avoid
/// repeated initialization overhead.
#[derive(Clone)]
pub struct DnsResolver {
    timeout: Duration,
    /// Cached default resolver (Google DNS). Reused across all queries
    /// that don't specify a custom nameserver.
    default_resolver: TokioResolver,
    /// [`query`](Self::query)'s direct transport, built once with the same
    /// timeout (its rustls client config is not free to build).
    transport: Transport,
    /// Port override for custom-nameserver queries. Always `None` in
    /// production (the port comes from the parsed [`NameserverSpec`]);
    /// settable only through the `#[cfg(test)]` seam so mock-server tests
    /// can bind an ephemeral local port.
    port_override: Option<u16>,
    /// When true, skips the SSRF/reserved-IP validation on custom
    /// nameservers so tests can point the resolver at a 127.0.0.1 fixture.
    /// Not settable outside `#[cfg(test)]` builds — production paths always
    /// validate.
    allow_private_hosts: bool,
    /// Test-only: nameserver spec used when a caller passes `None`, so code
    /// that always queries the default upstream (posture, CAA) can be pointed
    /// at the loopback fixture. Absent from release builds.
    #[cfg(test)]
    test_default_nameserver: Option<String>,
}

impl std::fmt::Debug for DnsResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsResolver")
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl Default for DnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsResolver {
    /// Creates a new DNS resolver with default settings.
    pub fn new() -> Self {
        Self::with_timeout_only(DEFAULT_DNS_TIMEOUT)
    }

    /// A resolver with `timeout` and every other setting at its default:
    /// the one place the cached resolver and transport are built, once each.
    fn with_timeout_only(timeout: Duration) -> Self {
        Self {
            timeout,
            default_resolver: build_default_resolver(timeout),
            transport: Transport::new(timeout),
            port_override: None,
            allow_private_hosts: false,
            #[cfg(test)]
            test_default_nameserver: None,
        }
    }

    /// Builds a resolver honoring `~/.seer/config.toml` settings.
    ///
    /// Reads `timeouts.dns_secs` (already clamped to 1–60s by
    /// [`crate::config::SeerConfig::load`]) — the same resolver as
    /// `DnsResolver::new().with_timeout(config.dns_timeout())`, built once.
    ///
    /// The `nameserver` config key is deliberately NOT applied here: the
    /// resolver takes the nameserver per-query (see [`DnsResolver::resolve`]),
    /// so callers thread `config.nameserver` at the call site where it can be
    /// overridden per-invocation.
    pub fn from_config(config: &crate::config::SeerConfig) -> Self {
        Self::with_timeout_only(config.dns_timeout())
    }

    /// Test-only: the per-query timeout, for asserting config plumbing.
    #[cfg(test)]
    pub(crate) fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Test-only: allow custom nameservers on loopback/private hosts (mock servers).
    #[cfg(test)]
    pub(crate) fn allowing_private_hosts(mut self) -> Self {
        self.allow_private_hosts = true;
        self
    }

    /// Test-only: query custom nameservers on a non-standard port (mock
    /// servers bind ephemeral ports).
    #[cfg(test)]
    pub(crate) fn with_port(mut self, port: u16) -> Self {
        self.port_override = Some(port);
        self
    }

    /// Test-only: send queries that name no nameserver to `nameserver`
    /// instead of the cached default (Google) resolver.
    #[cfg(test)]
    pub(crate) fn with_default_nameserver(mut self, nameserver: &str) -> Self {
        self.test_default_nameserver = Some(nameserver.to_string());
        self
    }

    /// The nameserver a query actually uses: the caller's choice, or (in test
    /// builds only) the fixture default installed by
    /// [`with_default_nameserver`](Self::with_default_nameserver).
    #[cfg(test)]
    fn effective_nameserver<'a>(&'a self, nameserver: Option<&'a str>) -> Option<&'a str> {
        nameserver.or(self.test_default_nameserver.as_deref())
    }

    #[cfg(not(test))]
    fn effective_nameserver<'a>(&self, nameserver: Option<&'a str>) -> Option<&'a str> {
        nameserver
    }

    /// Sets the timeout for DNS queries.
    ///
    /// The default is 5 seconds, which is sufficient for most DNS queries.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self.default_resolver = build_default_resolver(timeout);
        self.transport = Transport::new(timeout);
        self
    }

    async fn create_custom_resolver(&self, nameserver: &str) -> Result<TokioResolver> {
        build_resolver(self.custom_upstream_config(nameserver).await?, self.timeout)
    }

    /// The upstream config for a caller's nameserver spec: parsed, its host
    /// resolved when it is a name, every address SSRF-vetted, then one server
    /// per address (see [`build_upstream_config`]). The one path to a custom
    /// nameserver, shared by the resolver ([`resolve`](Self::resolve)) and
    /// the direct queries of [`query`](Self::query), so the vetting cannot
    /// differ between them.
    async fn custom_upstream_config(&self, nameserver: &str) -> Result<ResolverConfig> {
        // Parse the spec first: bare IP/host (UDP), tls:// (DoT), https://
        // (DoH). Every surface (CLI, REPL, config.toml, py/REST/MCP) funnels
        // its opaque nameserver string through here, so this one parse gives
        // all of them every transport.
        let spec = NameserverSpec::parse(nameserver)?;

        // Accept either a literal IP or a hostname. For hostnames, resolve
        // via the default (Google DNS) hickory resolver so we do not depend
        // on the OS resolver — that is the same fallback principle as the
        // SSL probe fix: when the local system resolver is broken (split
        // DNS, broken router, container netns), hickory still reaches the
        // public name servers and the user-supplied authoritative server
        // is still usable. DoT/DoH hostnames bootstrap-resolve through this
        // exact same path (the TLS handshake still verifies the hostname).
        let ips: Vec<IpAddr> = if let Ok(ip) = spec.host.parse::<IpAddr>() {
            vec![ip]
        } else {
            let response = self
                .default_resolver
                .lookup_ip(spec.host.as_str())
                .await
                .map_err(|e| {
                    SeerError::DnsError(format!(
                        "failed to resolve nameserver hostname {}: {}",
                        spec.host, e
                    ))
                })?;
            let resolved: Vec<IpAddr> = response.iter().collect();
            if resolved.is_empty() {
                return Err(SeerError::DnsError(format!(
                    "nameserver {} did not resolve to any addresses",
                    spec.host
                )));
            }
            resolved
        };

        self.vet_nameserver_ips(nameserver, &ips)?;
        Ok(build_upstream_config(&spec, &ips, self.port_override))
    }

    /// SSRF protection: rejects private/reserved IPs — whether supplied
    /// literally or returned by name resolution, and identically for UDP,
    /// tls:// and https:// specs. Without this, a hostname under attacker
    /// control could point at internal infra. `allow_private_hosts` is only
    /// settable via the `#[cfg(test)]` seam; production builds always
    /// validate.
    fn vet_nameserver_ips(&self, nameserver: &str, ips: &[IpAddr]) -> Result<()> {
        if self.allow_private_hosts {
            return Ok(());
        }
        for ip in ips {
            if let Some(reason) = crate::validation::describe_reserved_ip(ip) {
                return Err(SeerError::DnsError(format!(
                    "nameserver {} blocked: {}",
                    nameserver, reason
                )));
            }
        }
        Ok(())
    }

    /// The checks on a nameserver spec that send nothing: it parses, and an
    /// IP-literal host passes [`vet_nameserver_ips`](Self::vet_nameserver_ips).
    /// For a query hickory answers itself ([`answered_locally`]), where the
    /// server is never asked, so resolving its hostname would be network
    /// traffic for nothing.
    fn vet_nameserver_offline(&self, nameserver: &str) -> Result<()> {
        let spec = NameserverSpec::parse(nameserver)?;
        match spec.host.parse::<IpAddr>() {
            Ok(ip) => self.vet_nameserver_ips(nameserver, &[ip]),
            Err(_) => Ok(()),
        }
    }

    /// The resolver a query runs on: one built for `nameserver` (parsed,
    /// resolved and SSRF-vetted by `custom_upstream_config`), or the cached
    /// default.
    async fn upstream(&self, nameserver: Option<&str>) -> Result<Cow<'_, TokioResolver>> {
        Ok(match self.effective_nameserver(nameserver) {
            Some(ns) => Cow::Owned(self.create_custom_resolver(ns).await?),
            None => Cow::Borrowed(&self.default_resolver),
        })
    }

    /// Where [`query`](Self::query) sends a query for `name`: hickory's
    /// resolver for a special-use name it answers itself (the nameserver is
    /// only vetted offline — it is never asked), else straight to the servers
    /// of `nameserver` (parsed, resolved and SSRF-vetted by
    /// `custom_upstream_config`) or of the default upstream.
    async fn query_upstream(&self, name: &str, nameserver: Option<&str>) -> Result<Upstream<'_>> {
        if answered_locally(name) {
            if let Some(ns) = self.effective_nameserver(nameserver) {
                self.vet_nameserver_offline(ns)?;
            }
            return Ok(Upstream::Local(&self.default_resolver));
        }
        let config = match self.effective_nameserver(nameserver) {
            Some(ns) => self.custom_upstream_config(ns).await?,
            None => default_upstream_config(),
        };
        Ok(Upstream::Direct {
            config,
            transport: &self.transport,
        })
    }

    /// Queries one name the way `dig` does and reports the whole response:
    /// status, header flags, the CNAME chain and answers under their real
    /// owner names, the AUTHORITY section, and a wildcard probe.
    ///
    /// Takes the same input as [`resolve`](Self::resolve) — normalization,
    /// the dig-style `_service._proto.name` SRV form, a raw IP literal for
    /// PTR, and a custom nameserver spec (SSRF-vetted) or `None` for the
    /// default upstream — but where `resolve` folds every negative answer
    /// into an empty list, `query` reports it: NXDOMAIN, NODATA, SERVFAIL
    /// and REFUSED are `Ok` results with that [`DnsQueryResult::status`].
    /// An `Err` means there is no response to report: invalid input (a
    /// malformed name, a bare-domain SRV query), a nameserver that was
    /// refused (a private or reserved address) or did not resolve, or a
    /// transport failure (timeout, no connection) at every server.
    ///
    /// Like dig, it sends one query (with RD set) and reports the response
    /// the server sent — header, ANSWER and AUTHORITY sections as they came
    /// — rather than a resolver lookup, which would chase a CNAME itself and
    /// fold a negative answer into an error: a chain that ends at a name that
    /// does not exist is reported with the chain and NXDOMAIN, as the
    /// recursive server returns it. The servers are the nameserver's (or the
    /// default upstream's), asked in order, IPv4 first; UDP, repeated over
    /// TCP when the reply is truncated; and a server that does not respond
    /// passes the query to the next, all under two DNS timeouts.
    ///
    /// `ANY` fans out concurrently to A, AAAA, CNAME, MX, NS, TXT, SOA, CAA,
    /// HTTPS, DS and DNSKEY and merges the answers (see
    /// [`DnsQueryResult::answers`]); a sub-query that failed is listed in
    /// [`DnsQueryResult::failed_types`], and the query errors only when
    /// every sub-query failed.
    ///
    /// For a name strictly below its registrable domain (`www.example.com`,
    /// not `example.com`), a random sibling (`seer-probe-….example.com`) is
    /// queried for the same type concurrently with the main query, and its
    /// outcome attached as [`DnsQueryResult::wildcard`] when the main answer
    /// has records. The probe never fails the query, a positive answer waits
    /// for it at most a fifth of the DNS timeout, and
    /// [`DnsQueryResult::query_time_ms`] times the main query alone.
    ///
    /// A special-use name (RFC 6761: `localhost`, `127.in-addr.arpa`,
    /// `invalid`, `onion`, …) is never sent to a server — RFC 7686 forbids
    /// leaking `.onion` names into the DNS — but answered by hickory's
    /// resolver itself; the result says so
    /// ([`DnsQueryResult::answered_locally`]) and runs no probe. A
    /// nameserver given with it is parsed and, when an IP literal, vetted,
    /// but a hostname is not resolved: nothing is sent to it.
    #[instrument(skip(self), fields(domain = %domain, record_type = %record_type))]
    pub async fn query(
        &self,
        domain: &str,
        record_type: RecordType,
        nameserver: Option<&str>,
    ) -> Result<DnsQueryResult> {
        // Input first: a bad name must not cost a nameserver-hostname lookup.
        let domain = prepare_query(domain, record_type)?;
        let name = wire_query_name(&domain, record_type)?;
        let upstream = self.query_upstream(&name, nameserver).await?;

        debug!(
            nameserver = nameserver.unwrap_or(DEFAULT_UPSTREAM),
            "Querying DNS"
        );

        let (exchange, query_time, wildcard) = if record_type == RecordType::ANY {
            let started = Instant::now();
            let exchange = merge_any(exchange_any(&upstream, &name).await)?;
            (exchange, started.elapsed(), None)
        } else {
            let grace = self.timeout / PROBE_GRACE_DIVISOR;
            exchange_with_probe(&upstream, &name, record_type, grace).await?
        };
        Ok(exchange.into_result(name, record_type, nameserver, wildcard, query_time))
    }

    /// One server's view of a name, for propagation checks:
    /// [`query`](Self::query) sent to `nameserver` alone, without the
    /// wildcard probe, and with a transport failure reported as
    /// [`ServerReply::Silent`] and its reason rather than as an error. For
    /// ANY the reply is `Silent` only when no sub-query got a response; a
    /// partial one lists the rest in [`DnsQueryResult::failed_types`], which
    /// a comparison must read as "unknown", not as "no records". An `Err` is
    /// invalid input or a nameserver that was refused (private or reserved)
    /// or did not resolve.
    pub(crate) async fn query_server(
        &self,
        domain: &str,
        record_type: RecordType,
        nameserver: &str,
    ) -> Result<ServerReply> {
        let domain = prepare_query(domain, record_type)?;
        let name = wire_query_name(&domain, record_type)?;
        if answered_locally(&name) {
            // Never sent (RFC 7686); `query` answers it without a probe.
            return self
                .query(&domain, record_type, Some(nameserver))
                .await
                .map(ServerReply::Response);
        }
        let upstream = self.query_upstream(&name, Some(nameserver)).await?;

        let started = Instant::now();
        let exchange = if record_type == RecordType::ANY {
            let replies = exchange_any(&upstream, &name).await;
            // Silent only when no sub-query got through; a partial answer
            // carries its failed types (`DnsQueryResult::failed_types`).
            if replies.iter().all(|(_, reply)| matches!(reply, Ok(Err(_)))) {
                if let Some((_, Ok(Err(why)))) = replies.first() {
                    return Ok(ServerReply::Silent(why.reason()));
                }
            }
            merge_any(replies)?
        } else {
            match upstream.try_exchange(&name, record_type).await? {
                Ok(exchange) => exchange,
                Err(why) => return Ok(ServerReply::Silent(why.reason())),
            }
        };
        Ok(ServerReply::Response(exchange.into_result(
            name,
            record_type,
            Some(nameserver),
            None,
            started.elapsed(),
        )))
    }

    /// Resolves DNS records for a domain: the records of `record_type` only,
    /// each named by the queried name, with NXDOMAIN and NODATA folded into
    /// an empty list. For the response itself — status, CNAME chain, the SOA
    /// of a negative answer — use [`query`](Self::query).
    ///
    /// # Arguments
    /// * `domain` - The domain name to query
    /// * `record_type` - The type of DNS record to look up (A, AAAA, MX, etc.)
    /// * `nameserver` - Optional custom nameserver spec; uses Google DNS if
    ///   None. Accepts a bare IP/hostname with optional port (UDP),
    ///   `tls://host[:port]` (DNS over TLS), or `https://host[:port][/path]`
    ///   (DNS over HTTPS) — see [`NameserverSpec`]
    #[instrument(skip(self), fields(domain = %domain, record_type = %record_type))]
    pub async fn resolve(
        &self,
        domain: &str,
        record_type: RecordType,
        nameserver: Option<&str>,
    ) -> Result<Vec<DnsRecord>> {
        // Input first: a bad name must not cost a nameserver-hostname lookup.
        let domain = prepare_query(domain, record_type)?;
        // Reuse the cached default resolver when no custom nameserver is specified
        let resolver = self.upstream(nameserver).await?;

        debug!(
            nameserver = nameserver.unwrap_or(DEFAULT_UPSTREAM),
            "Resolving DNS"
        );

        match record_type {
            RecordType::SRV => match parse_srv_query(&domain) {
                // dig-style `_service._proto.name` queries resolve directly.
                Some((service, protocol, name)) => {
                    self.resolve_srv_core(&resolver, &service, &protocol, &name)
                        .await
                }
                // A bare domain isn't a valid SRV query — surface a usage hint
                // as an input error (permanent), not a transient DNS failure.
                None => Err(srv_format_error()),
            },
            RecordType::ANY => self.resolve_any(&resolver, &domain).await,
            single => self.resolve_type(&resolver, &domain, single).await,
        }
    }

    /// Core SRV resolution against an already-built resolver, behind the
    /// `dig`-style `_service._proto.name` path in [`resolve`](Self::resolve).
    /// Validates the service/protocol labels (DNS query-injection guard) then
    /// queries `_service._proto.domain`. Label-validation failures are
    /// [`SeerError::InvalidInput`] — they are caller mistakes, not transient
    /// DNS failures, so they must not be advertised as retryable.
    async fn resolve_srv_core(
        &self,
        resolver: &TokioResolver,
        service: &str,
        protocol: &str,
        domain: &str,
    ) -> Result<Vec<DnsRecord>> {
        let query_name = srv_query_name(service, protocol, domain)?;
        self.resolve_records(resolver, &query_name, RecordType::SRV)
            .await
    }

    /// Single-type dispatch shared by [`resolve`](Self::resolve) and
    /// [`resolve_any`](Self::resolve_any) — the one place a seer [`RecordType`] is routed to a
    /// lookup, so the two entry points cannot diverge.
    ///
    /// `SRV` and `ANY` are composite queries owned by `resolve` (label
    /// validation / fan-out); requesting them here yields the same
    /// "unsupported record type" error from either entry point.
    async fn resolve_type(
        &self,
        resolver: &TokioResolver,
        domain: &str,
        record_type: RecordType,
    ) -> Result<Vec<DnsRecord>> {
        match record_type {
            RecordType::SRV | RecordType::ANY => Err(unsupported_record_type(record_type)),
            // PTR accepts a raw IP literal, which is queried as its
            // reverse-DNS name (and reported under that name).
            RecordType::PTR => {
                self.resolve_records(resolver, &ptr_query_name(domain), RecordType::PTR)
                    .await
            }
            single => self.resolve_records(resolver, domain, single).await,
        }
    }

    /// Generic single-type lookup: queries the wire type for `record_type`
    /// and maps each matching answer through [`convert_rdata`]. Answers of
    /// other types (e.g. a CNAME returned alongside A records) are skipped.
    /// NXDOMAIN/NODATA fold to an empty vec: the absence of a type is a
    /// valid answer, not a failure.
    ///
    /// MX is the one type with a meaningful intra-response order: answers
    /// are sorted by preference so the highest-priority exchange is first.
    async fn resolve_records(
        &self,
        resolver: &TokioResolver,
        domain: &str,
        record_type: RecordType,
    ) -> Result<Vec<DnsRecord>> {
        let Some(wire_type) = wire_type(record_type) else {
            return Err(unsupported_record_type(record_type));
        };

        let response = match resolver.lookup(domain, wire_type).await {
            Ok(response) => response,
            Err(e) if e.is_no_records_found() => return Ok(vec![]),
            Err(e) => {
                return Err(SeerError::DnsError(format!(
                    "{record_type} lookup failed: {e}"
                )))
            }
        };

        let mut records: Vec<DnsRecord> = response
            .answers()
            .iter()
            .filter_map(|record| {
                convert_rdata(record_type, &record.data, NameSpelling::Display).map(|data| {
                    DnsRecord {
                        name: domain.to_string(),
                        record_type,
                        ttl: record.ttl,
                        data,
                    }
                })
            })
            .collect();

        if record_type == RecordType::MX {
            records.sort_by_key(|r| match &r.data {
                RecordData::MX { preference, .. } => *preference,
                _ => 0,
            });
        }

        Ok(records)
    }

    async fn resolve_any(&self, resolver: &TokioResolver, domain: &str) -> Result<Vec<DnsRecord>> {
        // Query the ANY types concurrently — previously these ran serially,
        // making `ANY` ~7x slower than a single query (#61). `join_all`
        // preserves input order, so the merged record list keeps the
        // `ANY_TYPES` ordering.
        let results = future::join_all(ANY_TYPES.into_iter().map(|record_type| async move {
            (
                record_type,
                self.resolve_type(resolver, domain, record_type).await,
            )
        }))
        .await;

        // An empty answer still counts as success; only when every type
        // errored is that error surfaced. A record list has nowhere to carry
        // the failed types — `query()` reports them.
        let (record_sets, _failed) = fold_any(results)?;
        Ok(dedupe_records(record_sets.into_iter().flatten()))
    }
}

/// Where [`DnsResolver::query`] sends its queries.
enum Upstream<'a> {
    /// A special-use name hickory's resolver answers itself
    /// ([`answered_locally`]): the resolver, which sends it nowhere.
    Local(&'a TokioResolver),
    /// Any other name: straight to these (vetted) servers, one query per
    /// type, the response reported as the server sent it.
    Direct {
        config: ResolverConfig,
        transport: &'a Transport,
    },
}

impl Upstream<'_> {
    /// Runs one query for `name`/`record_type` and maps its outcome to an
    /// [`Exchange`], with the answers in report order.
    async fn exchange(&self, name: &str, record_type: RecordType) -> Result<Exchange> {
        self.try_exchange(name, record_type)
            .await?
            .map_err(|why| SeerError::DnsError(format!("{record_type} lookup failed: {why}")))
    }

    /// [`exchange`](Self::exchange), keeping a transport failure (no server
    /// responded) apart from the other errors as the inner `Err`.
    async fn try_exchange(
        &self,
        name: &str,
        record_type: RecordType,
    ) -> Result<std::result::Result<Exchange, NoResponse>> {
        let wire = wire_type(record_type).ok_or_else(|| unsupported_record_type(record_type))?;
        let exchange = match self {
            Upstream::Local(resolver) => {
                Exchange::from_local(resolver.lookup(name, wire).await, record_type)?
            }
            Upstream::Direct { config, transport } => {
                let qname = Name::from_ascii(fqdn(name))
                    .map_err(|e| SeerError::InvalidDomain(format!("{name}: {e}")))?;
                let request = transport.request(qname, wire, true);
                match transport.query(config.name_servers(), &request).await {
                    Ok(response) => Exchange::from_message(&response),
                    Err(why) => return Ok(Err(why)),
                }
            }
        };
        Ok(Ok(exchange.ordered(name, record_type)))
    }
}

/// How one nameserver answered [`DnsResolver::query_server`].
#[derive(Debug)]
pub(crate) enum ServerReply {
    /// The server responded — any status, SERVFAIL and REFUSED included.
    Response(DnsQueryResult),
    /// It sent no response: a short reason (`timed out`, `no route from this
    /// host (…)`), safe to show.
    Silent(String),
}

/// The `ANY` fan-out behind [`DnsResolver::query`] and
/// [`DnsResolver::query_server`]: every [`ANY_TYPES`] query concurrently,
/// each outcome by its type, in `ANY_TYPES` order — for [`merge_any`].
async fn exchange_any(upstream: &Upstream<'_>, name: &str) -> Vec<(RecordType, SubQuery)> {
    future::join_all(ANY_TYPES.into_iter().map(|record_type| async move {
        (record_type, upstream.try_exchange(name, record_type).await)
    }))
    .await
}

/// One query plus, when eligible, its wildcard probe run concurrently.
/// Returns the main exchange, the main query's own duration, and the judged
/// probe.
///
/// The probe must not cost the main query anything: it never turns the
/// result into an error, it is dropped unawaited when the main answer
/// finishes first with nothing to attach it to (an error, a negative
/// answer), a positive answer waits at most `grace` more for it, and the
/// reported duration is the main query's alone.
async fn exchange_with_probe(
    upstream: &Upstream<'_>,
    name: &str,
    record_type: RecordType,
    grace: Duration,
) -> Result<(Exchange, Duration, Option<WildcardProbe>)> {
    let main = async {
        let started = Instant::now();
        let result = upstream.exchange(name, record_type).await;
        (result, started.elapsed())
    };
    let Some(probe_name) = wildcard_probe_name(name, record_type, &random_probe_label()) else {
        let (result, elapsed) = main.await;
        return Ok((result?, elapsed, None));
    };
    let probe = upstream.exchange(&probe_name, record_type);

    let main = pin!(main);
    let probe = pin!(probe);
    let ((result, elapsed), probe) = match future::select(main, probe).await {
        Either::Left(((result, elapsed), probe)) => {
            let attachable = matches!(&result, Ok(answer) if answer.has_records(record_type));
            // Regression: this awaited the probe's whole budget (two
            // timeouts) when its server never answered, stalling an answer
            // already in hand.
            let probe = if attachable {
                tokio::time::timeout(grace, probe).await.ok()
            } else {
                None
            };
            ((result, elapsed), probe)
        }
        Either::Right((probe, main)) => (main.await, Some(probe)),
    };
    let answer = result?;
    let wildcard =
        probe.and_then(|probe| wildcard_outcome(&probe_name, record_type, &answer, probe));
    Ok((answer, elapsed, wildcard))
}

/// Whether a domain appears to exist in the public DNS. Used as a
/// corroborating availability signal when registry data (RDAP/WHOIS) is
/// inconclusive — e.g. a thin/blocked WHOIS body and an RDAP failure that is
/// not an authoritative 404.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsPresence {
    /// The apex returned NS records — the domain is delegated and exists.
    Present,
    /// NXDOMAIN / empty answer — the domain has no DNS presence.
    Absent,
    /// The DNS query itself failed; presence is unknown.
    Unknown,
}

/// Maps an apex NS lookup result to a [`DnsPresence`]. Pure so the mapping is
/// unit-testable without a live resolver. `resolve(.., NS, ..)` already folds
/// NXDOMAIN/NODATA into `Ok(vec![])` (see `dns_lookup_or_empty`), so an empty
/// `Ok` is the "no presence" signal and an `Err` is a genuine query failure.
fn classify_ns_presence(result: &Result<Vec<DnsRecord>>) -> DnsPresence {
    match result {
        Ok(records) if records.is_empty() => DnsPresence::Absent,
        Ok(_) => DnsPresence::Present,
        Err(_) => DnsPresence::Unknown,
    }
}

impl DnsResolver {
    /// Probes whether a domain has any DNS presence by querying its apex NS
    /// records. A registered, delegated domain returns NS records; an
    /// unregistered domain returns NXDOMAIN (an empty record set).
    ///
    /// This is a heuristic, not proof: a registered-but-undelegated domain
    /// also has no NS records, so callers should treat
    /// [`DnsPresence::Absent`] as "likely available" (medium confidence).
    pub async fn presence(&self, domain: &str) -> DnsPresence {
        // A registration-level question: `www.example.com` means
        // `example.com` here (as it does for WHOIS/RDAP), so strip `www.`
        // explicitly — `resolve` itself now keeps it (see `prepare_query`).
        let Ok(apex) = normalize_domain(domain) else {
            return DnsPresence::Unknown;
        };
        classify_ns_presence(&self.resolve(&apex, RecordType::NS, None).await)
    }
}

/// Prepares the query name for a DNS record lookup.
///
/// Record queries are about one exact DNS name, so this normalizes with
/// [`normalize_query_name`], which — unlike [`normalize_domain`] — keeps a
/// leading `www.`: `www` routinely carries its own records (typically a
/// CNAME), and stripping it silently answered `dig www.example.com CNAME` for
/// the apex. It also accepts a leading wildcard label (`*.example.com`), so
/// the wildcard's own records can be queried like any other name.
///
/// PTR queries may be given a raw IP literal. IPv6 literals in particular must
/// NOT pass through the normalizer: its trailing-`:port` strip heuristic
/// truncates the final hextet (e.g. `::1111` → dropped) and the remaining `:`
/// separators then fail character validation, so IPv6 reverse lookups errored
/// out with "Invalid domain name" before ever reaching `resolve_ptr`. For PTR
/// queries we therefore detect an IP literal up front and pass it through in
/// canonical form; everything else (domains, and PTR queries given a
/// reverse-DNS name such as `1.1.1.1.in-addr.arpa`) is normalized as usual.
///
/// Shared (crate-internal) with compare / propagation / follow so every entry
/// point that stores or echoes the queried name agrees with what `resolve`
/// actually queries — they previously re-normalized with `normalize_domain`,
/// losing `www.` and mangling IPv6 PTR literals.
pub(crate) fn prepare_query(domain: &str, record_type: RecordType) -> Result<String> {
    prepare_query_with(domain, record_type, normalize_query_name)
}

/// [`prepare_query`] with the normalizer injected, so the IP-literal PTR path
/// is testable against a rejecting normalizer (the real one reads the
/// process-global `SEER_DOMAIN_ALLOWLIST`, which tests cannot set).
fn prepare_query_with(
    domain: &str,
    record_type: RecordType,
    normalize: impl Fn(&str) -> Result<String>,
) -> Result<String> {
    if record_type == RecordType::PTR {
        if let Ok(ip) = IpAddr::from_str(domain.trim()) {
            // `SEER_DOMAIN_ALLOWLIST` is enforced inside the normalizer, which
            // an IP literal skips. Run the name that will actually be queried
            // (the reverse-DNS name) through it, so a PTR query for an IP
            // obeys the allowlist exactly like the equivalent
            // `x.x.x.x.in-addr.arpa` query does.
            normalize(&reverse_dns_name(&ip))?;
            return Ok(ip.to_string());
        }
    }
    normalize(domain)
}

/// Parses a `dig`-style SRV query name of the form `_service._proto.name` into
/// its `(service, protocol, name)` parts, with the leading underscores
/// stripped. Returns `None` when the input is not in that shape — e.g. a bare
/// domain with no service/proto labels — so callers can surface a usage hint.
pub(crate) fn parse_srv_query(name: &str) -> Option<(String, String, String)> {
    let mut parts = name.splitn(3, '.');
    let service = parts.next()?.strip_prefix('_')?;
    let protocol = parts.next()?.strip_prefix('_')?;
    let rest = parts.next()?;
    if service.is_empty() || protocol.is_empty() || rest.is_empty() {
        return None;
    }
    Some((service.to_string(), protocol.to_string(), rest.to_string()))
}

/// Builds the validated `_service._proto.domain` SRV query name. The labels
/// are checked first (a DNS query-injection guard): a bad one is a caller
/// mistake, so it is [`SeerError::InvalidInput`], not a retryable DNS error.
fn srv_query_name(service: &str, protocol: &str, domain: &str) -> Result<String> {
    if !is_valid_srv_label(service) {
        return Err(SeerError::InvalidInput(format!(
            "invalid SRV service name: {}",
            service
        )));
    }
    if !is_valid_srv_label(protocol) {
        return Err(SeerError::InvalidInput(format!(
            "invalid SRV protocol name: {}",
            protocol
        )));
    }
    Ok(format!("_{}._{}.{}", service, protocol, domain))
}

/// The name a PTR query asks for: the reverse-DNS name of an IP literal, or
/// the (already reverse) name as given.
fn ptr_query_name(domain: &str) -> String {
    match IpAddr::from_str(domain) {
        Ok(ip) => reverse_dns_name(&ip),
        Err(_) => domain.to_string(),
    }
}

/// The name that goes on the wire for a prepared query (the output of
/// [`prepare_query`]), with `resolve`'s rules: SRV must be a valid
/// `_service._proto.name`, and PTR turns an IP literal into its reverse name.
/// Shared with the trace walker (`dns::trace`), so a trace asks for — and
/// reports — the name `query` would.
pub(crate) fn wire_query_name(domain: &str, record_type: RecordType) -> Result<String> {
    match record_type {
        RecordType::SRV => {
            let (service, protocol, name) = parse_srv_query(domain).ok_or_else(srv_format_error)?;
            srv_query_name(&service, &protocol, &name)
        }
        RecordType::PTR => Ok(ptr_query_name(domain)),
        _ => Ok(domain.to_string()),
    }
}

/// The canonical "bad SRV query name" error, shared by the single-query resolver
/// path and the propagation checker so both reject a bare-domain SRV query with
/// the identical permanent `InvalidInput` message.
pub(crate) fn srv_format_error() -> SeerError {
    SeerError::InvalidInput(
        "SRV records require service name format: _service._proto.name".to_string(),
    )
}

fn reverse_dns_name(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(addr) => {
            let octets = addr.octets();
            format!(
                "{}.{}.{}.{}.in-addr.arpa",
                octets[3], octets[2], octets[1], octets[0]
            )
        }
        IpAddr::V6(addr) => {
            let segments = addr.segments();
            // 32 hex nibbles + 31 dots + ".ip6.arpa" (9) = 72 chars
            let mut result = String::with_capacity(72);
            let mut first = true;
            for segment in segments.iter().rev() {
                for shift in [0, 4, 8, 12] {
                    if !first {
                        result.push('.');
                    }
                    first = false;
                    let nibble = (segment >> shift) & 0xF;
                    result
                        .push(char::from_digit(nibble as u32, 16).expect("nibble is always 0-15"));
                }
            }
            result.push_str(".ip6.arpa");
            result
        }
    }
}

fn parse_caa(caa: &CAA) -> (u8, String, String) {
    // hickory 0.26: CAA fields are public. `flags()` reassembles the full
    // wire flags byte — the issuer-critical bit plus the reserved bits hickory
    // keeps in `reserved_flags` — so the reported value matches what the zone
    // publishes (rebuilding it from `issuer_critical` alone dropped the
    // reserved bits). `value` is a `Vec<u8>` because RFC 8659 permits binary
    // values for unknown property types. For seer's reporting purposes the
    // common tags (issue/issuewild/iodef) are always UTF-8, so a lossy
    // conversion preserves prior behavior without panicking on the rare
    // binary case.
    let flags = caa.flags();
    let tag = caa.tag.clone();
    let value = String::from_utf8_lossy(&caa.value).to_string();
    (flags, tag, value)
}

/// Splits HTTPS/SVCB RDATA (RFC 9460) into priority, target name and
/// SvcParams in presentation form.
///
/// The presentation is built here rather than taken from hickory's
/// `Display`, which leaves a trailing comma on every list (`h3,h2,`) and
/// names unregistered keys `unknown<N>` instead of RFC 9460's `key<N>`.
fn parse_svcb(svcb: &SVCB, names: NameSpelling) -> (u16, String, Vec<SvcParam>) {
    let params = svcb
        .svc_params
        .iter()
        .map(|(key, value)| SvcParam {
            key: svc_param_key_name(*key),
            value: svc_param_value(value),
        })
        .collect();
    (svcb.svc_priority, names.spell(&svcb.target_name), params)
}

/// The RFC 9460 presentation name of a SvcParamKey: the registered name, or
/// `key<N>` (§2.1) for any other key.
fn svc_param_key_name(key: SvcParamKey) -> String {
    match key {
        SvcParamKey::Mandatory => "mandatory".to_string(),
        SvcParamKey::Alpn => "alpn".to_string(),
        SvcParamKey::NoDefaultAlpn => "no-default-alpn".to_string(),
        SvcParamKey::Port => "port".to_string(),
        SvcParamKey::Ipv4Hint => "ipv4hint".to_string(),
        SvcParamKey::EchConfigList => "ech".to_string(),
        SvcParamKey::Ipv6Hint => "ipv6hint".to_string(),
        SvcParamKey::Key(_) | SvcParamKey::Key65535 | SvcParamKey::Unknown(_) => {
            format!("key{}", u16::from(key))
        }
    }
}

/// The presentation value of a SvcParam, unquoted (RFC 9460 §2.1, §7): lists
/// are comma-separated, `ech` is base64, `no-default-alpn` is empty, and an
/// opaque value is a character-string with `\DDD` escapes.
fn svc_param_value(value: &SvcParamValue) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    fn join<T: std::fmt::Display>(items: impl Iterator<Item = T>) -> String {
        items
            .map(|item| item.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }
    match value {
        SvcParamValue::Mandatory(keys) => join(keys.0.iter().map(|k| svc_param_key_name(*k))),
        // Two levels of escaping, undone in reverse by a parser (RFC 9460
        // Appendix A.1): the value-list level first (`\` → `\\`, `,` → `\,`)
        // so a comma inside an alpn-id does not split it, then the
        // character-string level over the result — `f\oo,bar` becomes
        // `f\\\\oo\\,bar` (Appendix D.2).
        SvcParamValue::Alpn(alpn) => join(alpn.0.iter().map(|id| {
            let listed = id.replace('\\', "\\\\").replace(',', "\\,");
            escape_char_string(listed.as_bytes())
        })),
        SvcParamValue::NoDefaultAlpn => String::new(),
        SvcParamValue::Port(port) => port.to_string(),
        SvcParamValue::Ipv4Hint(hint) => join(hint.0.iter().map(|a| a.0)),
        SvcParamValue::EchConfigList(ech) => STANDARD.encode(&ech.0),
        SvcParamValue::Ipv6Hint(hint) => join(hint.0.iter().map(|aaaa| aaaa.0)),
        SvcParamValue::Unknown(opaque) => escape_char_string(&opaque.0),
    }
}

/// Renders bytes as an unquoted DNS character-string (RFC 1035 §5.1):
/// printable ASCII stays, `"` and `\` are backslash-escaped, and anything
/// else — space and control bytes included, so the value is one token —
/// becomes `\DDD`.
fn escape_char_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        match b {
            b'"' | b'\\' => {
                out.push('\\');
                out.push(char::from(b));
            }
            0x21..=0x7E => out.push(char::from(b)),
            _ => out.push_str(&format!("\\{b:03}")),
        }
    }
    out
}

/// Maps a concrete seer [`RecordType`] to the hickory wire type it queries.
///
/// `ANY` is a composite lookup (a fan-out over `ANY_TYPES`) and deliberately
/// has no wire type. `SRV` maps to its wire type, but `resolve` routes it
/// through its dedicated `_service._proto.name` path (`resolve_srv_core`), so
/// [`DnsResolver::resolve_type`] still rejects both.
pub(crate) fn wire_type(record_type: RecordType) -> Option<HickoryRecordType> {
    Some(match record_type {
        RecordType::A => HickoryRecordType::A,
        RecordType::AAAA => HickoryRecordType::AAAA,
        RecordType::CNAME => HickoryRecordType::CNAME,
        RecordType::MX => HickoryRecordType::MX,
        RecordType::NS => HickoryRecordType::NS,
        RecordType::TXT => HickoryRecordType::TXT,
        RecordType::SOA => HickoryRecordType::SOA,
        RecordType::PTR => HickoryRecordType::PTR,
        RecordType::SRV => HickoryRecordType::SRV,
        RecordType::CAA => HickoryRecordType::CAA,
        RecordType::DNSKEY => HickoryRecordType::DNSKEY,
        RecordType::DS => HickoryRecordType::DS,
        // RFC 7344 child-side copies of DS/DNSKEY, published for the parent
        // to pick up (automated DS maintenance).
        RecordType::CDS => HickoryRecordType::CDS,
        RecordType::CDNSKEY => HickoryRecordType::CDNSKEY,
        // RFC 9460 service bindings.
        RecordType::HTTPS => HickoryRecordType::HTTPS,
        RecordType::SVCB => HickoryRecordType::SVCB,
        // TLSA queries are how DANE clients discover the certificate
        // association data for a TLS endpoint. The convention is
        // `_<port>._<proto>.<host>` (e.g. `_443._tcp.example.com`); seer
        // does not enforce the label shape because TLSA is also used for
        // other transports.
        RecordType::TLSA => HickoryRecordType::TLSA,
        RecordType::SSHFP => HickoryRecordType::SSHFP,
        RecordType::NAPTR => HickoryRecordType::NAPTR,
        RecordType::ANY => return None,
    })
}

/// The canonical error for record types that cannot be resolved as a single
/// wire query, shared by every dispatch path so the message never diverges.
fn unsupported_record_type(record_type: RecordType) -> SeerError {
    SeerError::DnsError(format!("unsupported record type: {}", record_type))
}

/// Uppercase hex rendering for wire-format byte fields (DS digests, TLSA
/// certificate data, SSHFP fingerprints), matching dig's presentation.
fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect()
}

/// How [`convert_rdata`] spells the domain names inside RDATA: a CNAME,
/// PTR, SRV, HTTPS/SVCB or NAPTR target, an MX exchange, an NS host, an SOA
/// mname/rname.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NameSpelling {
    /// hickory's `Display`, which decodes IDN labels to Unicode: what
    /// [`DnsResolver::resolve`] has always returned, kept for its callers.
    Display,
    /// ASCII, an IDN label as its `xn--` A-label — the spelling of owner and
    /// query names (see `owner_name`), so every name in a result compares
    /// as written (a CNAME target equals the next hop's owner) and reads as
    /// dig prints it.
    Ascii,
}

impl NameSpelling {
    fn spell(self, name: &Name) -> String {
        match self {
            NameSpelling::Display => name.to_string(),
            NameSpelling::Ascii => name.to_ascii(),
        }
    }
}

/// Converts one hickory answer's RData into our [`RecordData`], if it is the
/// variant `record_type` asked for, spelling the names in it as `names`
/// says. Any other RData in the answer section (e.g. a CNAME returned
/// alongside A records) yields `None` and is skipped.
///
/// This is the single RData→RecordData conversion table used by every
/// resolution path.
pub(crate) fn convert_rdata(
    record_type: RecordType,
    data: &HickoryRData,
    names: NameSpelling,
) -> Option<RecordData> {
    use hickory_resolver::proto::dnssec::rdata::DNSSECRData;

    match (record_type, data) {
        (RecordType::A, HickoryRData::A(addr)) => Some(RecordData::A {
            address: addr.0.to_string(),
        }),
        (RecordType::AAAA, HickoryRData::AAAA(addr)) => Some(RecordData::AAAA {
            address: addr.0.to_string(),
        }),
        (RecordType::CNAME, HickoryRData::CNAME(cname)) => Some(RecordData::CNAME {
            target: names.spell(&cname.0),
        }),
        (RecordType::MX, HickoryRData::MX(mx)) => Some(RecordData::MX {
            preference: mx.preference,
            exchange: names.spell(&mx.exchange),
        }),
        (RecordType::NS, HickoryRData::NS(ns)) => Some(RecordData::NS {
            nameserver: names.spell(&ns.0),
        }),
        (RecordType::TXT, HickoryRData::TXT(txt)) => Some(RecordData::txt(
            txt.txt_data
                .iter()
                .map(|data| String::from_utf8_lossy(data).into_owned())
                .collect(),
        )),
        (RecordType::SOA, HickoryRData::SOA(soa)) => Some(RecordData::SOA {
            mname: names.spell(&soa.mname),
            rname: names.spell(&soa.rname),
            serial: soa.serial,
            // hickory models refresh/retry/expire as i32, but they are
            // unsigned 32-bit wire intervals. A value >= 2^31 arrives as a
            // negative i32; `try_into()` would fail and zero it out, hiding
            // the real (large) value. `as u32` reinterprets the bits to the
            // correct unsigned value instead.
            refresh: soa.refresh as u32,
            retry: soa.retry as u32,
            expire: soa.expire as u32,
            minimum: soa.minimum,
        }),
        (RecordType::PTR, HickoryRData::PTR(ptr)) => Some(RecordData::PTR {
            target: names.spell(&ptr.0),
        }),
        (RecordType::SRV, HickoryRData::SRV(srv)) => Some(RecordData::SRV {
            priority: srv.priority,
            weight: srv.weight,
            port: srv.port,
            target: names.spell(&srv.target),
        }),
        (RecordType::CAA, HickoryRData::CAA(caa)) => {
            let (flags, tag, value) = parse_caa(caa);
            Some(RecordData::CAA { flags, tag, value })
        }
        (RecordType::DNSKEY, HickoryRData::DNSSEC(DNSSECRData::DNSKEY(dnskey))) => {
            use base64::{engine::general_purpose::STANDARD, Engine};
            let public_key_buf = dnskey.public_key();
            Some(RecordData::DNSKEY {
                flags: dnskey.flags(),
                // Protocol is always 3 for DNSSEC (RFC 4034)
                protocol: 3,
                algorithm: u8::from(public_key_buf.algorithm()),
                public_key: STANDARD.encode(public_key_buf.public_bytes()),
            })
        }
        (RecordType::DS, HickoryRData::DNSSEC(DNSSECRData::DS(ds))) => Some(RecordData::DS {
            key_tag: ds.key_tag(),
            algorithm: u8::from(ds.algorithm()),
            digest_type: u8::from(ds.digest_type()),
            digest: hex_upper(ds.digest()),
        }),
        // hickory models the RFC 8078 delete request's algorithm 0 as `None`.
        (RecordType::CDS, HickoryRData::DNSSEC(DNSSECRData::CDS(cds))) => Some(RecordData::CDS {
            key_tag: cds.key_tag(),
            algorithm: cds.algorithm().map_or(0, u8::from),
            digest_type: u8::from(cds.digest_type()),
            digest: hex_upper(cds.digest()),
        }),
        (RecordType::CDNSKEY, HickoryRData::DNSSEC(DNSSECRData::CDNSKEY(cdnskey))) => {
            use base64::{engine::general_purpose::STANDARD, Engine};
            // hickory keeps the key bytes private and exposes them only as a
            // `PublicKeyBuf`, which a delete request (algorithm 0) has none
            // of. The RDATA layout is fixed (RFC 7344 §3.2, identical to
            // DNSKEY: flags(2) protocol(1) algorithm(1) key), so read the key
            // from the re-encoded RDATA — exact for every record, delete
            // requests included.
            let rdata = cdnskey.to_bytes().ok()?;
            Some(RecordData::CDNSKEY {
                flags: cdnskey.flags(),
                // Protocol is always 3 (RFC 4034); hickory rejects any other.
                protocol: 3,
                algorithm: cdnskey.algorithm().map_or(0, u8::from),
                public_key: STANDARD.encode(rdata.get(4..)?),
            })
        }
        (RecordType::HTTPS, HickoryRData::HTTPS(https)) => {
            let (priority, target, params) = parse_svcb(&https.0, names);
            Some(RecordData::HTTPS {
                priority,
                target,
                params,
            })
        }
        (RecordType::SVCB, HickoryRData::SVCB(svcb)) => {
            let (priority, target, params) = parse_svcb(svcb, names);
            Some(RecordData::SVCB {
                priority,
                target,
                params,
            })
        }
        (RecordType::TLSA, HickoryRData::TLSA(tlsa)) => Some(RecordData::TLSA {
            cert_usage: u8::from(tlsa.cert_usage),
            selector: u8::from(tlsa.selector),
            matching: u8::from(tlsa.matching),
            cert_data: hex_upper(&tlsa.cert_data),
        }),
        (RecordType::SSHFP, HickoryRData::SSHFP(sshfp)) => Some(RecordData::SSHFP {
            algorithm: u8::from(sshfp.algorithm),
            fingerprint_type: u8::from(sshfp.fingerprint_type),
            fingerprint: hex_upper(&sshfp.fingerprint),
        }),
        // flags/services/regexp are DNS <character-string>s (raw bytes);
        // they are conventionally ASCII, so a lossy decode is a faithful,
        // panic-free rendering.
        (RecordType::NAPTR, HickoryRData::NAPTR(naptr)) => Some(RecordData::NAPTR {
            order: naptr.order,
            preference: naptr.preference,
            flags: String::from_utf8_lossy(&naptr.flags).into_owned(),
            services: String::from_utf8_lossy(&naptr.services).into_owned(),
            regexp: String::from_utf8_lossy(&naptr.regexp).into_owned(),
            replacement: names.spell(&naptr.replacement),
        }),
        _ => None,
    }
}

/// The seer [`RecordType`] a hickory wire type maps to, if seer models it.
///
/// Derived from [`wire_type`] over [`RecordType::ALL`], so the two directions
/// cannot drift: a type added to `wire_type` is recognized here too.
pub(crate) fn from_wire_type(wire: HickoryRecordType) -> Option<RecordType> {
    RecordType::ALL
        .iter()
        .copied()
        .find(|t| wire_type(*t) == Some(wire))
}

/// Converts one hickory record into a [`DnsRecord`] under its real owner
/// name, typed by the record's own wire type — the conversion for any path
/// that reports a response section as-is (a CNAME chain, an authority SOA, a
/// trace hop), where records of several types and owners appear together.
///
/// The owner name is ASCII (see `owner_name`) and loses its trailing root
/// dot, matching how query names are reported; the names in the record's
/// data are ASCII too ([`NameSpelling::Ascii`]), so the result uses one
/// spelling throughout. Returns `None` for types seer does not model.
pub(crate) fn to_dns_record(record: &Record) -> Option<DnsRecord> {
    let record_type = from_wire_type(record.record_type())?;
    let data = convert_rdata(record_type, &record.data, NameSpelling::Ascii)?;
    Some(DnsRecord {
        name: owner_name(&record.name),
        record_type,
        ttl: record.ttl,
        data,
    })
}

/// A hickory name as seer reports an owner: in ASCII — an IDN label as its
/// `xn--` A-label, the spelling of the (normalized) query name it sits
/// beside — and without the trailing root dot, except for the root itself
/// (`.`). hickory's `Display` would decode A-labels to Unicode.
fn owner_name(name: &Name) -> String {
    let text = name.to_ascii();
    match text.strip_suffix('.') {
        Some(rest) if !rest.is_empty() => rest.to_string(),
        _ => text,
    }
}

/// Validates SRV service/protocol labels (alphanumeric and hyphens only, no dots)
fn is_valid_srv_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

#[cfg(test)]
mod tests {
    //! Unit tests for the pure helpers and public surface of the DNS
    //! resolver, plus hermetic mock-server tests (see the `mock_*` tests
    //! below) that exercise the full `resolve()` path against the shared
    //! loopback UDP fixture in [`crate::dns::test_support`]. Live-network
    //! variants remain `#[ignore]`d here and in the sibling modules
    //! (`dns/dnssec.rs`, `dns/follow.rs`).

    use super::*;

    /// Regression: an intermittent 5-second stall on every default-resolver
    /// lookup, and an outright `seer doctor` FAIL, on hosts that advertise an
    /// IPv6 default route but have no working IPv6 transit (RA-advertised
    /// IPv6 with no real transit is common on consumer networks).
    ///
    /// `GOOGLE` carries two IPv4 and two IPv6 addresses. hickory queries
    /// `num_concurrent_reqs` (default 2) servers in parallel, and under the
    /// default `QueryStatistics` ordering a short-lived CLI process has no
    /// statistics to order by — so roughly one run in six drew both IPv6
    /// servers, black-holed, and burned the full per-query timeout.
    ///
    /// `UserProvidedOrder` makes the first two picks deterministically the
    /// IPv4 servers. IPv6 stays in the list for IPv6-only hosts, where the
    /// IPv4 sends fail immediately with ENETUNREACH rather than timing out.
    #[test]
    fn standard_opts_pin_server_order_so_ipv4_is_tried_first() {
        let mut opts = ResolverOpts::default();
        apply_standard_opts(&mut opts, Duration::from_secs(5));
        assert_eq!(
            opts.server_ordering_strategy,
            ServerOrderingStrategy::UserProvidedOrder,
            "QueryStatistics ordering is nondeterministic in a short-lived \
             process and can draw only black-holed IPv6 servers"
        );
    }

    /// The ordering fix is only meaningful if the configured list actually
    /// starts with IPv4 servers, and only sufficient if at least
    /// `num_concurrent_reqs` of them are IPv4 — otherwise a parallel pair
    /// still includes a black-holeable IPv6 server.
    #[test]
    fn default_config_lists_enough_ipv4_servers_before_any_ipv6() {
        let config = ResolverConfig::udp_and_tcp(&GOOGLE);
        let ips: Vec<_> = config.name_servers().iter().map(|ns| ns.ip).collect();
        let concurrent = ResolverOpts::default().num_concurrent_reqs.max(1);
        assert!(
            ips.len() > concurrent,
            "expected more servers than the concurrency window: {ips:?}"
        );
        for (i, ip) in ips.iter().take(concurrent).enumerate() {
            assert!(
                ip.is_ipv4(),
                "server {i} in the concurrency window is not IPv4: {ips:?}"
            );
        }
    }

    #[test]
    fn from_config_applies_dns_timeout() {
        let mut config = crate::config::SeerConfig::default();
        config.timeouts.dns_secs = 9;
        let resolver = DnsResolver::from_config(&config);
        assert_eq!(resolver.timeout, Duration::from_secs(9));
        assert_eq!(resolver.transport.timeout(), Duration::from_secs(9));
        let rebuilt = DnsResolver::new().with_timeout(Duration::from_secs(3));
        assert_eq!(rebuilt.transport.timeout(), Duration::from_secs(3));
    }

    #[test]
    fn transport_budget_is_the_resolvers_attempts() {
        let mut opts = ResolverOpts::default();
        apply_standard_opts(&mut opts, Duration::from_secs(5));
        assert_eq!(
            opts.attempts as u32,
            crate::dns::transport::QUERY_BUDGET_TIMEOUTS
        );
    }
    use std::net::{Ipv4Addr, Ipv6Addr};

    // --- is_valid_srv_label ------------------------------------------

    #[test]
    fn srv_label_accepts_alphanumeric_and_hyphen() {
        assert!(is_valid_srv_label("http"));
        assert!(is_valid_srv_label("ldap-tls"));
        assert!(is_valid_srv_label("a1"));
        assert!(is_valid_srv_label("tcp"));
    }

    #[test]
    fn srv_label_rejects_empty() {
        assert!(!is_valid_srv_label(""));
    }

    #[test]
    fn srv_label_rejects_leading_or_trailing_hyphen() {
        assert!(!is_valid_srv_label("-http"));
        assert!(!is_valid_srv_label("http-"));
        assert!(!is_valid_srv_label("-"));
    }

    #[test]
    fn srv_label_rejects_dots() {
        // Dots would let an attacker construct `_service._tcp.evil.com.target`
        // and pivot the query to a different domain.
        assert!(!is_valid_srv_label("http.evil"));
        assert!(!is_valid_srv_label("a.b"));
    }

    #[test]
    fn srv_label_rejects_special_chars() {
        assert!(!is_valid_srv_label("http evil"));
        assert!(!is_valid_srv_label("http/evil"));
        assert!(!is_valid_srv_label("http\0"));
        assert!(!is_valid_srv_label("http\n"));
    }

    #[test]
    fn srv_label_rejects_over_63_chars() {
        let too_long = "a".repeat(64);
        assert!(!is_valid_srv_label(&too_long));
        let exactly_63 = "a".repeat(63);
        assert!(is_valid_srv_label(&exactly_63));
    }

    // --- classify_ns_presence ----------------------------------------

    #[test]
    fn classify_ns_presence_absent_on_empty_ok() {
        // resolve(.., NS) folds NXDOMAIN/NODATA into Ok(vec![]).
        let r: Result<Vec<DnsRecord>> = Ok(vec![]);
        assert_eq!(classify_ns_presence(&r), DnsPresence::Absent);
    }

    #[test]
    fn classify_ns_presence_present_on_records() {
        let rec = DnsRecord {
            name: "example.test.".to_string(),
            record_type: RecordType::NS,
            ttl: 3600,
            data: RecordData::NS {
                nameserver: "ns1.example.net.".to_string(),
            },
        };
        let r: Result<Vec<DnsRecord>> = Ok(vec![rec]);
        assert_eq!(classify_ns_presence(&r), DnsPresence::Present);
    }

    #[test]
    fn classify_ns_presence_unknown_on_error() {
        let r: Result<Vec<DnsRecord>> = Err(SeerError::DnsError("servfail".to_string()));
        assert_eq!(classify_ns_presence(&r), DnsPresence::Unknown);
    }

    // --- reverse_dns_name --------------------------------------------

    #[test]
    fn reverse_dns_name_formats_ipv4_correctly() {
        let ip: IpAddr = Ipv4Addr::new(192, 0, 2, 1).into();
        assert_eq!(reverse_dns_name(&ip), "1.2.0.192.in-addr.arpa");
    }

    #[test]
    fn reverse_dns_name_formats_ipv6_correctly() {
        // ::1 (loopback) → 32 nibbles of 0 followed by ...0.0.0.1 reversed.
        let ip: IpAddr = Ipv6Addr::LOCALHOST.into();
        let name = reverse_dns_name(&ip);
        assert!(
            name.ends_with(".ip6.arpa"),
            "must end with .ip6.arpa; got: {}",
            name
        );
        // The first nibble (most-reversed position) must be 1 (from ::1 low bit).
        assert!(
            name.starts_with("1."),
            "expected '1.' prefix, got: {}",
            name
        );
        // 32 nibbles + 31 dots + ".ip6.arpa" (9 chars) = 72.
        assert_eq!(name.len(), 72);
    }

    // --- create_custom_resolver validation ---------------------------

    #[tokio::test]
    async fn custom_resolver_rejects_invalid_input() {
        // After hostname support was added, a string that is neither a
        // valid IP nor a resolvable hostname should fail with a clear
        // "failed to resolve" error rather than panicking or hanging.
        // We pick a name that is *syntactically* impossible to resolve.
        let r = DnsResolver::new();
        let err = r.create_custom_resolver("..").await.unwrap_err();
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("dns resolution failed") || msg.contains("invalid"),
            "expected resolution failure, got: {}",
            msg
        );
    }

    #[tokio::test]
    async fn custom_resolver_rejects_private_ipv4() {
        // SSRF defense: private / reserved ranges must be blocked even
        // when passed as a literal IP rather than a hostname.
        let r = DnsResolver::new();
        for reserved in ["127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254"] {
            let err = r.create_custom_resolver(reserved).await.unwrap_err();
            let msg = err.to_string().to_lowercase();
            assert!(
                msg.contains("blocked") || msg.contains("reserved"),
                "reserved IP {} must be rejected, got error: {}",
                reserved,
                msg
            );
        }
    }

    #[tokio::test]
    async fn custom_resolver_rejects_loopback_ipv6() {
        let r = DnsResolver::new();
        let err = r.create_custom_resolver("::1").await.unwrap_err();
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("blocked") || msg.contains("reserved"),
            "::1 must be rejected, got error: {}",
            msg
        );
    }

    #[tokio::test]
    async fn custom_resolver_accepts_public_ipv4() {
        // A known public resolver IP must be acceptable.
        let r = DnsResolver::new();
        let result = r.create_custom_resolver("8.8.8.8").await;
        assert!(
            result.is_ok(),
            "8.8.8.8 must be accepted as a public nameserver, got: {:?}",
            result.err()
        );
    }

    // --- DoT/DoH: SSRF refusal parity ---------------------------------
    //
    // The reserved-IP guard must apply identically to tls:// and https://
    // specs — an encrypted transport is not a bypass of the SSRF policy.

    #[tokio::test]
    async fn custom_resolver_rejects_private_ip_for_dot_and_doh() {
        let r = DnsResolver::new();
        for reserved in [
            "tls://127.0.0.1",
            "tls://192.168.1.1:853",
            "tls://[::1]",
            "https://10.0.0.1/dns-query",
            "https://169.254.169.254",
            "tls://[fd00::1]:853",
        ] {
            let err = r.create_custom_resolver(reserved).await.unwrap_err();
            let msg = err.to_string().to_lowercase();
            assert!(
                msg.contains("blocked") || msg.contains("reserved"),
                "reserved spec {} must be rejected, got error: {}",
                reserved,
                msg
            );
        }
        // DoH to an IPv6 literal is refused even earlier, at parse time
        // (it can never work — see `NameserverSpec::parse`).
        let err = r
            .create_custom_resolver("https://[fd00::1]:443/dns-query")
            .await
            .unwrap_err();
        assert!(matches!(err, SeerError::InvalidInput(_)), "{err:?}");
    }

    #[tokio::test]
    async fn custom_resolver_accepts_public_dot_and_doh_literals() {
        // Construction (parse → validate → config build) must succeed for
        // public DoT/DoH IP literals without any network traffic.
        let r = DnsResolver::new();
        for spec in ["tls://1.1.1.1", "https://8.8.8.8/dns-query"] {
            let result = r.create_custom_resolver(spec).await;
            assert!(
                result.is_ok(),
                "{} must be accepted, got: {:?}",
                spec,
                result.err()
            );
        }
    }

    #[tokio::test]
    async fn custom_resolver_rejects_unknown_scheme() {
        let r = DnsResolver::new();
        let err = r.create_custom_resolver("ftp://8.8.8.8").await.unwrap_err();
        assert!(
            matches!(err, SeerError::InvalidInput(_)),
            "unknown scheme must be an input error, got: {err:?}"
        );
    }

    // --- build_upstream_config: protocol/port/tls-name construction ----

    fn spec(s: &str) -> NameserverSpec {
        NameserverSpec::parse(s).unwrap_or_else(|e| panic!("{s:?} must parse: {e}"))
    }

    #[test]
    fn upstream_config_udp_defaults() {
        use hickory_resolver::config::ProtocolConfig;

        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let config = build_upstream_config(&spec("8.8.8.8"), &[ip], None);
        let servers = config.name_servers();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].ip, ip);
        assert_eq!(servers[0].connections.len(), 1);
        assert_eq!(servers[0].connections[0].port, 53);
        assert!(matches!(
            servers[0].connections[0].protocol,
            ProtocolConfig::Udp
        ));
    }

    #[test]
    fn upstream_config_udp_explicit_port() {
        let ip: IpAddr = "9.9.9.9".parse().unwrap();
        let config = build_upstream_config(&spec("9.9.9.9:5353"), &[ip], None);
        assert_eq!(config.name_servers()[0].connections[0].port, 5353);
    }

    #[test]
    fn upstream_config_tls_sets_protocol_port_and_server_name() {
        use hickory_resolver::config::ProtocolConfig;

        let ip: IpAddr = "9.9.9.9".parse().unwrap();
        let config = build_upstream_config(&spec("tls://dns.quad9.net"), &[ip], None);
        let ns = &config.name_servers()[0];
        assert_eq!(ns.ip, ip);
        assert_eq!(ns.connections.len(), 1);
        assert_eq!(ns.connections[0].port, 853);
        match &ns.connections[0].protocol {
            ProtocolConfig::Tls { server_name } => {
                assert_eq!(&**server_name, "dns.quad9.net");
            }
            other => panic!("expected Tls protocol, got {other:?}"),
        }
    }

    #[test]
    fn upstream_config_tls_ip_literal_uses_ip_as_server_name() {
        use hickory_resolver::config::ProtocolConfig;

        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        let config = build_upstream_config(&spec("tls://1.1.1.1"), &[ip], None);
        match &config.name_servers()[0].connections[0].protocol {
            ProtocolConfig::Tls { server_name } => assert_eq!(&**server_name, "1.1.1.1"),
            other => panic!("expected Tls protocol, got {other:?}"),
        }
    }

    #[test]
    fn upstream_config_https_sets_protocol_port_path_and_server_name() {
        use hickory_resolver::config::ProtocolConfig;

        let ip: IpAddr = "104.16.248.249".parse().unwrap();
        let config = build_upstream_config(&spec("https://cloudflare-dns.com"), &[ip], None);
        let ns = &config.name_servers()[0];
        assert_eq!(ns.connections[0].port, 443);
        match &ns.connections[0].protocol {
            ProtocolConfig::Https { server_name, path } => {
                assert_eq!(&**server_name, "cloudflare-dns.com");
                assert_eq!(&**path, "/dns-query");
            }
            other => panic!("expected Https protocol, got {other:?}"),
        }
    }

    #[test]
    fn upstream_config_https_custom_port_and_path() {
        use hickory_resolver::config::ProtocolConfig;

        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let config = build_upstream_config(&spec("https://dns.google:8443/resolve"), &[ip], None);
        let ns = &config.name_servers()[0];
        assert_eq!(ns.connections[0].port, 8443);
        match &ns.connections[0].protocol {
            ProtocolConfig::Https { server_name, path } => {
                assert_eq!(&**server_name, "dns.google");
                assert_eq!(&**path, "/resolve");
            }
            other => panic!("expected Https protocol, got {other:?}"),
        }
    }

    #[test]
    fn upstream_config_multiple_ips_share_spec() {
        // A hostname spec resolving to several addresses gets one upstream
        // per IP, all speaking the same protocol/port/TLS name.
        use hickory_resolver::config::ProtocolConfig;

        let ips: Vec<IpAddr> = vec![
            "9.9.9.9".parse().unwrap(),
            "149.112.112.112".parse().unwrap(),
        ];
        let config = build_upstream_config(&spec("tls://dns.quad9.net"), &ips, None);
        let servers = config.name_servers();
        assert_eq!(servers.len(), 2);
        for (ns, expected_ip) in servers.iter().zip(&ips) {
            assert_eq!(&ns.ip, expected_ip);
            assert_eq!(ns.connections[0].port, 853);
            assert!(matches!(
                &ns.connections[0].protocol,
                ProtocolConfig::Tls { server_name } if &**server_name == "dns.quad9.net"
            ));
        }
    }

    /// Regression: every dual-stack hostname nameserver (`dns.google`,
    /// `tls://one.one.one.one`, `https://cloudflare-dns.com/dns-query`) timed
    /// out on hosts with an IPv6 default route but no IPv6 transit, while IP
    /// literals worked. The bootstrap `lookup_ip` returns AAAA before A, the
    /// upstream list kept that order, and the pool's first parallel pair was
    /// both IPv6 — which spent the whole per-query deadline before any IPv4
    /// entry was tried.
    #[test]
    fn upstream_config_orders_ipv4_before_ipv6() {
        // As hickory's `lookup_ip` returns them: AAAA records first.
        let ips: Vec<IpAddr> = [
            "2606:4700::6810:f8f9",
            "2606:4700::6810:f9f9",
            "104.16.248.249",
            "104.16.249.249",
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
        let config =
            build_upstream_config(&spec("https://cloudflare-dns.com/dns-query"), &ips, None);
        let order: Vec<IpAddr> = config.name_servers().iter().map(|ns| ns.ip).collect();
        assert_eq!(
            order,
            [ips[2], ips[3], ips[0], ips[1]],
            "IPv4 first, each family in resolved order, nothing dropped"
        );
        let concurrent = ResolverOpts::default().num_concurrent_reqs.max(1);
        assert!(
            order.iter().take(concurrent).all(IpAddr::is_ipv4),
            "the parallel window must be all IPv4: {order:?}"
        );
    }

    #[test]
    fn upstream_config_test_port_override_wins() {
        // The #[cfg(test)] mock-server seam must override the spec's port.
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let config = build_upstream_config(&spec("127.0.0.1"), &[ip], Some(9999));
        assert_eq!(config.name_servers()[0].connections[0].port, 9999);
    }

    #[tokio::test]
    async fn query_asks_dot_and_doh_servers_through_the_vetted_config() {
        // `query` sends to the servers of `custom_upstream_config` — the one
        // the resolver for `resolve` is built from — so a DoT or DoH spec is
        // asked over TLS, with its host as the TLS server name (checked
        // against the certificate), and DoH on its path. Built without any
        // network traffic for IP literals.
        use hickory_resolver::config::ProtocolConfig;

        let r = DnsResolver::new();
        let dot = r.custom_upstream_config("tls://1.1.1.1").await.unwrap();
        let [server] = dot.name_servers() else {
            panic!("one server per address: {dot:?}");
        };
        assert_eq!(server.ip, IpAddr::from([1, 1, 1, 1]));
        assert_eq!(server.connections.len(), 1);
        assert_eq!(server.connections[0].port, 853);
        assert!(matches!(
            &server.connections[0].protocol,
            ProtocolConfig::Tls { server_name } if &**server_name == "1.1.1.1"
        ));

        let doh = r
            .custom_upstream_config("https://8.8.8.8/dns-query")
            .await
            .unwrap();
        let [server] = doh.name_servers() else {
            panic!("one server per address: {doh:?}");
        };
        assert_eq!(server.connections[0].port, 443);
        assert!(matches!(
            &server.connections[0].protocol,
            ProtocolConfig::Https { server_name, path }
                if &**server_name == "8.8.8.8" && &**path == "/dns-query"
        ));

        // A bare spec is UDP on port 53 (a truncated reply is repeated over
        // TCP by the transport, not configured here).
        let udp = r.custom_upstream_config("9.9.9.9").await.unwrap();
        assert_eq!(udp.name_servers()[0].connections[0].port, 53);
        assert!(matches!(
            udp.name_servers()[0].connections[0].protocol,
            ProtocolConfig::Udp
        ));
        // The default upstream is Google's, IPv4 first.
        let Upstream::Direct { config, .. } = r.query_upstream("seer.test", None).await.unwrap()
        else {
            panic!("a public name is sent to the default upstream");
        };
        assert!(config.name_servers()[0].ip.is_ipv4());
    }

    // --- Live DoT/DoH queries (opt-in only) ----------------------------

    #[tokio::test]
    #[ignore = "live network — DoT query against Cloudflare"]
    async fn live_query_over_dot() {
        let result = DnsResolver::new()
            .query("example.com", RecordType::A, Some("tls://1.1.1.1"))
            .await
            .expect("DoT query should get a response");
        assert_eq!(result.status, DnsStatus::NoError);
        assert!(result.flags.contains(&"qr".to_string()), "{result:?}");
        assert!(result.records().count() > 0, "expected A records over DoT");
    }

    #[tokio::test]
    #[ignore = "live network — DoH query against Cloudflare"]
    async fn live_query_over_doh() {
        let result = DnsResolver::new()
            .query(
                "example.com",
                RecordType::A,
                Some("https://cloudflare-dns.com/dns-query"),
            )
            .await
            .expect("DoH query should get a response");
        assert_eq!(result.status, DnsStatus::NoError);
        assert!(result.records().count() > 0, "expected A records over DoH");
    }

    #[tokio::test]
    #[ignore = "live network — NXDOMAIN keeps its header"]
    async fn live_query_nxdomain_has_flags_and_the_soa() {
        let result = DnsResolver::new()
            // `.example` is reserved (RFC 2606): the root says NXDOMAIN.
            .query("seer-does-not-exist.example", RecordType::A, None)
            .await
            .expect("a negative answer is a result");
        assert_eq!(result.status, DnsStatus::NxDomain);
        assert!(result.flags.contains(&"qr".to_string()), "{result:?}");
        assert!(
            result
                .authority
                .iter()
                .any(|r| r.record_type == RecordType::SOA),
            "{result:?}"
        );
    }

    #[tokio::test]
    #[ignore = "live network — DoT query against Cloudflare"]
    async fn live_resolve_over_dot() {
        let r = DnsResolver::new();
        let records = r
            .resolve("example.com", RecordType::A, Some("tls://1.1.1.1"))
            .await
            .expect("DoT lookup should succeed");
        assert!(!records.is_empty(), "expected A records over DoT");
    }

    #[tokio::test]
    #[ignore = "live network — DoH query against Cloudflare"]
    async fn live_resolve_over_doh() {
        let r = DnsResolver::new();
        let records = r
            .resolve(
                "example.com",
                RecordType::A,
                Some("https://cloudflare-dns.com/dns-query"),
            )
            .await
            .expect("DoH lookup should succeed");
        assert!(!records.is_empty(), "expected A records over DoH");
    }

    // --- SRV query validation (integration between helper + resolver) ----

    #[tokio::test]
    async fn resolve_srv_rejects_invalid_service_label() {
        let r = DnsResolver::new();
        // With_dot service name would construct a malformed DNS query.
        let result = r
            .resolve_srv_core(&r.default_resolver, "http.evil", "tcp", "example.com")
            .await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string().to_lowercase();
        assert!(
            msg.contains("invalid srv service"),
            "expected SRV service validation error, got: {}",
            msg
        );
    }

    #[tokio::test]
    async fn resolve_srv_rejects_invalid_protocol_label() {
        let r = DnsResolver::new();
        let result = r
            .resolve_srv_core(&r.default_resolver, "http", "tcp.evil", "example.com")
            .await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string().to_lowercase();
        assert!(
            msg.contains("invalid srv protocol"),
            "expected SRV protocol validation error, got: {}",
            msg
        );
    }

    #[tokio::test]
    async fn resolve_srv_normalizes_and_validates_domain_input() {
        // SRV names must be normalized/validated like every other query, or
        // garbage input reaches query construction as a (misclassified) DNS
        // failure instead of an input error (2026-07-11 review).
        let r = DnsResolver::new();
        let result = r
            .resolve("_http._tcp.not a valid domain", RecordType::SRV, None)
            .await;
        assert!(
            matches!(result, Err(SeerError::InvalidDomain(_))),
            "expected InvalidDomain from domain validation, got: {result:?}"
        );
    }

    // --- Normalization applied before resolution ---------------------

    #[tokio::test]
    async fn resolve_normalizes_uppercase_domain_input() {
        // We can't hit the network in unit tests, but we can at least
        // assert that normalization rejects clearly-invalid input
        // before any network call is made. Domains with a leading `.`
        // are rejected by the normalizer.
        let r = DnsResolver::new();
        let result = r.resolve(".bad.example", RecordType::A, None).await;
        assert!(result.is_err(), "leading-dot domain must be rejected");
    }

    // --- SRV record -------------------------------------------------

    // --- SRV via dig-style names (parse_srv_query) -------------------

    #[test]
    fn parse_srv_query_extracts_service_proto_and_name() {
        assert_eq!(
            parse_srv_query("_sip._tcp.example.com"),
            Some((
                "sip".to_string(),
                "tcp".to_string(),
                "example.com".to_string()
            ))
        );
    }

    #[test]
    fn parse_srv_query_keeps_multilabel_domain() {
        assert_eq!(
            parse_srv_query("_sip._tcp.sip.voice.google.com"),
            Some((
                "sip".to_string(),
                "tcp".to_string(),
                "sip.voice.google.com".to_string()
            ))
        );
    }

    #[test]
    fn fqdn_appends_root_dot_once() {
        assert_eq!(fqdn("example.com"), "example.com.");
        assert_eq!(fqdn("example.com."), "example.com.");
    }

    #[test]
    fn parse_srv_query_rejects_bare_domain() {
        assert_eq!(parse_srv_query("example.com"), None);
    }

    #[test]
    fn parse_srv_query_rejects_missing_proto_label() {
        // Second label must be an `_proto` label.
        assert_eq!(parse_srv_query("_sip.example.com"), None);
    }

    #[tokio::test]
    async fn resolve_rejects_bare_domain_for_srv_as_input_error() {
        // A bare domain (no _service._proto labels) cannot be an SRV query.
        // This is a usage/input error — NOT a transient DNS failure — so it
        // must surface as InvalidInput (which maps to a permanent, non-retryable
        // signal across the Python/MCP boundary), and still carry the hint.
        let r = DnsResolver::new();
        let err = r
            .resolve("example.com", RecordType::SRV, None)
            .await
            .expect_err("bare-domain SRV must error");
        assert!(
            matches!(err, SeerError::InvalidInput(_)),
            "bare-domain SRV should be an input error, got: {err:?}"
        );
        assert!(err.to_string().contains("_service._proto"));
    }

    #[tokio::test]
    #[ignore = "live network"]
    async fn resolve_srv_via_dig_style_name_returns_records() {
        // _caldavs._tcp.google.com is a long-standing public SRV record
        // (CalDAV discovery → calendar.google.com:443).
        let r = DnsResolver::new();
        let records = r
            .resolve("_caldavs._tcp.google.com", RecordType::SRV, None)
            .await
            .expect("dig-style SRV lookup should succeed");
        assert!(!records.is_empty(), "expected SRV records");
        assert!(records.iter().all(|r| r.record_type == RecordType::SRV));
    }

    #[tokio::test]
    #[ignore = "live network"]
    async fn resolve_naptr_returns_records() {
        // sip2sip.info publishes stable NAPTR records for SIP discovery.
        let r = DnsResolver::new();
        let records = r
            .resolve("sip2sip.info", RecordType::NAPTR, None)
            .await
            .expect("NAPTR lookup should succeed");
        assert!(!records.is_empty(), "expected NAPTR records");
        assert!(records.iter().all(|r| r.record_type == RecordType::NAPTR));
    }

    // --- prepare_query: PTR must accept raw IP literals (incl. IPv6) --

    #[test]
    fn prepare_query_passes_ipv6_literal_through_for_ptr() {
        // Regression: normalize_domain's port-strip heuristic mangled IPv6
        // literals (the trailing `:1111` group looks like a `:port`), so IPv6
        // reverse lookups failed with "Invalid domain name" before ever
        // reaching resolve_ptr. PTR queries for IP literals must bypass domain
        // normalization.
        let out = prepare_query("2606:4700:4700::1111", RecordType::PTR).unwrap();
        assert_eq!(out, "2606:4700:4700::1111");
    }

    #[test]
    fn prepare_query_passes_ipv6_loopback_through_for_ptr() {
        let out = prepare_query("::1", RecordType::PTR).unwrap();
        assert_eq!(out, "::1");
    }

    #[test]
    fn prepare_query_passes_ipv4_literal_through_for_ptr() {
        let out = prepare_query("8.8.8.8", RecordType::PTR).unwrap();
        assert_eq!(out, "8.8.8.8");
    }

    #[test]
    fn prepare_query_normalizes_non_ip_ptr_names() {
        // A reverse-DNS name (not an IP literal) still gets normalized.
        let out = prepare_query("1.1.1.1.in-addr.arpa", RecordType::PTR).unwrap();
        assert_eq!(out, "1.1.1.1.in-addr.arpa");
    }

    #[test]
    fn prepare_query_keeps_www_for_record_queries() {
        // Regression: record queries normalized with `normalize_domain`,
        // which strips `www.` — so `dig www.example.com CNAME` silently
        // queried the apex. A record query is about the exact name.
        let out = prepare_query("HTTPS://WWW.Example.com/path", RecordType::A).unwrap();
        assert_eq!(out, "www.example.com");
        let out = prepare_query("www.example.com", RecordType::CNAME).unwrap();
        assert_eq!(out, "www.example.com");
    }

    #[test]
    fn prepare_query_still_normalizes_scheme_port_path_and_case() {
        let out = prepare_query("https://API.Example.COM:8443/v1?q=1#frag", RecordType::A).unwrap();
        assert_eq!(out, "api.example.com");
        let out = prepare_query("example.com.", RecordType::MX).unwrap();
        assert_eq!(out, "example.com");
        assert!(prepare_query("not a domain", RecordType::A).is_err());
    }

    #[test]
    fn prepare_query_accepts_a_leading_wildcard_label() {
        // Regression: `dig *.example.com` failed with "Invalid domain name"
        // because the query name went through the host normalizer, which
        // rejects `*`. Querying a wildcard owner name is ordinary DNS.
        let out = prepare_query("*.Example.com.", RecordType::A).unwrap();
        assert_eq!(out, "*.example.com");
        let out = prepare_query("*.1.168.192.in-addr.arpa", RecordType::PTR).unwrap();
        assert_eq!(out, "*.1.168.192.in-addr.arpa");
        // Only the whole leftmost label may be `*`.
        assert!(prepare_query("a.*.example.com", RecordType::A).is_err());
        assert!(prepare_query("a*.example.com", RecordType::A).is_err());
    }

    #[test]
    fn prepare_query_runs_ptr_ip_literal_through_the_normalizer() {
        // Regression: an IP literal skipped the normalizer entirely, and with
        // it the `SEER_DOMAIN_ALLOWLIST` check that lives inside — so a PTR
        // query for an IP bypassed the allowlist that the equivalent
        // `in-addr.arpa` query obeys. Simulate an allowlist that excludes
        // the reverse zones with a rejecting normalizer.
        let deny_arpa = |name: &str| -> Result<String> {
            if name.ends_with(".arpa") {
                Err(SeerError::DomainNotAllowed {
                    domain: name.to_string(),
                    tld: "arpa".to_string(),
                })
            } else {
                Ok(name.to_string())
            }
        };
        for ip in ["192.0.2.1", "2606:4700:4700::1111"] {
            let err = prepare_query_with(ip, RecordType::PTR, deny_arpa)
                .expect_err("PTR for an IP literal must obey the normalizer");
            assert!(matches!(err, SeerError::DomainNotAllowed { .. }), "{err:?}");
        }
        // With the real normalizer (no allowlist in tests) both still pass.
        assert_eq!(
            prepare_query_with("192.0.2.1", RecordType::PTR, normalize_query_name).unwrap(),
            "192.0.2.1"
        );
    }

    #[test]
    fn from_wire_type_inverts_wire_type_for_every_single_type() {
        for record_type in RecordType::ALL.iter().copied() {
            match wire_type(record_type) {
                Some(wire) => assert_eq!(from_wire_type(wire), Some(record_type)),
                None => assert_eq!(record_type, RecordType::ANY),
            }
        }
        // SRV has a wire type (so an SRV answer converts under its owner);
        // types seer does not model have none.
        assert_eq!(
            from_wire_type(HickoryRecordType::SRV),
            Some(RecordType::SRV)
        );
        assert_eq!(from_wire_type(HickoryRecordType::RRSIG), None);
    }

    #[test]
    fn to_dns_record_keeps_the_real_owner_and_type() {
        let cname = Record::from_rdata(
            Name::from_ascii("www.seer.test.").unwrap(),
            300,
            HickoryRData::CNAME(hickory_resolver::proto::rr::rdata::CNAME(
                Name::from_ascii("edge.cdn.test.").unwrap(),
            )),
        );
        let converted = to_dns_record(&cname).expect("CNAME is modeled");
        assert_eq!(converted.name, "www.seer.test");
        assert_eq!(converted.record_type, RecordType::CNAME);
        assert_eq!(converted.ttl, 300);
        assert_eq!(converted.data.to_string(), "edge.cdn.test.");

        let a = Record::from_rdata(
            Name::from_ascii("edge.cdn.test.").unwrap(),
            60,
            HickoryRData::A(hickory_resolver::proto::rr::rdata::A(Ipv4Addr::new(
                192, 0, 2, 7,
            ))),
        );
        let converted = to_dns_record(&a).expect("A is modeled");
        assert_eq!(converted.name, "edge.cdn.test");
        assert_eq!(converted.record_type, RecordType::A);

        assert_eq!(owner_name(&Name::root()), ".");
        // An IDN owner keeps its A-label, the spelling of the query name.
        assert_eq!(
            owner_name(&Name::from_utf8("bücher.seer.test.").unwrap()),
            "xn--bcher-kva.seer.test"
        );
    }

    #[test]
    fn to_dns_record_spells_rdata_names_as_a_labels_where_resolve_keeps_unicode() {
        use hickory_resolver::proto::rr::rdata::{CNAME, MX, SOA, SRV};
        let idn = |name: &str| Name::from_utf8(name).unwrap();
        let data = |rdata: HickoryRData| {
            let record = Record::from_rdata(idn("xn--bcher-kva.seer.test."), 300, rdata);
            to_dns_record(&record).expect("modeled").data.to_string()
        };
        // Regression: RDATA names used hickory's Unicode `Display`, so a
        // CNAME target (`edge.café.test.`) never equalled the next hop's
        // A-label owner (`edge.xn--caf-dma.test`).
        assert_eq!(
            data(HickoryRData::CNAME(CNAME(idn("edge.café.test.")))),
            "edge.xn--caf-dma.test."
        );
        assert_eq!(
            data(HickoryRData::MX(MX::new(10, idn("mail.café.test.")))),
            "10 mail.xn--caf-dma.test."
        );
        assert_eq!(
            data(HickoryRData::SRV(SRV::new(
                1,
                5,
                443,
                idn("sip.café.test.")
            ))),
            "1 5 443 sip.xn--caf-dma.test."
        );
        assert_eq!(
            data(HickoryRData::SOA(SOA::new(
                idn("ns1.café.test."),
                idn("hostmaster.café.test."),
                1,
                7200,
                3600,
                1209600,
                300,
            ))),
            "ns1.xn--caf-dma.test. hostmaster.xn--caf-dma.test. 1 7200 3600 1209600 300"
        );

        // `resolve`'s conversion keeps its long-standing Unicode spelling.
        let cname = HickoryRData::CNAME(CNAME(idn("edge.café.test.")));
        assert_eq!(
            convert_rdata(RecordType::CNAME, &cname, NameSpelling::Display)
                .expect("modeled")
                .to_string(),
            "edge.café.test."
        );
    }

    #[test]
    fn parse_caa_keeps_reserved_flag_bits() {
        // Regression: flags were rebuilt from `issuer_critical` alone, so a
        // record published with reserved bits set reported flags=128/0.
        let mut caa = CAA::new_issue(
            true,
            Some(Name::from_ascii("letsencrypt.org").unwrap()),
            vec![],
        );
        caa.reserved_flags = 0x01;
        let (flags, tag, value) = parse_caa(&caa);
        assert_eq!(flags, 0x81);
        assert_eq!(tag, "issue");
        assert_eq!(value, "letsencrypt.org");
    }

    #[test]
    fn alpn_ids_are_escaped_at_both_levels() {
        use hickory_resolver::proto::rr::rdata::svcb::Alpn;
        let alpn = |ids: &[&str]| {
            svc_param_value(&SvcParamValue::Alpn(Alpn(
                ids.iter().map(|id| id.to_string()).collect(),
            )))
        };
        assert_eq!(alpn(&["h3", "h2"]), "h3,h2");
        // Regression: a comma or backslash inside an alpn-id was escaped once,
        // so a parser's character-string pass consumed the escape and the
        // value-list pass then split `a,b` in two and dropped the `\`. The
        // expected strings are raw: `a\\,b` and `x\\\\y` as written here.
        assert_eq!(alpn(&["a,b"]), r"a\\,b");
        assert_eq!(alpn(&[r"x\y"]), r"x\\\\y");
        // RFC 9460 Appendix D.2's vector: alpn-ids `f\oo,bar` and `h2`.
        assert_eq!(alpn(&[r"f\oo,bar", "h2"]), r"f\\\\oo\\,bar,h2");
    }

    // --- Hermetic mock-server tests -----------------------------------
    //
    // These exercise the full resolve() / query() path (normalization →
    // custom-resolver construction → hickory transport → RData conversion)
    // against the shared loopback fixture in `crate::dns::test_support`,
    // without touching the network. The SSRF guards deliberately refuse
    // loopback, so the resolver under test uses the `#[cfg(test)]`-only
    // `allowing_private_hosts` / `with_port` seams, which do not exist in
    // release builds.

    use crate::dns::query::DnsStatus;
    use crate::dns::test_support::{
        a_rdata, cname_rdata, mock_dns_resolver, mock_dns_resolver_default, record, spawn_mock_dns,
        spawn_mock_dns_fn, spawn_mock_dns_fn_with_tcp, MockMode, MockReply,
    };
    use hickory_resolver::proto::op::ResponseCode;

    async fn mock_zone_lookup(record_type: RecordType, domain: &str) -> Vec<DnsRecord> {
        let port = spawn_mock_dns(MockMode::Zone).await;
        mock_dns_resolver(port)
            .resolve(domain, record_type, Some("127.0.0.1"))
            .await
            .unwrap_or_else(|e| panic!("{record_type} lookup against mock must succeed: {e}"))
    }

    #[tokio::test]
    async fn mock_resolve_a_returns_addresses() {
        let records = mock_zone_lookup(RecordType::A, "seer.test").await;
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|r| r.record_type == RecordType::A));
        assert_eq!(records[0].name, "seer.test");
        assert_eq!(records[0].ttl, 300);
        let addresses: Vec<String> = records
            .iter()
            .map(|r| match &r.data {
                RecordData::A { address } => address.clone(),
                other => panic!("expected A data, got {other:?}"),
            })
            .collect();
        assert!(addresses.contains(&"192.0.2.1".to_string()));
        assert!(addresses.contains(&"192.0.2.2".to_string()));
    }

    #[tokio::test]
    async fn mock_resolve_mx_sorts_by_preference() {
        let records = mock_zone_lookup(RecordType::MX, "seer.test").await;
        let prefs: Vec<u16> = records
            .iter()
            .map(|r| match &r.data {
                RecordData::MX { preference, .. } => *preference,
                other => panic!("expected MX data, got {other:?}"),
            })
            .collect();
        // The zone serves 30, 10, 20 — resolve() must sort ascending.
        assert_eq!(prefs, vec![10, 20, 30]);
        assert!(matches!(
            &records[0].data,
            RecordData::MX { exchange, .. } if exchange == "a.mail.seer.test."
        ));
    }

    #[tokio::test]
    async fn mock_resolve_txt_joins_character_strings() {
        let records = mock_zone_lookup(RecordType::TXT, "seer.test").await;
        assert_eq!(records.len(), 1);
        match &records[0].data {
            RecordData::TXT { text, strings } => {
                assert_eq!(text, "v=spf1 -all");
                assert_eq!(strings, &["v=spf1 ", "-all"], "the strings as sent");
            }
            other => panic!("expected TXT data, got {other:?}"),
        }
        assert_eq!(records[0].data.to_string(), r#""v=spf1 " "-all""#);
    }

    #[tokio::test]
    async fn mock_resolve_soa_maps_all_fields() {
        let records = mock_zone_lookup(RecordType::SOA, "seer.test").await;
        assert_eq!(records.len(), 1);
        match &records[0].data {
            RecordData::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                assert_eq!(mname, "ns1.seer.test.");
                assert_eq!(rname, "hostmaster.seer.test.");
                assert_eq!(*serial, 2026070101);
                assert_eq!(*refresh, 7200);
                assert_eq!(*retry, 3600);
                assert_eq!(*expire, 1209600);
                assert_eq!(*minimum, 300);
            }
            other => panic!("expected SOA data, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn mock_resolve_caa_maps_flags_tag_and_value() {
        let records = mock_zone_lookup(RecordType::CAA, "seer.test").await;
        assert_eq!(records.len(), 2);
        let by_tag = |wanted: &str| {
            records
                .iter()
                .find_map(|r| match &r.data {
                    RecordData::CAA { flags, tag, value } if tag == wanted => {
                        Some((*flags, value.clone()))
                    }
                    _ => None,
                })
                .unwrap_or_else(|| panic!("expected a CAA record with tag {wanted}"))
        };
        // issuer_critical=false → flags 0; true → 128 (RFC 8659 critical bit).
        assert_eq!(by_tag("issue"), (0, "letsencrypt.org".to_string()));
        assert_eq!(
            by_tag("iodef"),
            (128, "mailto:security@seer.test".to_string())
        );
    }

    #[tokio::test]
    async fn mock_resolve_tlsa_hex_encodes_cert_data() {
        let records = mock_zone_lookup(RecordType::TLSA, "_443._tcp.seer.test").await;
        assert_eq!(records.len(), 1);
        match &records[0].data {
            RecordData::TLSA {
                cert_usage,
                selector,
                matching,
                cert_data,
            } => {
                assert_eq!((*cert_usage, *selector, *matching), (3, 1, 1));
                assert_eq!(cert_data, "ABCD01");
            }
            other => panic!("expected TLSA data, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn mock_resolve_sshfp_hex_encodes_fingerprint() {
        let records = mock_zone_lookup(RecordType::SSHFP, "seer.test").await;
        assert_eq!(records.len(), 1);
        match &records[0].data {
            RecordData::SSHFP {
                algorithm,
                fingerprint_type,
                fingerprint,
            } => {
                assert_eq!((*algorithm, *fingerprint_type), (4, 2));
                assert_eq!(fingerprint, "DEADBEEF");
            }
            other => panic!("expected SSHFP data, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn mock_resolve_naptr_decodes_character_strings() {
        let records = mock_zone_lookup(RecordType::NAPTR, "seer.test").await;
        assert_eq!(records.len(), 1);
        match &records[0].data {
            RecordData::NAPTR {
                order,
                preference,
                flags,
                services,
                regexp,
                replacement,
            } => {
                assert_eq!((*order, *preference), (100, 50));
                assert_eq!(flags, "U");
                assert_eq!(services, "E2U+sip");
                assert_eq!(regexp, "!^.*$!sip:info@seer.test!");
                assert_eq!(replacement, ".");
            }
            other => panic!("expected NAPTR data, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn mock_resolve_srv_via_dig_style_name() {
        let records = mock_zone_lookup(RecordType::SRV, "_sip._tcp.seer.test").await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, "_sip._tcp.seer.test");
        match &records[0].data {
            RecordData::SRV {
                priority,
                weight,
                port,
                target,
            } => {
                assert_eq!((*priority, *weight, *port), (10, 5, 5060));
                assert_eq!(target, "sipserver.seer.test.");
            }
            other => panic!("expected SRV data, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn mock_resolve_ptr_transforms_ip_literal() {
        let records = mock_zone_lookup(RecordType::PTR, "192.0.2.1").await;
        assert_eq!(records.len(), 1);
        // The record is reported under the reverse-DNS name, not the raw IP.
        assert_eq!(records[0].name, "1.2.0.192.in-addr.arpa");
        assert!(matches!(
            &records[0].data,
            RecordData::PTR { target } if target == "ptr.seer.test."
        ));
    }

    #[tokio::test]
    async fn mock_resolve_keeps_www_label() {
        // Regression: `resolve("www.x", CNAME)` queried `x` (normalize_domain
        // strips `www.`), which has no CNAME — an empty, wrong answer.
        let records = mock_zone_lookup(RecordType::CNAME, "www.seer.test").await;
        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(records[0].name, "www.seer.test");
        assert_eq!(records[0].data.to_string(), "edge.cdn.test.");
    }

    #[tokio::test]
    async fn mock_resolve_srv_keeps_www_label() {
        let port = spawn_mock_dns_fn(|qname, qtype| match (qname, qtype) {
            ("_sip._tcp.www.seer.test", HickoryRecordType::SRV) => {
                MockReply::Answer(vec![HickoryRData::SRV(
                    hickory_resolver::proto::rr::rdata::SRV::new(
                        10,
                        5,
                        5060,
                        Name::from_ascii("sip.seer.test.").unwrap(),
                    ),
                )])
            }
            _ => MockReply::NoData,
        })
        .await;
        let records = mock_dns_resolver(port)
            .resolve(
                "_sip._tcp.www.seer.test",
                RecordType::SRV,
                Some("127.0.0.1"),
            )
            .await
            .expect("SRV against mock");
        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(records[0].name, "_sip._tcp.www.seer.test");
    }

    #[tokio::test]
    async fn mock_resolve_queries_a_wildcard_owner_name() {
        // The literal `*` label reaches the wire, and the records come back
        // reported under the wildcard name that was asked for.
        let port = spawn_mock_dns_fn(|qname, qtype| match (qname, qtype) {
            ("*.seer.test", HickoryRecordType::A) => MockReply::Answer(vec![HickoryRData::A(
                hickory_resolver::proto::rr::rdata::A(Ipv4Addr::new(192, 0, 2, 42)),
            )]),
            _ => MockReply::NoData,
        })
        .await;
        let records = mock_dns_resolver(port)
            .resolve("*.seer.test", RecordType::A, Some("127.0.0.1"))
            .await
            .expect("wildcard A against mock");
        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(records[0].name, "*.seer.test");
        assert_eq!(records[0].data.to_string(), "192.0.2.42");
    }

    #[tokio::test]
    async fn mock_presence_still_probes_the_apex_for_www_input() {
        // `presence` answers a registration-level question, so it must keep
        // stripping `www.` even though `resolve` no longer does.
        let port = spawn_mock_dns_fn(|qname, qtype| match (qname, qtype) {
            ("seer.test", HickoryRecordType::NS) => MockReply::Answer(vec![HickoryRData::NS(
                hickory_resolver::proto::rr::rdata::NS(Name::from_ascii("ns1.seer.test.").unwrap()),
            )]),
            // What a recursive resolver relays for a name inside the zone:
            // querying `www` itself would read as "no NS" → Absent.
            ("www.seer.test", HickoryRecordType::NS) => MockReply::NoDataWithSoa("seer.test"),
            _ => MockReply::NxDomain,
        })
        .await;
        let resolver = mock_dns_resolver_default(port);
        assert_eq!(
            resolver.presence("www.seer.test").await,
            DnsPresence::Present
        );
    }

    #[tokio::test]
    async fn mock_resolve_ptr_transforms_ipv6_literal() {
        let records = mock_zone_lookup(RecordType::PTR, "2606:4700:4700::1111").await;
        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(records[0].data.to_string(), "one.one.one.one.");
    }

    #[tokio::test]
    async fn mock_resolve_any_aggregates_multiple_types() {
        let records = mock_zone_lookup(RecordType::ANY, "seer.test").await;
        // resolve_any fans out over ANY_TYPES; the zone publishes all of
        // these (and no CNAME or DS at the apex).
        for expected in [
            RecordType::A,
            RecordType::AAAA,
            RecordType::MX,
            RecordType::NS,
            RecordType::TXT,
            RecordType::SOA,
            RecordType::CAA,
            RecordType::HTTPS,
            RecordType::DNSKEY,
        ] {
            assert!(
                records.iter().any(|r| r.record_type == expected),
                "ANY must include {expected} records"
            );
        }
        // 2 A + 1 AAAA + 3 MX + 1 NS + 1 TXT + 1 SOA + 2 CAA + 1 HTTPS
        // + 1 DNSKEY = 13; every record is named by the query name.
        assert_eq!(records.len(), 13);
        assert!(records.iter().all(|r| r.name == "seer.test"));
        // CDS/CDNSKEY/SVCB are published but not part of the fan-out.
        assert!(!records.iter().any(|r| r.record_type == RecordType::CDS));
    }

    #[tokio::test]
    async fn mock_resolve_converts_service_bindings() {
        let records = mock_zone_lookup(RecordType::HTTPS, "seer.test").await;
        assert_eq!(records.len(), 1, "{records:?}");
        let RecordData::HTTPS {
            priority,
            target,
            params,
        } = &records[0].data
        else {
            panic!("expected HTTPS data, got {:?}", records[0].data);
        };
        assert_eq!((*priority, target.as_str()), (1, "."));
        let pairs: Vec<(&str, &str)> = params
            .iter()
            .map(|p| (p.key.as_str(), p.value.as_str()))
            .collect();
        assert_eq!(
            pairs,
            [
                ("alpn", "h3,h2"),
                ("port", "8443"),
                ("ipv4hint", "192.0.2.1,192.0.2.2"),
                ("ech", "AAH+"),
                ("ipv6hint", "2001:db8::1"),
                // Private-use key: RFC 9460 `key<N>` name, the opaque value
                // as an escaped character-string (the space is `\032`).
                ("key65333", "ex\\0321"),
            ]
        );
        assert_eq!(
            records[0].data.to_string(),
            "1 . alpn=\"h3,h2\" port=8443 ipv4hint=192.0.2.1,192.0.2.2 ech=AAH+ \
             ipv6hint=2001:db8::1 key65333=ex\\0321"
        );

        let alias = mock_zone_lookup(RecordType::HTTPS, "alias.seer.test").await;
        assert_eq!(alias.len(), 1, "{alias:?}");
        assert_eq!(alias[0].data.to_string(), "0 pool.seer.test.");

        let svcb = mock_zone_lookup(RecordType::SVCB, "_8443._foo.seer.test").await;
        assert_eq!(svcb.len(), 1, "{svcb:?}");
        assert_eq!(svcb[0].record_type, RecordType::SVCB);
        assert_eq!(
            svcb[0].data.to_string(),
            "2 svc.seer.test. mandatory=alpn,port alpn=\"foo\" no-default-alpn port=8443"
        );
    }

    #[tokio::test]
    async fn mock_resolve_converts_child_dnssec_records() {
        // ED25519 is algorithm 15; SHA-256 is digest type 2.
        let cds = mock_zone_lookup(RecordType::CDS, "seer.test").await;
        let shown: Vec<String> = cds.iter().map(|r| r.data.to_string()).collect();
        assert_eq!(shown, ["2371 15 2 ABCDEF", "0 0 0 00"]);
        assert!(cds.iter().all(|r| r.record_type == RecordType::CDS));

        let cdnskey = mock_zone_lookup(RecordType::CDNSKEY, "seer.test").await;
        let shown: Vec<String> = cdnskey.iter().map(|r| r.data.to_string()).collect();
        assert_eq!(
            shown,
            [
                "257 3 15 BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
                // The RFC 8078 delete request keeps its one-octet key.
                "0 3 0 AA==",
            ]
        );
    }

    #[tokio::test]
    async fn mock_resolve_keeps_only_the_requested_type_behind_a_cname() {
        // `resolve`'s contract is unchanged by the CNAME chain `query`
        // reports: records of the requested type only, each named by the
        // query name.
        let port = spawn_mock_dns_fn(|qname, qtype| match (qname, qtype) {
            ("www.seer.test", HickoryRecordType::A) => MockReply::Records(vec![
                record("www.seer.test.", 300, cname_rdata("edge.cdn.test.")),
                record("edge.cdn.test.", 60, a_rdata([192, 0, 2, 7])),
            ]),
            _ => MockReply::NxDomain,
        })
        .await;
        let records = mock_dns_resolver(port)
            .resolve("www.seer.test", RecordType::A, Some("127.0.0.1"))
            .await
            .expect("A behind a CNAME");
        assert_eq!(
            records,
            [DnsRecord {
                name: "www.seer.test".to_string(),
                record_type: RecordType::A,
                ttl: 60,
                data: RecordData::A {
                    address: "192.0.2.7".to_string(),
                },
            }]
        );
    }

    // --- query(): the full dig-style result -----------------------------

    fn is_probe(qname: &str) -> bool {
        qname.starts_with("seer-probe-")
    }

    /// Every (name, type) the mock was asked, in order.
    type Asked = Arc<std::sync::Mutex<Vec<(String, HickoryRecordType)>>>;

    /// [`spawn_mock_dns_fn`] that also records what it was asked.
    async fn spawn_recording<F>(mut handler: F) -> (u16, Asked)
    where
        F: FnMut(&str, HickoryRecordType) -> MockReply + Send + 'static,
    {
        let asked: Asked = Arc::default();
        let log = Arc::clone(&asked);
        let port = spawn_mock_dns_fn(move |qname, qtype| {
            log.lock().unwrap().push((qname.to_string(), qtype));
            handler(qname, qtype)
        })
        .await;
        (port, asked)
    }

    fn probes_sent(asked: &Asked) -> usize {
        asked
            .lock()
            .unwrap()
            .iter()
            .filter(|(name, _)| is_probe(name))
            .count()
    }

    async fn mock_query(port: u16, name: &str, record_type: RecordType) -> DnsQueryResult {
        mock_dns_resolver(port)
            .query(name, record_type, Some("127.0.0.1"))
            .await
            .unwrap_or_else(|e| panic!("{record_type} query against mock must succeed: {e}"))
    }

    fn shown(records: &[&DnsRecord]) -> Vec<(String, RecordType, String)> {
        records
            .iter()
            .map(|r| (r.name.clone(), r.record_type, r.data.to_string()))
            .collect()
    }

    fn row(name: &str, record_type: RecordType, data: &str) -> (String, RecordType, String) {
        (name.to_string(), record_type, data.to_string())
    }

    #[tokio::test]
    async fn mock_query_reports_the_cname_chain_under_real_owners() {
        let port = spawn_mock_dns_fn(|qname, qtype| match (qname, qtype) {
            ("www.seer.test", HickoryRecordType::A) => MockReply::Records(vec![
                record("www.seer.test.", 300, cname_rdata("edge.cdn.test.")),
                record("edge.cdn.test.", 120, cname_rdata("origin.cdn.test.")),
                record("origin.cdn.test.", 60, a_rdata([192, 0, 2, 7])),
                record("origin.cdn.test.", 60, a_rdata([192, 0, 2, 8])),
            ]),
            _ => MockReply::NxDomain,
        })
        .await;
        let result = mock_query(port, "WWW.Seer.test", RecordType::A).await;

        assert_eq!(result.name, "www.seer.test");
        assert_eq!(result.record_type, RecordType::A);
        assert_eq!(result.server.as_deref(), Some("127.0.0.1"));
        assert_eq!(result.status, DnsStatus::NoError);
        assert_eq!(result.flags, ["qr", "rd", "ra"]);
        assert_eq!(
            shown(&result.cname_chain().collect::<Vec<_>>()),
            [
                row("www.seer.test", RecordType::CNAME, "edge.cdn.test."),
                row("edge.cdn.test", RecordType::CNAME, "origin.cdn.test."),
            ]
        );
        assert_eq!(
            shown(&result.records().collect::<Vec<_>>()),
            [
                row("origin.cdn.test", RecordType::A, "192.0.2.7"),
                row("origin.cdn.test", RecordType::A, "192.0.2.8"),
            ]
        );
        assert_eq!(result.answers[2].ttl, 60);
        assert!(result.authority.is_empty());
        assert!(!result.is_nodata());
        // The sibling probe got NXDOMAIN: no wildcard.
        let wildcard = result
            .wildcard
            .expect("probe ran for a name below seer.test");
        assert!(is_probe(&wildcard.probe_name), "{wildcard:?}");
        assert!(wildcard.probe_name.ends_with(".seer.test"), "{wildcard:?}");
        assert!(!wildcard.present && !wildcard.matches_answer);
    }

    #[tokio::test]
    async fn mock_query_reports_idn_owners_as_a_labels() {
        // The query name is normalized to its A-label; owners and the CNAME
        // target are reported in that spelling too, so the chain connects
        // name for name.
        let port = spawn_mock_dns_fn(|qname, qtype| match (qname, qtype) {
            ("xn--bcher-kva.seer.test", HickoryRecordType::A) => MockReply::Records(vec![
                record(
                    "xn--bcher-kva.seer.test.",
                    300,
                    cname_rdata("edge.xn--caf-dma.test."),
                ),
                record("edge.xn--caf-dma.test.", 60, a_rdata([192, 0, 2, 7])),
            ]),
            _ => MockReply::NxDomain,
        })
        .await;
        let result = mock_query(port, "Bücher.seer.test", RecordType::A).await;
        assert_eq!(result.name, "xn--bcher-kva.seer.test");
        assert_eq!(
            shown(&result.answers.iter().collect::<Vec<_>>()),
            [
                row(
                    "xn--bcher-kva.seer.test",
                    RecordType::CNAME,
                    "edge.xn--caf-dma.test."
                ),
                row("edge.xn--caf-dma.test", RecordType::A, "192.0.2.7"),
            ]
        );
        assert_eq!(result.cname_chain().count(), 1);
    }

    #[tokio::test]
    async fn query_refuses_a_reserved_nameserver() {
        // SSRF: `query` builds its upstream through the same vetted path as
        // `resolve`, so a loopback or private nameserver is refused before
        // any packet is sent.
        let r = DnsResolver::new();
        for reserved in ["127.0.0.1", "10.0.0.1", "::1", "tls://192.168.1.1"] {
            let err = r
                .query("www.example.com", RecordType::A, Some(reserved))
                .await
                .expect_err("a reserved nameserver must be refused");
            let msg = err.to_string().to_lowercase();
            assert!(
                msg.contains("blocked") || msg.contains("reserved"),
                "{reserved}: {msg}"
            );
        }
    }

    #[tokio::test]
    async fn mock_query_reports_a_cname_the_server_did_not_follow_as_sent() {
        // A server that does not recurse answers with the CNAME alone. Like
        // dig, `query` reports that response and asks nothing more — hickory's
        // resolver used to chase the target itself, with a second query to
        // the same server.
        let (port, asked) = spawn_recording(|qname, qtype| match (qname, qtype) {
            ("www.seer.test", HickoryRecordType::A) => MockReply::Records(vec![record(
                "www.seer.test.",
                300,
                cname_rdata("edge.cdn.test."),
            )]),
            ("edge.cdn.test", HickoryRecordType::A) => {
                MockReply::Answer(vec![a_rdata([192, 0, 2, 7])])
            }
            _ => MockReply::NxDomain,
        })
        .await;
        let result = mock_query(port, "www.seer.test", RecordType::A).await;
        assert_eq!(result.status, DnsStatus::NoError);
        assert_eq!(result.flags, ["qr", "rd", "ra"]);
        assert_eq!(
            shown(&result.answers.iter().collect::<Vec<_>>()),
            [row("www.seer.test", RecordType::CNAME, "edge.cdn.test.")]
        );
        assert_eq!(result.records().count(), 0);
        assert!(
            !asked
                .lock()
                .unwrap()
                .iter()
                .any(|(n, _)| n == "edge.cdn.test"),
            "the target is not chased: {asked:?}"
        );
    }

    #[tokio::test]
    async fn mock_query_reports_a_dangling_cname_with_its_chain() {
        // Regression: a CNAME whose target does not exist read as a bare
        // "Name does not exist (NXDOMAIN)" — no chain, no flags — because
        // hickory's resolver discarded the chain and the response header.
        let port = spawn_mock_dns_fn(|qname, _| match qname {
            "www.seer.test" => MockReply::Negative {
                code: ResponseCode::NXDomain,
                chain: vec![
                    record("www.seer.test.", 300, cname_rdata("shop.seer.test.")),
                    record("shop.seer.test.", 300, cname_rdata("gone.cdn.test.")),
                ],
                soa: "cdn.test",
            },
            _ => MockReply::NxDomainWithSoa("seer.test"),
        })
        .await;
        let result = mock_query(port, "www.seer.test", RecordType::A).await;
        assert_eq!(result.status, DnsStatus::NxDomain);
        assert_eq!(result.flags, ["qr", "rd", "ra"]);
        assert_eq!(
            shown(&result.cname_chain().collect::<Vec<_>>()),
            [
                row("www.seer.test", RecordType::CNAME, "shop.seer.test."),
                row("shop.seer.test", RecordType::CNAME, "gone.cdn.test."),
            ]
        );
        assert_eq!(result.records().count(), 0);
        assert_eq!(
            shown(&result.authority.iter().collect::<Vec<_>>()),
            [row(
                "cdn.test",
                RecordType::SOA,
                "ns1.cdn.test. hostmaster.cdn.test. 2026070101 7200 3600 1209600 300"
            )]
        );
        assert!(!result.is_nodata());
        assert_eq!(result.referral_zone(), None);
        assert_eq!(
            result.wildcard, None,
            "a negative answer has nothing to compare"
        );
    }

    #[tokio::test]
    async fn mock_query_reports_nodata_behind_a_cname() {
        let port = spawn_mock_dns_fn(|qname, _| match qname {
            "www.seer.test" => MockReply::Negative {
                code: ResponseCode::NoError,
                chain: vec![record("www.seer.test.", 300, cname_rdata("edge.cdn.test."))],
                soa: "cdn.test",
            },
            _ => MockReply::NxDomain,
        })
        .await;
        let result = mock_query(port, "www.seer.test", RecordType::AAAA).await;
        assert_eq!(result.status, DnsStatus::NoError);
        assert_eq!(result.flags, ["qr", "rd", "ra"]);
        assert_eq!(result.cname_chain().count(), 1);
        assert_eq!(result.records().count(), 0);
        assert!(result.is_nodata());
        assert_eq!(result.referral_zone(), None);
        assert_eq!(result.authority.len(), 1);
        assert_eq!(result.authority[0].name, "cdn.test");
    }

    #[tokio::test]
    async fn mock_query_reports_nxdomain_with_the_zone_soa() {
        let (port, asked) = spawn_recording(|_, _| MockReply::NxDomainWithSoa("seer.test")).await;
        let result = mock_query(port, "nx.seer.test", RecordType::A).await;
        assert_eq!(result.status, DnsStatus::NxDomain);
        assert!(result.answers.is_empty());
        assert!(!result.is_nodata(), "NXDOMAIN is not NODATA");
        // Regression: a negative answer came back without its header.
        assert_eq!(result.flags, ["qr", "rd", "ra"]);
        assert_eq!(
            shown(&result.authority.iter().collect::<Vec<_>>()),
            [row(
                "seer.test",
                RecordType::SOA,
                "ns1.seer.test. hostmaster.seer.test. 2026070101 7200 3600 1209600 300"
            )]
        );
        // A negative answer has nothing to compare a wildcard with.
        assert_eq!(result.wildcard, None);
        assert!(asked
            .lock()
            .unwrap()
            .iter()
            .any(|(n, _)| n == "nx.seer.test"));
    }

    #[tokio::test]
    async fn mock_query_reports_nodata_with_the_zone_soa() {
        let port = spawn_mock_dns_fn(|_, _| MockReply::NoDataWithSoa("seer.test")).await;
        let result = mock_query(port, "www.seer.test", RecordType::MX).await;
        assert_eq!(result.status, DnsStatus::NoError);
        assert!(result.is_nodata());
        assert!(result.answers.is_empty());
        assert_eq!(result.authority.len(), 1);
        assert_eq!(result.authority[0].record_type, RecordType::SOA);
        assert_eq!(result.authority[0].name, "seer.test");
        assert_eq!(result.wildcard, None);
    }

    #[tokio::test]
    async fn mock_query_reports_error_codes_as_results() {
        let port = spawn_mock_dns_fn(|qname, _| match qname {
            "servfail.seer.test" => MockReply::Rcode(ResponseCode::ServFail),
            "refused.seer.test" => MockReply::Rcode(ResponseCode::Refused),
            "notimp.seer.test" => MockReply::Rcode(ResponseCode::NotImp),
            _ => MockReply::NxDomain,
        })
        .await;
        for (name, status, shown) in [
            ("servfail.seer.test", DnsStatus::ServFail, "SERVFAIL"),
            ("refused.seer.test", DnsStatus::Refused, "REFUSED"),
            ("notimp.seer.test", DnsStatus::Other(4), "NOTIMP"),
        ] {
            let result = mock_query(port, name, RecordType::A).await;
            assert_eq!(result.status, status, "{name}");
            assert_eq!(result.status.to_string(), shown);
            assert!(result.answers.is_empty() && result.authority.is_empty());
            assert_eq!(result.flags, ["qr", "rd", "ra"], "{name}");
            assert!(!result.is_nodata());
            assert_eq!(result.wildcard, None);
        }
    }

    #[tokio::test]
    async fn mock_query_reads_an_extended_rcode_from_edns() {
        // BADVERS (16) does not fit the header's four bits: its high bits
        // travel in the OPT record, and the status must include them.
        let port = spawn_mock_dns_fn(|_, _| MockReply::Rcode(ResponseCode::BADVERS)).await;
        let result = mock_query(port, "www.seer.test", RecordType::A).await;
        assert_eq!(result.status, DnsStatus::Other(16));
        assert_eq!(result.status.to_string(), "BADVERS");
    }

    #[tokio::test]
    async fn mock_query_repeats_a_truncated_reply_over_tcp() {
        // A bare `@server` spec configures UDP only; like dig, a truncated
        // reply is asked again over TCP, of the same address and port.
        let transports = Arc::new(std::sync::Mutex::new(0));
        let seen = Arc::clone(&transports);
        let port = spawn_mock_dns_fn_with_tcp(move |qname, _| {
            if qname != "big.seer.test" {
                return MockReply::NxDomain;
            }
            let mut n = seen.lock().unwrap();
            *n += 1;
            if *n == 1 {
                MockReply::Truncated
            } else {
                MockReply::Answer((1..=3).map(|i| a_rdata([192, 0, 2, i])).collect())
            }
        })
        .await;
        let result = mock_query(port, "big.seer.test", RecordType::A).await;
        assert_eq!(result.status, DnsStatus::NoError);
        assert_eq!(result.records().count(), 3);
        assert!(
            !result.flags.contains(&"tc".to_string()),
            "{:?}",
            result.flags
        );
        assert_eq!(*transports.lock().unwrap(), 2, "UDP, then TCP");
    }

    #[tokio::test]
    async fn mock_query_reports_a_referral_as_neither_nodata_nor_an_answer() {
        // A server that is not authoritative for the name and does not
        // recurse refers the query to the child zone's servers. Regression:
        // this was reported as NODATA ("the name exists").
        let port = spawn_mock_dns_fn(|_, _| MockReply::Delegation {
            zone: "child.seer.test".to_string(),
            servers: vec![
                (
                    "ns1.child.seer.test".to_string(),
                    vec![IpAddr::from([192, 0, 2, 1])],
                ),
                ("ns2.child.seer.test".to_string(), vec![]),
            ],
        })
        .await;
        let result = mock_query(port, "www.child.seer.test", RecordType::A).await;
        assert_eq!(result.status, DnsStatus::NoError);
        // The header, as the referring server set it: no `aa`, no `ra`.
        assert_eq!(result.flags, ["qr", "rd"]);
        assert!(result.answers.is_empty());
        assert_eq!(result.referral_zone(), Some("child.seer.test"));
        assert!(!result.is_nodata());
        assert_eq!(
            shown(&result.authority.iter().collect::<Vec<_>>()),
            [
                row("child.seer.test", RecordType::NS, "ns1.child.seer.test."),
                row("child.seer.test", RecordType::NS, "ns2.child.seer.test."),
            ]
        );
        assert_eq!(result.wildcard, None);
    }

    #[tokio::test]
    async fn mock_query_reports_special_use_names_as_answered_locally() {
        // hickory answers RFC 6761 names itself. Regression: `-x 127.0.0.1`
        // was reported as the server's answer (`flags: qr`, `server: …`) and,
        // since the probe's sibling got the same local answer, as likely
        // wildcard-synthesized.
        let (port, asked) = spawn_recording(|_, _| MockReply::NxDomain).await;
        let ptr = mock_query(port, "127.0.0.1", RecordType::PTR).await;
        assert_eq!(ptr.name, "1.0.0.127.in-addr.arpa");
        assert!(ptr.answered_locally);
        assert_eq!(ptr.server, None, "no server was asked");
        assert!(ptr.flags.is_empty(), "the header is hickory's own");
        assert_eq!(ptr.status, DnsStatus::NoError);
        assert_eq!(
            shown(&ptr.answers.iter().collect::<Vec<_>>()),
            [row("1.0.0.127.in-addr.arpa", RecordType::PTR, "localhost.")]
        );
        assert_eq!(ptr.wildcard, None, "no wildcard probe for a local name");

        let mx = mock_query(port, "foo.localhost", RecordType::MX).await;
        assert!(mx.answered_locally && mx.is_nodata());
        let onion = mock_query(port, "x.onion", RecordType::A).await;
        assert!(onion.answered_locally);
        assert_eq!(onion.status, DnsStatus::NxDomain);

        assert!(asked.lock().unwrap().is_empty(), "{asked:?}");
    }

    #[tokio::test]
    async fn mock_query_times_out_as_an_error() {
        let port = spawn_mock_dns(MockMode::Ignore).await;
        let resolver = DnsResolver::new()
            .with_timeout(Duration::from_millis(200))
            .allowing_private_hosts()
            .with_port(port);
        let result = resolver
            .query("www.seer.test", RecordType::A, Some("127.0.0.1"))
            .await;
        assert!(
            matches!(&result, Err(SeerError::DnsError(m)) if m.contains("A lookup failed")),
            "an unanswered query is a transport error, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn mock_query_reads_flags_from_the_response_header() {
        let port = spawn_mock_dns_fn(|qname, qtype| match (qname, qtype) {
            ("seer.test", HickoryRecordType::A) => {
                MockReply::AuthoritativeAnswer(vec![a_rdata([192, 0, 2, 1])])
            }
            _ => MockReply::NxDomain,
        })
        .await;
        let result = mock_query(port, "seer.test", RecordType::A).await;
        assert_eq!(result.flags, ["qr", "aa", "rd", "ra"]);
        assert_eq!(result.cname_chain().count(), 0);
        assert_eq!(
            result.records().next().map(|r| r.name.as_str()),
            Some("seer.test")
        );
    }

    #[tokio::test]
    async fn mock_query_converts_the_new_record_types_under_their_owner() {
        let port = spawn_mock_dns(MockMode::Zone).await;
        let https = mock_query(port, "seer.test", RecordType::HTTPS).await;
        assert_eq!(https.answers.len(), 1, "{https:?}");
        assert_eq!(https.answers[0].name, "seer.test");
        assert!(https.answers[0]
            .data
            .to_string()
            .starts_with("1 . alpn=\"h3,h2\" port=8443"));

        let alias = mock_query(port, "alias.seer.test", RecordType::HTTPS).await;
        assert_eq!(alias.answers[0].data.to_string(), "0 pool.seer.test.");
        assert_eq!(alias.answers[0].name, "alias.seer.test");

        let cds = mock_query(port, "seer.test", RecordType::CDS).await;
        assert_eq!(cds.answers.len(), 2);
        let cdnskey = mock_query(port, "seer.test", RecordType::CDNSKEY).await;
        assert_eq!(cdnskey.answers[1].data.to_string(), "0 3 0 AA==");
    }

    #[tokio::test]
    async fn mock_query_sorts_mx_like_resolve() {
        let port = spawn_mock_dns(MockMode::Zone).await;
        let result = mock_query(port, "seer.test", RecordType::MX).await;
        let prefs: Vec<String> = result.answers.iter().map(|r| r.data.to_string()).collect();
        assert_eq!(
            prefs,
            [
                "10 a.mail.seer.test.",
                "20 b.mail.seer.test.",
                "30 c.mail.seer.test."
            ]
        );
    }

    #[tokio::test]
    async fn mock_query_resolves_srv_and_ptr_names_like_resolve() {
        let (port, asked) = spawn_recording(|qname, qtype| match (qname, qtype) {
            ("_sip._tcp.seer.test", HickoryRecordType::SRV) => {
                MockReply::Answer(vec![HickoryRData::SRV(
                    hickory_resolver::proto::rr::rdata::SRV::new(
                        10,
                        5,
                        5060,
                        Name::from_ascii("sip.seer.test.").unwrap(),
                    ),
                )])
            }
            ("1.2.0.192.in-addr.arpa", HickoryRecordType::PTR) => {
                MockReply::Answer(vec![HickoryRData::PTR(
                    hickory_resolver::proto::rr::rdata::PTR(
                        Name::from_ascii("ptr.seer.test.").unwrap(),
                    ),
                )])
            }
            _ => MockReply::NxDomain,
        })
        .await;

        let srv = mock_query(port, "_sip._tcp.seer.test", RecordType::SRV).await;
        assert_eq!(
            shown(&srv.answers.iter().collect::<Vec<_>>()),
            [row(
                "_sip._tcp.seer.test",
                RecordType::SRV,
                "10 5 5060 sip.seer.test."
            )]
        );
        // The sibling of an underscore name replaces its leftmost label.
        let probe = srv.wildcard.expect("SRV name is below seer.test");
        assert!(probe.probe_name.ends_with("._tcp.seer.test"), "{probe:?}");
        assert!(asked.lock().unwrap().iter().any(|(n, t)| is_probe(n)
            && n.ends_with("._tcp.seer.test")
            && *t == HickoryRecordType::SRV));

        let ptr = mock_query(port, "192.0.2.1", RecordType::PTR).await;
        assert_eq!(ptr.name, "1.2.0.192.in-addr.arpa");
        assert_eq!(ptr.answers[0].name, "1.2.0.192.in-addr.arpa");

        let err = mock_dns_resolver(port)
            .query("seer.test", RecordType::SRV, Some("127.0.0.1"))
            .await
            .expect_err("a bare domain is not an SRV query");
        assert!(matches!(err, SeerError::InvalidInput(_)), "{err:?}");
        let err = mock_dns_resolver(port)
            .query(".bad.example", RecordType::A, Some("127.0.0.1"))
            .await;
        assert!(err.is_err(), "invalid names are rejected before any I/O");
    }

    #[tokio::test]
    async fn mock_query_any_fans_out_to_the_new_types_and_dedupes() {
        let (port, asked) = spawn_recording(|qname, qtype| {
            let chain = || record("www.seer.test.", 300, cname_rdata("edge.seer.test."));
            match (qname, qtype) {
                ("www.seer.test", HickoryRecordType::CNAME) => MockReply::Records(vec![chain()]),
                ("www.seer.test", HickoryRecordType::A) => MockReply::Records(vec![
                    chain(),
                    record("edge.seer.test.", 60, a_rdata([192, 0, 2, 7])),
                ]),
                ("www.seer.test", HickoryRecordType::HTTPS) => {
                    MockReply::Records(vec![
                        chain(),
                        record(
                            "edge.seer.test.",
                            60,
                            HickoryRData::HTTPS(hickory_resolver::proto::rr::rdata::HTTPS(
                                SVCB::new(1, Name::root(), vec![]),
                            )),
                        ),
                    ])
                }
                // Every other type: the chain alone, as a NODATA at the
                // target reads.
                ("www.seer.test", _) => MockReply::Records(vec![chain()]),
                _ => MockReply::NoDataWithSoa("seer.test"),
            }
        })
        .await;
        let result = mock_query(port, "www.seer.test", RecordType::ANY).await;

        assert_eq!(result.record_type, RecordType::ANY);
        assert_eq!(result.status, DnsStatus::NoError);
        assert_eq!(result.flags, ["qr", "rd", "ra"]);
        // The CNAME came back from all 11 sub-queries; it is listed once.
        assert_eq!(
            shown(&result.answers.iter().collect::<Vec<_>>()),
            [
                row("www.seer.test", RecordType::CNAME, "edge.seer.test."),
                row("edge.seer.test", RecordType::A, "192.0.2.7"),
                row("edge.seer.test", RecordType::HTTPS, "1 ."),
            ]
        );
        assert_eq!(result.cname_chain().count(), 1);
        assert_eq!(result.records().count(), 2);
        assert!(!result.is_nodata());
        assert_eq!(result.wildcard, None, "ANY is never probed");

        let asked: Vec<HickoryRecordType> = asked
            .lock()
            .unwrap()
            .iter()
            .filter(|(n, _)| n == "www.seer.test")
            .map(|(_, t)| *t)
            .collect();
        for wire in ANY_TYPES.iter().filter_map(|t| wire_type(*t)) {
            assert!(asked.contains(&wire), "ANY must query {wire}: {asked:?}");
        }
        assert!(
            !asked.contains(&HickoryRecordType::ANY),
            "ANY is never sent"
        );
    }

    #[tokio::test]
    async fn mock_query_any_errors_only_when_every_sub_query_fails() {
        let port = spawn_mock_dns(MockMode::Ignore).await;
        let resolver = DnsResolver::new()
            .with_timeout(Duration::from_millis(200))
            .allowing_private_hosts()
            .with_port(port);
        let result = resolver
            .query("www.seer.test", RecordType::ANY, Some("127.0.0.1"))
            .await;
        assert!(matches!(result, Err(SeerError::DnsError(_))), "{result:?}");
    }

    /// A zone where `www` has its own A record and every other name under
    /// `seer.test` answers the probe with `probe_reply`.
    async fn wildcard_zone(probe_reply: fn() -> MockReply) -> (u16, Asked) {
        spawn_recording(move |qname, qtype| match (qname, qtype) {
            ("www.seer.test", HickoryRecordType::A) => {
                MockReply::Answer(vec![a_rdata([192, 0, 2, 50])])
            }
            (name, HickoryRecordType::A) if is_probe(name) => probe_reply(),
            _ => MockReply::NxDomain,
        })
        .await
    }

    #[tokio::test]
    async fn mock_wildcard_probe_matching_the_answer() {
        let (port, asked) =
            wildcard_zone(|| MockReply::Answer(vec![a_rdata([192, 0, 2, 50])])).await;
        let result = mock_query(port, "www.seer.test", RecordType::A).await;
        let probe = result.wildcard.expect("probe attached");
        assert!(probe.present && probe.matches_answer, "{probe:?}");
        assert_eq!(probes_sent(&asked), 1);
    }

    #[tokio::test]
    async fn mock_wildcard_probe_with_different_data() {
        let (port, _) = wildcard_zone(|| MockReply::Answer(vec![a_rdata([192, 0, 2, 99])])).await;
        let result = mock_query(port, "www.seer.test", RecordType::A).await;
        let probe = result.wildcard.expect("probe attached");
        assert!(probe.present && !probe.matches_answer, "{probe:?}");
    }

    #[tokio::test]
    async fn mock_wildcard_probe_absent() {
        let (port, _) = wildcard_zone(|| MockReply::NxDomainWithSoa("seer.test")).await;
        let result = mock_query(port, "www.seer.test", RecordType::A).await;
        let probe = result.wildcard.expect("probe attached");
        assert!(!probe.present && !probe.matches_answer, "{probe:?}");
    }

    #[tokio::test]
    async fn mock_wildcard_probe_that_fails_is_dropped_not_fatal() {
        let (port, _) = wildcard_zone(|| MockReply::Rcode(ResponseCode::ServFail)).await;
        let result = mock_query(port, "www.seer.test", RecordType::A).await;
        assert_eq!(result.status, DnsStatus::NoError);
        assert_eq!(result.wildcard, None);

        // An unanswered probe times out; the main answer still stands.
        let (port, _) = wildcard_zone(|| MockReply::NoReply).await;
        let resolver = DnsResolver::new()
            .with_timeout(Duration::from_millis(200))
            .allowing_private_hosts()
            .with_port(port);
        let result = resolver
            .query("www.seer.test", RecordType::A, Some("127.0.0.1"))
            .await
            .expect("the probe never fails the query");
        assert_eq!(result.records().count(), 1);
        assert_eq!(result.wildcard, None);
    }

    #[tokio::test]
    async fn mock_wildcard_probe_is_not_sent_for_ineligible_names() {
        // Every name answers, so a probe, if sent, would find a "wildcard".
        let (port, asked) =
            spawn_recording(|_, _| MockReply::Answer(vec![a_rdata([192, 0, 2, 50])])).await;
        // The registrable domain itself: its sibling would be TLD-level.
        assert_eq!(
            mock_query(port, "seer.test", RecordType::A).await.wildcard,
            None
        );
        // The wildcard owner itself.
        assert_eq!(
            mock_query(port, "*.seer.test", RecordType::A)
                .await
                .wildcard,
            None
        );
        // ANY is a fan-out, not one answer.
        assert_eq!(
            mock_query(port, "www.seer.test", RecordType::ANY)
                .await
                .wildcard,
            None
        );
        assert_eq!(probes_sent(&asked), 0, "{:?}", asked.lock().unwrap());
    }

    #[tokio::test]
    async fn mock_nodata_folds_to_empty_and_classifies_absent() {
        let port = spawn_mock_dns(MockMode::NoData).await;
        let result = mock_dns_resolver(port)
            .resolve("seer.test", RecordType::NS, Some("127.0.0.1"))
            .await;
        assert!(
            matches!(&result, Ok(records) if records.is_empty()),
            "NODATA must fold to Ok(vec![]), got: {result:?}"
        );
        assert_eq!(classify_ns_presence(&result), DnsPresence::Absent);
    }

    #[tokio::test]
    async fn mock_nxdomain_folds_to_empty_and_classifies_absent() {
        let port = spawn_mock_dns(MockMode::Nxdomain).await;
        let result = mock_dns_resolver(port)
            .resolve("seer.test", RecordType::NS, Some("127.0.0.1"))
            .await;
        assert!(
            matches!(&result, Ok(records) if records.is_empty()),
            "NXDOMAIN must fold to Ok(vec![]), got: {result:?}"
        );
        assert_eq!(classify_ns_presence(&result), DnsPresence::Absent);
    }

    #[tokio::test]
    async fn mock_timeout_errors_and_classifies_unknown() {
        let port = spawn_mock_dns(MockMode::Ignore).await;
        // Short timeout keeps the test fast: 2 attempts × 200ms ≈ 400ms.
        let resolver = DnsResolver::new()
            .with_timeout(Duration::from_millis(200))
            .allowing_private_hosts()
            .with_port(port);
        let result = resolver
            .resolve("seer.test", RecordType::NS, Some("127.0.0.1"))
            .await;
        match &result {
            Err(SeerError::DnsError(_)) => {}
            other => panic!("unanswered query must surface a DnsError, got: {other:?}"),
        }
        assert_eq!(classify_ns_presence(&result), DnsPresence::Unknown);
    }

    #[tokio::test]
    async fn resolve_type_rejects_composite_types_consistently() {
        // SRV and ANY are composite queries owned by resolve(); the shared
        // dispatch must reject them identically for every entry point. The
        // rejection happens before any I/O, so this test never contacts a
        // server despite using the default resolver.
        let r = DnsResolver::new();
        for composite in [RecordType::SRV, RecordType::ANY] {
            let err = r
                .resolve_type(&r.default_resolver, "seer.test", composite)
                .await
                .expect_err("composite types must be rejected by resolve_type");
            assert_eq!(
                err.to_string(),
                unsupported_record_type(composite).to_string()
            );
        }
    }

    #[tokio::test]
    async fn mock_unanswered_probe_costs_a_positive_answer_only_the_grace() {
        // Regression: after the main answer landed, the probe was awaited
        // for its whole budget (two timeouts) when its server never
        // answered it. It now waits a fifth of one timeout at most.
        let (port, asked) = wildcard_zone(|| MockReply::NoReply).await;
        let resolver = DnsResolver::new()
            .with_timeout(Duration::from_secs(2))
            .allowing_private_hosts()
            .with_port(port);
        let started = Instant::now();
        let result = resolver
            .query("www.seer.test", RecordType::A, Some("127.0.0.1"))
            .await
            .expect("the main query is answered");
        let elapsed = started.elapsed();
        assert_eq!(result.records().count(), 1);
        assert_eq!(result.wildcard, None, "an unfinished probe says nothing");
        assert!(probes_sent(&asked) >= 1, "the probe was sent");
        // Grace 400ms; the old wait was the probe's 4s budget.
        assert!(elapsed >= Duration::from_millis(400), "{elapsed:?}");
        assert!(elapsed < Duration::from_millis(1500), "{elapsed:?}");
    }

    /// A zone whose `www` answers every ANY sub-type but TXT and DNSKEY,
    /// which its server never answers.
    async fn partly_silent_zone() -> u16 {
        spawn_mock_dns_fn(|_, qtype| match qtype {
            HickoryRecordType::A => MockReply::Answer(vec![a_rdata([192, 0, 2, 7])]),
            HickoryRecordType::TXT | HickoryRecordType::DNSKEY => MockReply::NoReply,
            _ => MockReply::NoDataWithSoa("seer.test"),
        })
        .await
    }

    fn short_resolver(port: u16) -> DnsResolver {
        DnsResolver::new()
            .with_timeout(Duration::from_millis(200))
            .allowing_private_hosts()
            .with_port(port)
    }

    #[tokio::test]
    async fn mock_query_any_reports_the_types_that_failed() {
        // Regression: the timed-out TXT and DNSKEY sub-queries were dropped
        // silently, so the ANY answer read as complete.
        let port = partly_silent_zone().await;
        let result = short_resolver(port)
            .query("www.seer.test", RecordType::ANY, Some("127.0.0.1"))
            .await
            .expect("some sub-queries were answered");
        assert_eq!(result.records().count(), 1);
        let failed: Vec<RecordType> = result.failed_types.iter().map(|f| f.record_type).collect();
        assert_eq!(failed, [RecordType::TXT, RecordType::DNSKEY]);
        assert!(
            result.failed_types[0].error.contains("timed out"),
            "{:?}",
            result.failed_types
        );

        // A single-type query never carries any.
        let a = short_resolver(port)
            .query("www.seer.test", RecordType::A, Some("127.0.0.1"))
            .await
            .unwrap();
        assert!(a.failed_types.is_empty());
    }

    #[tokio::test]
    async fn mock_query_server_any_keeps_partial_failures_apart_from_silence() {
        let port = partly_silent_zone().await;
        let reply = short_resolver(port)
            .query_server("www.seer.test", RecordType::ANY, "127.0.0.1")
            .await
            .unwrap();
        let ServerReply::Response(result) = reply else {
            panic!("a partial answer is a response: {reply:?}");
        };
        assert_eq!(result.records().count(), 1);
        let failed: Vec<RecordType> = result.failed_types.iter().map(|f| f.record_type).collect();
        assert_eq!(failed, [RecordType::TXT, RecordType::DNSKEY]);

        // No sub-query answered: the server is silent, not empty.
        let silent = spawn_mock_dns(MockMode::Ignore).await;
        let reply = short_resolver(silent)
            .query_server("www.seer.test", RecordType::ANY, "127.0.0.1")
            .await
            .unwrap();
        assert!(
            matches!(&reply, ServerReply::Silent(reason) if reason == "timed out"),
            "{reply:?}"
        );
    }

    #[tokio::test]
    async fn resolve_validates_the_name_before_resolving_the_nameserver() {
        // Regression: the nameserver hostname was resolved (a network
        // lookup) before the name was checked. The bad name fails first,
        // without touching the network.
        let err = DnsResolver::new()
            .resolve(".bad..name", RecordType::A, Some("ns.seer.test"))
            .await
            .expect_err("an invalid name is rejected");
        assert!(
            matches!(
                err,
                SeerError::InvalidDomain(_) | SeerError::InvalidInput(_)
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn a_local_answer_never_resolves_the_nameserver_hostname() {
        // Regression: `dig -x 127.0.0.1 @ns.example` resolved `ns.example` over
        // the network though hickory answers that PTR itself. Only the
        // offline checks run: an unresolvable hostname is fine, a reserved
        // IP literal and a malformed spec are not.
        let r = DnsResolver::new();
        let result = r
            .query(
                "127.0.0.1",
                RecordType::PTR,
                Some("ns.does-not-resolve.test"),
            )
            .await
            .expect("answered locally, the nameserver unused");
        assert!(result.answered_locally);
        assert_eq!(result.records().count(), 1);

        let blocked = r
            .query("127.0.0.1", RecordType::PTR, Some("10.0.0.1"))
            .await
            .expect_err("a reserved nameserver is refused all the same");
        assert!(blocked.to_string().contains("blocked"), "{blocked}");
        assert!(r
            .query("127.0.0.1", RecordType::PTR, Some("ftp://ns.seer.test"))
            .await
            .is_err());
    }
}
