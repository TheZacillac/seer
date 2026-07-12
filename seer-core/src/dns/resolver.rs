//! DNS resolution over hickory-resolver.
//!
//! Retry boundary (deliberate): unlike the WHOIS/RDAP clients, this module
//! does NOT wrap queries in [`crate::retry::RetryPolicy`]. hickory-resolver
//! already performs its own retransmission (`opts.attempts` below) against
//! the configured nameserver within the per-query timeout; stacking an outer
//! retry loop on top would multiply worst-case latency without improving
//! resolution odds. If a retry knob is ever needed here, tune
//! `ResolverOpts::attempts` rather than adding a wrapper.

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::config::{NameServerConfig, ResolveHosts, ResolverConfig, GOOGLE};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::NetError;
use hickory_resolver::proto::dnssec::PublicKey;
use hickory_resolver::proto::rr::rdata::CAA;
use hickory_resolver::proto::rr::{RData as HickoryRData, RecordType as HickoryRecordType};
use hickory_resolver::TokioResolver;
use tracing::{debug, instrument};

use super::nameserver::{NameserverProtocol, NameserverSpec};
use super::records::{DnsRecord, RecordData, RecordType};
use crate::error::{Result, SeerError};
use crate::validation::normalize_domain;

/// Convert a DNS lookup result, treating "no records found" as an empty vec
/// rather than an error. This is correct DNS behavior — the absence of a
/// record type for a domain is a valid response (NODATA), not a failure.
fn dns_lookup_or_empty<T>(
    result: std::result::Result<T, NetError>,
    record_type: &str,
) -> Result<Option<T>> {
    match result {
        Ok(response) => Ok(Some(response)),
        Err(e) if e.is_no_records_found() => Ok(None),
        Err(e) => Err(SeerError::DnsError(format!(
            "{} lookup failed: {}",
            record_type, e
        ))),
    }
}

/// Default timeout for DNS queries (5 seconds).
/// DNS is typically fast; longer timeouts indicate network issues or unreachable servers.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

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
    {
        let opts = builder.options_mut();
        opts.timeout = timeout;
        opts.attempts = 2;
        opts.use_hosts_file = ResolveHosts::Never;
    }
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
    build_resolver(ResolverConfig::udp_and_tcp(&GOOGLE), timeout)
        .expect("default resolver build cannot fail with the bundled webpki root store")
}

/// Build the hickory upstream config for a parsed nameserver spec and its
/// resolved (and already SSRF-validated) addresses.
///
/// One `NameServerConfig` is added per IP, all speaking the spec's protocol
/// on the spec's port. For DoT/DoH the TLS server name is the spec's host —
/// the hostname when one was given, or the IP literal itself (verified
/// against the certificate's IP SANs, which the major public resolvers
/// carry). `port_override` is the `#[cfg(test)]` mock-server seam and is
/// always `None` in production.
fn build_upstream_config(
    spec: &NameserverSpec,
    ips: &[IpAddr],
    port_override: Option<u16>,
) -> ResolverConfig {
    let mut config = ResolverConfig::from_parts(None, vec![], vec![]);
    let port = port_override.unwrap_or(spec.port);
    for ip in ips {
        let mut ns = match spec.protocol {
            NameserverProtocol::Udp => NameServerConfig::udp(*ip),
            NameserverProtocol::Tls => NameServerConfig::tls(*ip, Arc::from(spec.tls_name())),
            NameserverProtocol::Https => NameServerConfig::https(
                *ip,
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
/// — see [`NameserverSpec`](super::NameserverSpec) for the accepted forms.
/// The default resolver is cached and reused across queries to avoid
/// repeated initialization overhead.
#[derive(Clone)]
pub struct DnsResolver {
    timeout: Duration,
    /// Cached default resolver (Google DNS). Reused across all queries
    /// that don't specify a custom nameserver.
    default_resolver: TokioResolver,
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
        Self {
            timeout: DEFAULT_TIMEOUT,
            default_resolver: build_default_resolver(DEFAULT_TIMEOUT),
            port_override: None,
            allow_private_hosts: false,
        }
    }

    /// Builds a resolver honoring `~/.seer/config.toml` settings.
    ///
    /// Reads `timeouts.dns_secs` (already clamped to 1–60s by
    /// [`crate::config::SeerConfig::load`]). Sugar over
    /// [`DnsResolver::with_timeout`] — equivalent to
    /// `DnsResolver::new().with_timeout(config.dns_timeout())`.
    ///
    /// The `nameserver` config key is deliberately NOT applied here: the
    /// resolver takes the nameserver per-query (see [`DnsResolver::resolve`]),
    /// so callers thread `config.nameserver` at the call site where it can be
    /// overridden per-invocation.
    pub fn from_config(config: &crate::config::SeerConfig) -> Self {
        Self::new().with_timeout(config.dns_timeout())
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

    /// Sets the timeout for DNS queries.
    ///
    /// The default is 5 seconds, which is sufficient for most DNS queries.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self.default_resolver = build_default_resolver(timeout);
        self
    }

    async fn create_custom_resolver(&self, nameserver: &str) -> Result<TokioResolver> {
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

        // SSRF protection: reject private/reserved IPs — whether supplied
        // literally or returned by name resolution, and identically for
        // UDP, tls://, and https:// specs. Without this, a hostname under
        // attacker control could point at internal infra.
        // `allow_private_hosts` is only settable via the `#[cfg(test)]`
        // seam; production builds always validate.
        if !self.allow_private_hosts {
            for ip in &ips {
                if let Some(reason) = crate::validation::describe_reserved_ip(ip) {
                    return Err(SeerError::DnsError(format!(
                        "nameserver {} blocked: {}",
                        nameserver, reason
                    )));
                }
            }
        }

        build_resolver(
            build_upstream_config(&spec, &ips, self.port_override),
            self.timeout,
        )
    }

    /// Resolves DNS records for a domain.
    ///
    /// # Arguments
    /// * `domain` - The domain name to query
    /// * `record_type` - The type of DNS record to look up (A, AAAA, MX, etc.)
    /// * `nameserver` - Optional custom nameserver spec; uses Google DNS if
    ///   None. Accepts a bare IP/hostname with optional port (UDP),
    ///   `tls://host[:port]` (DNS over TLS), or `https://host[:port][/path]`
    ///   (DNS over HTTPS) — see [`NameserverSpec`](super::NameserverSpec)
    #[instrument(skip(self), fields(domain = %domain, record_type = %record_type))]
    pub async fn resolve(
        &self,
        domain: &str,
        record_type: RecordType,
        nameserver: Option<&str>,
    ) -> Result<Vec<DnsRecord>> {
        // Reuse the cached default resolver when no custom nameserver is specified
        let custom_resolver;
        let resolver = if let Some(ns) = nameserver {
            custom_resolver = self.create_custom_resolver(ns).await?;
            &custom_resolver
        } else {
            &self.default_resolver
        };
        let domain = prepare_query(domain, record_type)?;

        debug!(nameserver = nameserver.unwrap_or("system"), "Resolving DNS");

        match record_type {
            RecordType::SRV => match parse_srv_query(&domain) {
                // dig-style `_service._proto.name` queries resolve directly.
                Some((service, protocol, name)) => {
                    self.resolve_srv_core(resolver, &service, &protocol, &name)
                        .await
                }
                // A bare domain isn't a valid SRV query — surface a usage hint
                // as an input error (permanent), not a transient DNS failure.
                None => Err(srv_format_error()),
            },
            RecordType::ANY => self.resolve_any(resolver, &domain).await,
            single => self.resolve_type(resolver, &domain, single).await,
        }
    }

    /// Resolves SRV records for a service.
    ///
    /// # Arguments
    /// * `service` - The service name (e.g., "http", "ldap")
    /// * `protocol` - The protocol (e.g., "tcp", "udp")
    /// * `domain` - The domain name
    /// * `nameserver` - Optional custom nameserver IP
    #[instrument(skip(self), fields(domain = %domain, service = %service, protocol = %protocol))]
    pub async fn resolve_srv(
        &self,
        service: &str,
        protocol: &str,
        domain: &str,
        nameserver: Option<&str>,
    ) -> Result<Vec<DnsRecord>> {
        // Same normalization/validation as every other public entry point —
        // callers may hand us URL-form or unvalidated input.
        let domain = normalize_domain(domain)?;
        let custom_resolver;
        let resolver = if let Some(ns) = nameserver {
            custom_resolver = self.create_custom_resolver(ns).await?;
            &custom_resolver
        } else {
            &self.default_resolver
        };
        self.resolve_srv_core(resolver, service, protocol, &domain)
            .await
    }

    /// Core SRV resolution against an already-built resolver. Validates the
    /// service/protocol labels (DNS query-injection guard) then queries
    /// `_service._proto.domain`. Shared by the public [`resolve_srv`] entry
    /// point and the `dig`-style SRV path in [`resolve`]. Label-validation
    /// failures are [`SeerError::InvalidInput`] — they are caller mistakes, not
    /// transient DNS failures, so they must not be advertised as retryable.
    async fn resolve_srv_core(
        &self,
        resolver: &TokioResolver,
        service: &str,
        protocol: &str,
        domain: &str,
    ) -> Result<Vec<DnsRecord>> {
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

        let query_name = format!("_{}._{}.{}", service, protocol, domain);

        let Some(response) = dns_lookup_or_empty(
            resolver.lookup(&query_name, HickoryRecordType::SRV).await,
            "SRV",
        )?
        else {
            return Ok(vec![]);
        };

        let records = response
            .answers()
            .iter()
            .filter_map(|record| {
                if let HickoryRData::SRV(srv) = &record.data {
                    Some(DnsRecord {
                        name: query_name.clone(),
                        record_type: RecordType::SRV,
                        ttl: record.ttl,
                        data: RecordData::SRV {
                            priority: srv.priority,
                            weight: srv.weight,
                            port: srv.port,
                            target: srv.target.to_string(),
                        },
                    })
                } else {
                    None
                }
            })
            .collect();

        Ok(records)
    }

    /// Single-type dispatch shared by [`resolve`](Self::resolve) and
    /// [`resolve_any`] — the one place a seer [`RecordType`] is routed to a
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
            // PTR accepts a raw IP literal, which is queried as its
            // reverse-DNS name (and reported under that name).
            RecordType::PTR => {
                let query = if let Ok(ip) = IpAddr::from_str(domain) {
                    reverse_dns_name(&ip)
                } else {
                    domain.to_string()
                };
                self.resolve_records(resolver, &query, RecordType::PTR)
                    .await
            }
            single => self.resolve_records(resolver, domain, single).await,
        }
    }

    /// Generic single-type lookup: queries the wire type for `record_type`
    /// and maps each matching answer through [`convert_rdata`]. Answers of
    /// other types (e.g. a CNAME returned alongside A records) are skipped.
    /// NXDOMAIN/NODATA fold to an empty vec (see [`dns_lookup_or_empty`]).
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

        let Some(response) = dns_lookup_or_empty(
            resolver.lookup(domain, wire_type).await,
            &record_type.to_string(),
        )?
        else {
            return Ok(vec![]);
        };

        let mut records: Vec<DnsRecord> = response
            .answers()
            .iter()
            .filter_map(|record| {
                convert_rdata(record_type, &record.data).map(|data| DnsRecord {
                    name: domain.to_string(),
                    record_type,
                    ttl: record.ttl,
                    data,
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
        // Query common record types concurrently — previously these ran
        // serially, making `ANY` ~7x slower than a single query (#61).
        // `join_all` preserves input order, so the merged record list keeps the
        // A, AAAA, MX, … ordering.
        let record_types = [
            RecordType::A,
            RecordType::AAAA,
            RecordType::MX,
            RecordType::NS,
            RecordType::TXT,
            RecordType::SOA,
            RecordType::CAA,
        ];

        let results = futures::future::join_all(
            record_types
                .into_iter()
                .map(|record_type| self.resolve_type(resolver, domain, record_type)),
        )
        .await;

        // Track whether any sub-query actually succeeded (an empty answer
        // for an existing domain still counts as success). If every type
        // errored — e.g. the resolver is unreachable — surface that error
        // rather than returning an empty set that reads as "no records".
        let mut all_records = Vec::new();
        let mut any_ok = false;
        let mut last_err = None;
        for result in results {
            match result {
                Ok(records) => {
                    any_ok = true;
                    all_records.extend(records);
                }
                Err(e) => last_err = Some(e),
            }
        }

        match last_err {
            Some(e) if !any_ok => Err(e),
            _ => Ok(all_records),
        }
    }
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
        classify_ns_presence(&self.resolve(domain, RecordType::NS, None).await)
    }
}

// Domain normalization is now handled by the shared validation module

/// Prepares the query string for a DNS lookup.
///
/// PTR queries may be given a raw IP literal. IPv6 literals in particular must
/// NOT pass through [`normalize_domain`]: its trailing-`:port` strip heuristic
/// truncates the final hextet (e.g. `::1111` → dropped) and the remaining `:`
/// separators then fail character validation, so IPv6 reverse lookups errored
/// out with "Invalid domain name" before ever reaching `resolve_ptr`. For PTR
/// queries we therefore detect an IP literal up front and pass it through in
/// canonical form; everything else (domains, and PTR queries given a
/// reverse-DNS name such as `1.1.1.1.in-addr.arpa`) is normalized as usual.
fn prepare_query(domain: &str, record_type: RecordType) -> Result<String> {
    if record_type == RecordType::PTR {
        if let Ok(ip) = IpAddr::from_str(domain.trim()) {
            return Ok(ip.to_string());
        }
    }
    normalize_domain(domain)
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
    // hickory 0.26: CAA fields are public. `issuer_critical` and `tag` are
    // plain fields; `value` is a `Vec<u8>` because RFC 8659 permits binary
    // values for unknown property types. For seer's reporting purposes the
    // common tags (issue/issuewild/iodef) are always UTF-8, so a lossy
    // conversion preserves prior behavior without panicking on the rare
    // binary case.
    let flags = if caa.issuer_critical { 128 } else { 0 };
    let tag = caa.tag.clone();
    let value = String::from_utf8_lossy(&caa.value).to_string();
    (flags, tag, value)
}

/// Maps a concrete seer [`RecordType`] to the hickory wire type it queries.
///
/// `SRV` and `ANY` are composite lookups with dedicated paths
/// (`resolve_srv_core` / `resolve_any`) and deliberately have no mapping
/// here — asking [`DnsResolver::resolve_type`] for them is an error.
fn wire_type(record_type: RecordType) -> Option<HickoryRecordType> {
    Some(match record_type {
        RecordType::A => HickoryRecordType::A,
        RecordType::AAAA => HickoryRecordType::AAAA,
        RecordType::CNAME => HickoryRecordType::CNAME,
        RecordType::MX => HickoryRecordType::MX,
        RecordType::NS => HickoryRecordType::NS,
        RecordType::TXT => HickoryRecordType::TXT,
        RecordType::SOA => HickoryRecordType::SOA,
        RecordType::PTR => HickoryRecordType::PTR,
        RecordType::CAA => HickoryRecordType::CAA,
        RecordType::DNSKEY => HickoryRecordType::DNSKEY,
        RecordType::DS => HickoryRecordType::DS,
        // TLSA queries are how DANE clients discover the certificate
        // association data for a TLS endpoint. The convention is
        // `_<port>._<proto>.<host>` (e.g. `_443._tcp.example.com`); seer
        // does not enforce the label shape because TLSA is also used for
        // other transports.
        RecordType::TLSA => HickoryRecordType::TLSA,
        RecordType::SSHFP => HickoryRecordType::SSHFP,
        RecordType::NAPTR => HickoryRecordType::NAPTR,
        RecordType::SRV | RecordType::ANY => return None,
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

/// Converts one hickory answer's RData into our [`RecordData`], if it is the
/// variant `record_type` asked for. Any other RData in the answer section
/// (e.g. a CNAME returned alongside A records) yields `None` and is skipped.
///
/// This is the single RData→RecordData conversion table used by every
/// resolution path.
fn convert_rdata(record_type: RecordType, data: &HickoryRData) -> Option<RecordData> {
    use hickory_resolver::proto::dnssec::rdata::DNSSECRData;

    match (record_type, data) {
        (RecordType::A, HickoryRData::A(addr)) => Some(RecordData::A {
            address: addr.0.to_string(),
        }),
        (RecordType::AAAA, HickoryRData::AAAA(addr)) => Some(RecordData::AAAA {
            address: addr.0.to_string(),
        }),
        (RecordType::CNAME, HickoryRData::CNAME(cname)) => Some(RecordData::CNAME {
            target: cname.0.to_string(),
        }),
        (RecordType::MX, HickoryRData::MX(mx)) => Some(RecordData::MX {
            preference: mx.preference,
            exchange: mx.exchange.to_string(),
        }),
        (RecordType::NS, HickoryRData::NS(ns)) => Some(RecordData::NS {
            nameserver: ns.0.to_string(),
        }),
        (RecordType::TXT, HickoryRData::TXT(txt)) => Some(RecordData::TXT {
            text: txt
                .txt_data
                .iter()
                .map(|data| String::from_utf8_lossy(data).to_string())
                .collect::<Vec<_>>()
                .join(""),
        }),
        (RecordType::SOA, HickoryRData::SOA(soa)) => Some(RecordData::SOA {
            mname: soa.mname.to_string(),
            rname: soa.rname.to_string(),
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
            target: ptr.0.to_string(),
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
            replacement: naptr.replacement.to_string(),
        }),
        _ => None,
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
    //! below) that exercise the full `resolve()` path against a local UDP
    //! fixture serving hickory-proto-encoded canned responses. Live-network
    //! variants remain `#[ignore]`d here and in the sibling modules
    //! (`dns/dnssec.rs`, `dns/follow.rs`).

    use super::*;

    #[test]
    fn from_config_applies_dns_timeout() {
        let mut config = crate::config::SeerConfig::default();
        config.timeouts.dns_secs = 9;
        let resolver = DnsResolver::from_config(&config);
        assert_eq!(resolver.timeout, Duration::from_secs(9));
    }
    use std::net::{Ipv4Addr, Ipv6Addr};

    // --- RecordType::from_str edge cases -----------------------------

    #[test]
    fn record_type_from_str_accepts_lowercase() {
        assert_eq!(RecordType::from_str("a").unwrap(), RecordType::A);
        assert_eq!(RecordType::from_str("mx").unwrap(), RecordType::MX);
        assert_eq!(RecordType::from_str("cname").unwrap(), RecordType::CNAME);
        assert_eq!(RecordType::from_str("dnskey").unwrap(), RecordType::DNSKEY);
    }

    #[test]
    fn record_type_from_str_accepts_mixed_case() {
        assert_eq!(RecordType::from_str("Mx").unwrap(), RecordType::MX);
        assert_eq!(RecordType::from_str("cNaMe").unwrap(), RecordType::CNAME);
    }

    #[test]
    fn record_type_from_str_rejects_whitespace_padded() {
        // No trim is done inside from_str; leading/trailing whitespace
        // must currently cause a parse error so callers don't pass
        // malformed labels through.
        assert!(RecordType::from_str(" A").is_err());
        assert!(RecordType::from_str("A ").is_err());
        assert!(RecordType::from_str("\tA\n").is_err());
    }

    #[test]
    fn record_type_from_str_rejects_unknown() {
        assert!(RecordType::from_str("NOTAREAL").is_err());
        assert!(RecordType::from_str("A1").is_err());
        assert!(RecordType::from_str("").is_err());
    }

    #[test]
    fn record_type_from_str_accepts_star_as_any() {
        assert_eq!(RecordType::from_str("*").unwrap(), RecordType::ANY);
        assert_eq!(RecordType::from_str("ANY").unwrap(), RecordType::ANY);
        assert_eq!(RecordType::from_str("any").unwrap(), RecordType::ANY);
    }

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

    // --- DnsResolver construction ------------------------------------

    #[test]
    fn resolver_new_has_default_timeout() {
        let r = DnsResolver::new();
        assert_eq!(r.timeout, DEFAULT_TIMEOUT);
    }

    #[test]
    fn resolver_with_timeout_overrides_default() {
        let custom = Duration::from_secs(42);
        let r = DnsResolver::new().with_timeout(custom);
        assert_eq!(r.timeout, custom);
    }

    #[test]
    fn resolver_default_matches_new() {
        let a = DnsResolver::default();
        let b = DnsResolver::new();
        assert_eq!(a.timeout, b.timeout);
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
            "https://[fd00::1]:443/dns-query",
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

    #[test]
    fn upstream_config_test_port_override_wins() {
        // The #[cfg(test)] mock-server seam must override the spec's port.
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let config = build_upstream_config(&spec("127.0.0.1"), &[ip], Some(9999));
        assert_eq!(config.name_servers()[0].connections[0].port, 9999);
    }

    // --- Live DoT/DoH queries (opt-in only) ----------------------------

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
        let result = r.resolve_srv("http.evil", "tcp", "example.com", None).await;
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
        let result = r.resolve_srv("http", "tcp.evil", "example.com", None).await;
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
        // resolve_srv was the one public entry point that skipped
        // normalize_domain, so garbage input reached query construction as a
        // (misclassified) DNS failure instead of an input error, and URL-form
        // input built a literal `_http._tcp.HTTPS://…` query name
        // (2026-07-11 review).
        let r = DnsResolver::new();
        let result = r
            .resolve_srv("http", "tcp", "not a valid domain", None)
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
    fn prepare_query_normalizes_domains_for_non_ptr() {
        let out = prepare_query("HTTPS://WWW.Example.com/path", RecordType::A).unwrap();
        assert_eq!(out, "example.com");
    }

    // --- Hermetic mock-server tests -----------------------------------
    //
    // These run a real UDP socket on 127.0.0.1 serving hickory-proto-encoded
    // canned responses, exercising the full resolve() path (normalization →
    // custom-resolver construction → hickory transport → RData conversion)
    // without touching the network. The SSRF guards deliberately refuse
    // loopback, so the resolver under test uses the `#[cfg(test)]`-only
    // `allowing_private_hosts` / `with_port` seams, which do not exist in
    // release builds.

    use hickory_resolver::proto::op::{Message, OpCode, ResponseCode};
    use hickory_resolver::proto::rr::rdata as wire;
    use hickory_resolver::proto::rr::rdata::{sshfp, tlsa};
    use hickory_resolver::proto::rr::{Name, Record};
    use tokio::net::UdpSocket;

    /// How the mock server answers every query it receives.
    #[derive(Clone, Copy)]
    enum MockMode {
        /// Answer from the canned zone (see [`zone_answers`]).
        Zone,
        /// NXDOMAIN for every query.
        Nxdomain,
        /// NOERROR with an empty answer section (NODATA).
        NoData,
        /// Never respond, forcing the client's timeout path.
        Ignore,
    }

    fn name(s: &str) -> Name {
        Name::from_ascii(s).expect("valid test name")
    }

    /// Canned zone for [`MockMode::Zone`]. Query names are matched with the
    /// trailing root dot stripped, since hickory sends fully-qualified names.
    fn zone_answers(qname: &str, qtype: HickoryRecordType) -> Vec<HickoryRData> {
        match (qname.trim_end_matches('.'), qtype) {
            ("seer.test", HickoryRecordType::A) => vec![
                HickoryRData::A(wire::A(Ipv4Addr::new(192, 0, 2, 1))),
                HickoryRData::A(wire::A(Ipv4Addr::new(192, 0, 2, 2))),
            ],
            ("seer.test", HickoryRecordType::AAAA) => vec![HickoryRData::AAAA(wire::AAAA(
                "2001:db8::1".parse().expect("valid IPv6 literal"),
            ))],
            // Deliberately out of preference order to prove resolve() sorts.
            ("seer.test", HickoryRecordType::MX) => vec![
                HickoryRData::MX(wire::MX::new(30, name("c.mail.seer.test."))),
                HickoryRData::MX(wire::MX::new(10, name("a.mail.seer.test."))),
                HickoryRData::MX(wire::MX::new(20, name("b.mail.seer.test."))),
            ],
            ("seer.test", HickoryRecordType::NS) => {
                vec![HickoryRData::NS(wire::NS(name("ns1.seer.test.")))]
            }
            // Two character-strings, to prove segments are joined.
            ("seer.test", HickoryRecordType::TXT) => vec![HickoryRData::TXT(wire::TXT::new(vec![
                "v=spf1 ".to_string(),
                "-all".to_string(),
            ]))],
            ("seer.test", HickoryRecordType::SOA) => vec![HickoryRData::SOA(wire::SOA::new(
                name("ns1.seer.test."),
                name("hostmaster.seer.test."),
                2026070101,
                7200,
                3600,
                1209600,
                300,
            ))],
            // `CAA` here is the top-of-file production import (it has no
            // struct-literal constructor; the type is #[non_exhaustive]).
            ("seer.test", HickoryRecordType::CAA) => vec![
                HickoryRData::CAA(CAA::new_issue(false, Some(name("letsencrypt.org")), vec![])),
                HickoryRData::CAA(CAA::new_iodef(
                    true,
                    url::Url::parse("mailto:security@seer.test").expect("valid iodef URL"),
                )),
            ],
            ("_443._tcp.seer.test", HickoryRecordType::TLSA) => {
                vec![HickoryRData::TLSA(wire::TLSA::new(
                    tlsa::CertUsage::from(3),
                    tlsa::Selector::from(1),
                    tlsa::Matching::from(1),
                    vec![0xAB, 0xCD, 0x01],
                ))]
            }
            ("seer.test", HickoryRecordType::SSHFP) => {
                vec![HickoryRData::SSHFP(wire::SSHFP::new(
                    sshfp::Algorithm::from(4),
                    sshfp::FingerprintType::from(2),
                    vec![0xDE, 0xAD, 0xBE, 0xEF],
                ))]
            }
            ("seer.test", HickoryRecordType::NAPTR) => {
                vec![HickoryRData::NAPTR(wire::NAPTR::new(
                    100,
                    50,
                    b"U".to_vec().into_boxed_slice(),
                    b"E2U+sip".to_vec().into_boxed_slice(),
                    b"!^.*$!sip:info@seer.test!".to_vec().into_boxed_slice(),
                    Name::root(),
                ))]
            }
            ("_sip._tcp.seer.test", HickoryRecordType::SRV) => vec![HickoryRData::SRV(
                wire::SRV::new(10, 5, 5060, name("sipserver.seer.test.")),
            )],
            ("1.2.0.192.in-addr.arpa", HickoryRecordType::PTR) => {
                vec![HickoryRData::PTR(wire::PTR(name("ptr.seer.test.")))]
            }
            _ => vec![],
        }
    }

    /// Binds a UDP socket on an ephemeral loopback port and answers DNS
    /// queries per `mode` until the test runtime shuts down. Returns the
    /// bound port.
    async fn spawn_mock_dns(mode: MockMode) -> u16 {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind mock DNS");
        let port = socket.local_addr().expect("mock DNS local addr").port();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                let Ok((len, src)) = socket.recv_from(&mut buf).await else {
                    return;
                };
                if matches!(mode, MockMode::Ignore) {
                    continue;
                }
                let Ok(request) = Message::from_vec(&buf[..len]) else {
                    continue;
                };
                let mut response = Message::response(request.metadata.id, OpCode::Query);
                response.metadata.recursion_desired = request.metadata.recursion_desired;
                response.metadata.recursion_available = true;
                // Echo the question section — hickory discards responses
                // whose queries don't match the request (anti-spoofing).
                for query in &request.queries {
                    response.add_query(query.clone());
                }
                match mode {
                    MockMode::Zone => {
                        if let Some(query) = request.queries.first() {
                            for rdata in zone_answers(&query.name.to_string(), query.query_type) {
                                response.add_answer(Record::from_rdata(
                                    query.name.clone(),
                                    300,
                                    rdata,
                                ));
                            }
                        }
                    }
                    MockMode::Nxdomain => {
                        response.metadata.response_code = ResponseCode::NXDomain;
                    }
                    MockMode::NoData | MockMode::Ignore => {}
                }
                let Ok(bytes) = response.to_vec() else {
                    continue;
                };
                let _ = socket.send_to(&bytes, src).await;
            }
        });
        port
    }

    fn mock_dns_resolver(port: u16) -> DnsResolver {
        DnsResolver::new()
            .with_timeout(Duration::from_millis(500))
            .allowing_private_hosts()
            .with_port(port)
    }

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
            RecordData::TXT { text } => assert_eq!(text, "v=spf1 -all"),
            other => panic!("expected TXT data, got {other:?}"),
        }
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
    async fn mock_resolve_any_aggregates_multiple_types() {
        let records = mock_zone_lookup(RecordType::ANY, "seer.test").await;
        // resolve_any fans out to exactly A/AAAA/MX/NS/TXT/SOA/CAA.
        for expected in [
            RecordType::A,
            RecordType::AAAA,
            RecordType::MX,
            RecordType::NS,
            RecordType::TXT,
            RecordType::SOA,
            RecordType::CAA,
        ] {
            assert!(
                records.iter().any(|r| r.record_type == expected),
                "ANY must include {expected} records"
            );
        }
        // 2 A + 1 AAAA + 3 MX + 1 NS + 1 TXT + 1 SOA + 2 CAA = 11
        assert_eq!(records.len(), 11);
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
}
