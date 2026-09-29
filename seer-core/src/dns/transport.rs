//! One DNS request, and the response exactly as the server sent it.
//!
//! hickory's resolver answers lookups, not queries: its name-server layer
//! (`DnsError::from_response`) turns every NXDOMAIN, NODATA and referral into
//! a `NoRecordsFound` error that drops the response header, and its caching
//! layer chases a CNAME with a follow-up query and reports only the last
//! name's outcome, so a chain that ends in NXDOMAIN loses the chain. `dig`
//! reports the response the server sent, so [`DnsResolver::query`] and the
//! trace walker (`dns::trace`) send their queries through here instead:
//! hickory's own per-connection API ([`ConnectionProvider::new_connection`],
//! a `DnsExchange`), which brings the resolver's UDP, TCP, DoT and DoH
//! transports and its TLS setup — the webpki roots on the aws-lc-rs provider
//! — without the lookup layers above them. The request is built as hickory's
//! resolver builds one (EDNS(0), a random ID).
//!
//! - [`Transport::exchange`] asks one server over one connection: over UDP
//!   first, and once more over TCP to the same address and port when the UDP
//!   reply is truncated, as dig does.
//! - [`Transport::query`] asks the servers of an upstream config in the
//!   config's order (IPv4 first — see `resolver::build_upstream_config`),
//!   each on its preferred connection, and moves to the next server when one
//!   fails in transport (no response, a timeout, no route) — failover, as
//!   hickory's server pool does it, not a retry of the query to the same
//!   server.
//!
//! **Retry boundary (deliberate):** like the rest of `dns/`, no
//! [`crate::retry::RetryPolicy`]. hickory's UDP transport retransmits a query
//! within the per-query timeout; nothing here re-sends it.
//!
//! **Bounds:** every exchange — a TCP repeat of a truncated reply included —
//! runs under the per-query timeout (the config file's DNS timeout), and a
//! [`Transport::query`] under [`QUERY_BUDGET_TIMEOUTS`] of them, as many as
//! the resolver's `attempts` setting.
//!
//! **SSRF:** the transport connects only to the addresses in the configs it
//! is handed and never resolves a name. Callers vet those addresses first:
//! the resolver's custom-nameserver path for `query`, and
//! `delegation::partition_reserved` for every trace hop.
//!
//! [`DnsResolver::query`]: crate::dns::DnsResolver::query

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ProtocolConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::xfer::{DnsHandle, FirstAnswer};
use hickory_resolver::net::NetError;
use hickory_resolver::proto::op::{DnsRequest, DnsRequestOptions, DnsResponse, Message, Query};
use hickory_resolver::proto::rr::{Name, RecordType as HickoryRecordType};
use hickory_resolver::{ConnectionProvider, PoolContext, TlsConfig};
use tracing::debug;

use super::delegation::is_local_no_route;
use super::resolver::{apply_standard_opts, RESOLVER_ATTEMPTS};

/// A [`Transport::query`]'s deadline, in per-query timeouts: the resolver's
/// `attempts` ([`RESOLVER_ATTEMPTS`]), so after one server times out there
/// is time to ask the next — no longer than a resolver lookup, whose retry
/// handle re-sends an attempt that timed out, may take.
pub(crate) const QUERY_BUDGET_TIMEOUTS: u32 = RESOLVER_ATTEMPTS as u32;

/// Sends DNS requests straight to given servers over hickory's transports
/// and hands back the responses as sent. See the module docs.
///
/// Cheap to clone: the options and TLS config are shared.
#[derive(Clone)]
pub(crate) struct Transport {
    /// What hickory's connections read: the resolver options (the per-query
    /// timeout among them) and the TLS client config for DoT/DoH.
    cx: Arc<PoolContext>,
}

impl Transport {
    /// A transport with seer's standard resolver options
    /// ([`apply_standard_opts`]) and `timeout` per query.
    ///
    /// The `expect` is the invariant `resolver::build_default_resolver`
    /// relies on: the TLS client config is the only fallible step, and with
    /// the bundled webpki root store its construction cannot fail.
    pub(crate) fn new(timeout: Duration) -> Self {
        let mut options = ResolverOpts::default();
        apply_standard_opts(&mut options, timeout);
        let tls =
            TlsConfig::new().expect("TLS config cannot fail with the bundled webpki root store");
        Self {
            cx: Arc::new(PoolContext::new(options, tls)),
        }
    }

    /// The per-query timeout.
    pub(crate) fn timeout(&self) -> Duration {
        self.cx.options.timeout
    }

    /// A query for `name`/`record_type`, built as hickory's resolver builds
    /// one (`Resolver::request_options`): EDNS(0) with the standard UDP
    /// payload size, a random ID, and the RD (recursion desired) bit as
    /// given — set for a query to a recursive resolver, clear for a trace
    /// hop, which must hear each server's own authority.
    pub(crate) fn request(
        &self,
        name: Name,
        record_type: HickoryRecordType,
        recursion_desired: bool,
    ) -> DnsRequest {
        let opts = &self.cx.options;
        let mut options = DnsRequestOptions::default();
        options.recursion_desired = recursion_desired;
        options.use_edns = opts.edns0;
        options.edns_payload_len = opts.edns_payload_len;
        options.case_randomization = opts.case_randomization;
        DnsRequest::from_query(Query::query(name, record_type), options)
    }

    /// Sends `request` to `ip` over `connection` and returns the response the
    /// server sent, whatever its response code. A truncated UDP reply is
    /// repeated over TCP to the same address and port — for a UDP-only
    /// nameserver spec too, as dig does. The whole exchange, TCP repeat
    /// included, runs under one per-query timeout. An `Err` means there is no
    /// response: a timeout, no route or connection, a TLS or HTTP failure, a
    /// reply that does not parse.
    pub(crate) async fn exchange(
        &self,
        ip: IpAddr,
        connection: &ConnectionConfig,
        request: &DnsRequest,
    ) -> Result<Message, NetError> {
        // A connection's I/O runs as a background task in the provider's task
        // set, which aborts its tasks once the last provider clone is
        // dropped. The UDP stream keeps a clone, but a TCP connection does
        // not, so this one outlives the whole exchange — and ends it after.
        let provider = TokioRuntimeProvider::default();
        let exchange = async {
            let response = self.send(&provider, ip, connection, request).await?;
            if !(response.metadata.truncation && connection.protocol == ProtocolConfig::Udp) {
                return Ok(response.into_message());
            }
            debug!(%ip, "truncated UDP reply, repeating the query over TCP");
            let response = self
                .send(&provider, ip, &tcp_like(connection), request)
                .await?;
            Ok(response.into_message())
        };
        tokio::time::timeout(self.timeout(), exchange)
            .await
            .unwrap_or(Err(NetError::Timeout))
    }

    /// Opens `connection` to `ip` as hickory's name server does and sends
    /// `request` on it.
    async fn send(
        &self,
        provider: &TokioRuntimeProvider,
        ip: IpAddr,
        connection: &ConnectionConfig,
        request: &DnsRequest,
    ) -> Result<DnsResponse, NetError> {
        let handle = provider.new_connection(ip, connection, &self.cx)?.await?;
        handle.send(request.clone()).first_answer().await
    }

    /// Sends `request` to `servers` in order until one responds, and returns
    /// that response as sent — NXDOMAIN, SERVFAIL or REFUSED included. Each
    /// server is asked once ([`exchange`](Self::exchange)) on its preferred
    /// connection: UDP when it has one, as hickory's pool prefers it, else
    /// its only one (DoT or DoH). A server that fails in transport passes the
    /// query to the next, under one deadline of [`QUERY_BUDGET_TIMEOUTS`]
    /// per-query timeouts for the whole list.
    ///
    /// The `Err` says why no server responded, server by server (see
    /// [`NoResponse`]).
    pub(crate) async fn query(
        &self,
        servers: &[NameServerConfig],
        request: &DnsRequest,
    ) -> Result<Message, NoResponse> {
        let budget = self.timeout().saturating_mul(QUERY_BUDGET_TIMEOUTS);
        let started = Instant::now();
        let mut failures = Vec::new();
        let mut unasked = None;
        for (index, server) in servers.iter().enumerate() {
            let remaining = budget.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                unasked = Some(format!(
                    "gave up after {budget:?} with {} more server(s) unasked",
                    servers.len() - index
                ));
                break;
            }
            let Some(connection) = preferred_connection(server) else {
                continue;
            };
            debug!(ip = %server.ip, "querying");
            let attempt = self.exchange(server.ip, connection, request);
            match tokio::time::timeout(remaining, attempt).await {
                Ok(Ok(message)) => return Ok(message),
                Ok(Err(e)) => failures.push((server.ip, transport_reason(&e))),
                Err(_) => failures.push((server.ip, "timed out".to_string())),
            }
        }
        Err(NoResponse { failures, unasked })
    }
}

/// Why no server responded to [`Transport::query`]: each asked server's
/// reason, in the order asked, and a note when the deadline left servers
/// unasked.
///
/// Displays as `"8.8.8.8: timed out; 8.8.4.4: timed out"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NoResponse {
    failures: Vec<(IpAddr, String)>,
    unasked: Option<String>,
}

impl NoResponse {
    /// Test-only: one server that timed out.
    #[cfg(test)]
    pub(crate) fn timed_out(ip: IpAddr) -> Self {
        Self {
            failures: vec![(ip, "timed out".to_string())],
            unasked: None,
        }
    }

    /// The first reason, without its server address — for a caller that
    /// asked one server and names it itself (`timed out`).
    pub(crate) fn reason(&self) -> String {
        match (self.failures.first(), &self.unasked) {
            (Some((_, reason)), _) => reason.clone(),
            (None, Some(note)) => note.clone(),
            (None, None) => NO_NAMESERVER.to_string(),
        }
    }
}

const NO_NAMESERVER: &str = "no nameserver to query";

impl std::fmt::Display for NoResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let parts: Vec<String> = self
            .failures
            .iter()
            .map(|(ip, reason)| format!("{ip}: {reason}"))
            .chain(self.unasked.clone())
            .collect();
        if parts.is_empty() {
            f.write_str(NO_NAMESERVER)
        } else {
            f.write_str(&parts.join("; "))
        }
    }
}

/// The connection a server is asked on: UDP when it has one — the order
/// hickory's name server prefers — else its first, which for a DoT or DoH
/// spec is its only one.
fn preferred_connection(server: &NameServerConfig) -> Option<&ConnectionConfig> {
    server
        .connections
        .iter()
        .find(|c| c.protocol == ProtocolConfig::Udp)
        .or_else(|| server.connections.first())
}

/// The TCP connection a truncated UDP reply is repeated over: the same port
/// and local bind address as the UDP one.
fn tcp_like(udp: &ConnectionConfig) -> ConnectionConfig {
    let mut tcp = ConnectionConfig::tcp();
    tcp.port = udp.port;
    tcp.bind_addr = udp.bind_addr;
    tcp
}

/// A short reason for an exchange that got no response.
pub(crate) fn transport_reason(err: &NetError) -> String {
    match err {
        NetError::Timeout => "timed out".to_string(),
        NetError::Io(io) if is_local_no_route(io) => format!("no route from this host ({io})"),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    //! Hermetic tests against the loopback fixture in
    //! [`crate::dns::test_support`]. The transport has no SSRF check of its
    //! own (its callers vet every address), so these build configs for
    //! 127.0.0.1 directly; each mock "server" is its own ephemeral port.

    use std::sync::Mutex;

    use hickory_resolver::config::ResolverConfig;
    use hickory_resolver::proto::op::ResponseCode;
    use hickory_resolver::proto::rr::RData;

    use super::*;
    use crate::dns::test_support::{
        a_rdata, fq_name, spawn_mock_dns, spawn_mock_dns_fn, spawn_mock_dns_fn_with_tcp, MockMode,
        MockReply,
    };

    const LOOPBACK: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

    fn transport() -> Transport {
        Transport::new(Duration::from_millis(300))
    }

    fn request_for(transport: &Transport, name: &str) -> DnsRequest {
        transport.request(fq_name(name), HickoryRecordType::A, true)
    }

    /// A UDP-only server on the loopback `port`, as a bare `@server` spec
    /// configures one.
    fn udp_server(port: u16) -> NameServerConfig {
        let mut server = NameServerConfig::udp(LOOPBACK);
        server.connections[0].port = port;
        server
    }

    fn addresses(message: &Message) -> Vec<String> {
        message
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::A(a) => Some(a.0.to_string()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn request_is_built_as_the_resolver_builds_one() {
        let transport = transport();
        let request = transport.request(fq_name("www.seer.test"), HickoryRecordType::AAAA, true);
        assert!(request.metadata.recursion_desired);
        assert_eq!(request.queries.len(), 1);
        assert_eq!(request.queries[0].name(), &fq_name("www.seer.test"));
        assert_eq!(request.queries[0].query_type(), HickoryRecordType::AAAA);
        let edns = request
            .edns
            .as_ref()
            .expect("EDNS(0), as the resolver sends");
        assert_eq!(edns.max_payload(), ResolverOpts::default().edns_payload_len);
        assert!(
            !edns.flags().dnssec_ok,
            "seer does not ask for DNSSEC records"
        );

        // A trace hop asks with recursion off.
        let hop = transport.request(fq_name("seer.test"), HickoryRecordType::NS, false);
        assert!(!hop.metadata.recursion_desired);
        assert_eq!(transport.timeout(), Duration::from_millis(300));
    }

    #[test]
    fn a_server_is_asked_over_udp_first_else_its_only_connection() {
        let google = ResolverConfig::udp_and_tcp(&hickory_resolver::config::GOOGLE);
        for server in google.name_servers() {
            assert_eq!(
                preferred_connection(server).map(|c| &c.protocol),
                Some(&ProtocolConfig::Udp)
            );
        }
        let tls = NameServerConfig::tls(LOOPBACK, Arc::from("dns.seer.test"));
        assert!(matches!(
            preferred_connection(&tls).map(|c| &c.protocol),
            Some(ProtocolConfig::Tls { server_name }) if &**server_name == "dns.seer.test"
        ));
        let https = NameServerConfig::https(LOOPBACK, Arc::from("dns.seer.test"), None);
        assert!(matches!(
            preferred_connection(&https).map(|c| &c.protocol),
            Some(ProtocolConfig::Https { path, .. }) if &**path == "/dns-query"
        ));

        let mut udp = ConnectionConfig::udp();
        udp.port = 5353;
        let tcp = tcp_like(&udp);
        assert_eq!(tcp.protocol, ProtocolConfig::Tcp);
        assert_eq!(
            tcp.port, 5353,
            "a truncated reply is repeated on the same port"
        );
    }

    #[tokio::test]
    async fn an_error_rcode_is_a_response_not_a_failure() {
        let port = spawn_mock_dns_fn(|_, _| MockReply::ServFail).await;
        let transport = transport();
        let request = request_for(&transport, "www.seer.test");
        let message = transport
            .query(&[udp_server(port)], &request)
            .await
            .expect("SERVFAIL is what the server said");
        assert_eq!(message.metadata.response_code, ResponseCode::ServFail);
        assert!(message.metadata.recursion_available);
    }

    #[tokio::test]
    async fn a_truncated_udp_reply_is_repeated_over_tcp() {
        let calls = Arc::new(Mutex::new(0));
        let seen = Arc::clone(&calls);
        let port = spawn_mock_dns_fn_with_tcp(move |_, _| {
            let mut n = seen.lock().unwrap();
            *n += 1;
            if *n == 1 {
                MockReply::Truncated
            } else {
                MockReply::Answer(vec![a_rdata([192, 0, 2, 7])])
            }
        })
        .await;
        let transport = transport();
        let request = request_for(&transport, "www.seer.test");
        // A UDP-only server, as a bare `@server` spec configures one: the TCP
        // repeat goes to the same address and port all the same.
        let message = transport
            .exchange(LOOPBACK, &udp_server(port).connections[0], &request)
            .await
            .expect("the TCP repeat answers");
        assert!(!message.metadata.truncation);
        assert_eq!(addresses(&message), ["192.0.2.7"]);
        assert_eq!(*calls.lock().unwrap(), 2, "one UDP query, one TCP query");
    }

    #[tokio::test]
    async fn a_server_that_never_answers_passes_the_query_to_the_next() {
        let silent = spawn_mock_dns(MockMode::Ignore).await;
        let answering =
            spawn_mock_dns_fn(|_, _| MockReply::Answer(vec![a_rdata([192, 0, 2, 9])])).await;
        let transport = transport();
        let request = request_for(&transport, "www.seer.test");
        let started = Instant::now();
        let message = transport
            .query(&[udp_server(silent), udp_server(answering)], &request)
            .await
            .expect("the second server answers");
        assert_eq!(addresses(&message), ["192.0.2.9"]);
        // One timeout for the silent server, then the answer.
        assert!(
            started.elapsed() < Duration::from_millis(600),
            "{:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn the_whole_list_shares_one_deadline() {
        let silent = spawn_mock_dns(MockMode::Ignore).await;
        let answering =
            spawn_mock_dns_fn(|_, _| MockReply::Answer(vec![a_rdata([192, 0, 2, 9])])).await;
        let transport = transport();
        let request = request_for(&transport, "www.seer.test");
        let started = Instant::now();
        // Two silent servers use up the budget of two timeouts: the third,
        // which would answer, is never asked.
        let servers = [
            udp_server(silent),
            udp_server(silent),
            udp_server(answering),
        ];
        let err = transport
            .query(&servers, &request)
            .await
            .expect_err("the deadline ends the list");
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(600), "{elapsed:?}");
        assert!(elapsed < Duration::from_millis(900), "{elapsed:?}");
        assert_eq!(
            err.to_string(),
            "127.0.0.1: timed out; 127.0.0.1: timed out; gave up after 600ms with 1 more \
             server(s) unasked"
        );
        assert_eq!(err.reason(), "timed out");
        let none = transport.query(&[], &request).await.unwrap_err();
        assert_eq!(none.to_string(), "no nameserver to query");
        assert_eq!(none.reason(), "no nameserver to query");
    }
}
