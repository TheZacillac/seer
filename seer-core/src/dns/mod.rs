//! DNS resolution and analysis over hickory-resolver.
//!
//! - [`DnsResolver`]: the 20 [`RecordType`]s, against Google Public DNS by
//!   default or a custom nameserver over UDP, DoT (`tls://`) or DoH
//!   (`https://`) — see [`NameserverSpec`]. A hostname nameserver's resolved
//!   addresses are tried IPv4 first. [`DnsResolver::resolve`] returns the
//!   records of the requested type; [`DnsResolver::query`] returns the whole
//!   response as dig reports it ([`DnsQueryResult`]: status, flags, CNAME
//!   chain under real owner names, negative-answer SOA, wildcard probe).
//! - [`PropagationChecker`]: fans one query out to 20 public resolvers across
//!   3 regions and reports consensus and inconsistencies.
//! - [`DnsComparator`] (two nameservers side by side), [`DnsFollower`] (live
//!   monitor), [`DnssecChecker`] and [`DelegationChecker`] (parent NS set vs.
//!   the zone's own NS RRset, plus lameness probes).
//! - [`DnsTracer`]: iterative resolution from the root servers down, one
//!   [`TraceHop`] per delegation level (`dig +trace`).
//!
//! No outer retry loop at this layer: hickory's own re-send of a timed-out
//! attempt is the only retry (see `resolver.rs`).

use std::time::Duration;

mod compare;
mod delegation;
mod dnssec;
mod follow;
mod nameserver;
mod propagation;
mod query;
mod records;
mod resolver;
#[cfg(test)]
pub(crate) mod test_support;
mod trace;
mod transport;

pub use compare::{DnsComparator, DnsComparison, ServerResult};
pub use delegation::{DelegationChecker, DelegationReport, LameNs};
pub use dnssec::{AuthenticationTier, DnskeyInfo, DnssecChecker, DnssecReport, DsInfo};
pub use follow::{
    DnsFollower, FollowConfig, FollowIteration, FollowProgressCallback, FollowResult,
    MAX_FOLLOW_INTERVAL_SECS, MAX_FOLLOW_ITERATIONS,
};
pub use nameserver::{NameserverProtocol, NameserverSpec};
pub use propagation::{
    ConsensusValue, DnsServer, Inconsistency, NameserverDetails, NameserverIpInconsistency,
    PropagationChecker, PropagationResult, PropagationServerResult, PropagationVerdict,
    ServerVerdict, UnreachableServer,
};
pub use query::{DnsQueryResult, DnsStatus, WildcardProbe};
pub use records::{DnsRecord, RecordData, RecordType, SvcParam};
pub use resolver::{DnsPresence, DnsResolver};
pub use trace::{DnsTrace, DnsTracer, TraceHop};
// Crate-internal: shared with `net.rs` so the SSRF fallback resolver and the
// main resolver cannot drift apart on option settings.
pub(crate) use resolver::apply_standard_opts;

/// The per-query DNS timeout when no config supplies one — the config
/// file's `timeouts.dns_secs` default. One definition for every DNS client's
/// `new()`.
pub(crate) const DEFAULT_DNS_TIMEOUT: Duration = Duration::from_secs(5);
