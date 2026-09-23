//! DNS resolution and analysis over hickory-resolver.
//!
//! - [`DnsResolver`]: the 16 [`RecordType`]s, against Google Public DNS by
//!   default or a custom nameserver over UDP, DoT (`tls://`) or DoH
//!   (`https://`) — see [`NameserverSpec`]. A hostname nameserver's resolved
//!   addresses are tried IPv4 first.
//! - [`PropagationChecker`]: fans one query out to 30 public resolvers across
//!   6 regions and reports consensus and inconsistencies.
//! - [`DnsComparator`] (two nameservers side by side), [`DnsFollower`] (live
//!   monitor), [`DnssecChecker`] and [`DelegationChecker`] (parent NS set vs.
//!   the zone's own NS RRset, plus lameness probes).
//!
//! No outer retry loop at this layer: hickory's own retransmission is the
//! only retry (see `resolver.rs`).

mod compare;
mod delegation;
mod dnssec;
mod follow;
mod nameserver;
mod propagation;
mod records;
mod resolver;
#[cfg(test)]
pub(crate) mod test_support;

pub use compare::{DnsComparator, DnsComparison, ServerResult};
pub use delegation::{DelegationChecker, DelegationReport, LameNs};
pub use dnssec::{AuthenticationTier, DnskeyInfo, DnssecChecker, DnssecReport, DsInfo, RrsigInfo};
pub use follow::{
    DnsFollower, FollowConfig, FollowIteration, FollowProgressCallback, FollowResult,
    MAX_FOLLOW_INTERVAL_SECS, MAX_FOLLOW_ITERATIONS,
};
pub use nameserver::{NameserverProtocol, NameserverSpec};
pub use propagation::{
    ConsensusValue, DnsServer, Inconsistency, NameserverDetails, NameserverIpInconsistency,
    PropagationChecker, PropagationResult, UnreachableServer,
};
pub use records::{DnsRecord, RecordData, RecordType};
pub use resolver::{DnsPresence, DnsResolver};
// Crate-internal: shared with `net.rs` so the SSRF fallback resolver and the
// main resolver cannot drift apart on option settings.
pub(crate) use resolver::apply_standard_opts;
