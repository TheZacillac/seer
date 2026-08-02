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
