mod compare;
mod dnssec;
mod follow;
mod nameserver;
mod propagation;
mod records;
mod resolver;
#[cfg(test)]
pub(crate) mod test_support;

pub use compare::{DnsComparator, DnsComparison, ServerResult};
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
