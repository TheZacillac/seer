mod compare;
mod dnssec;
mod follow;
mod propagation;
mod records;
mod resolver;

pub use compare::{DnsComparator, DnsComparison, ServerResult};
pub use dnssec::{DnskeyInfo, DnssecChecker, DnssecReport, DsInfo};
pub use follow::{
    DnsFollower, FollowConfig, FollowIteration, FollowProgressCallback, FollowResult,
};
pub use propagation::{
    ConsensusValue, DnsServer, Inconsistency, PropagationChecker, PropagationResult,
    UnreachableServer,
};
pub use records::{DnsRecord, RecordData, RecordType};
pub use resolver::DnsResolver;
