pub mod dnssec;
mod follow;
mod propagation;
mod records;
mod resolver;

pub use dnssec::{DnssecChecker, DnssecReport};
pub use follow::{
    DnsFollower, FollowConfig, FollowIteration, FollowProgressCallback, FollowResult,
};
pub use propagation::{DnsServer, PropagationChecker, PropagationResult};
pub use records::{DnsRecord, RecordData, RecordType};
pub use resolver::DnsResolver;
