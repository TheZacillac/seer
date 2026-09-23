//! DNS propagation checking: queries one record type against 30 public
//! resolvers concurrently (`servers.rs`), then groups the answers into a
//! consensus, per-server inconsistencies and unreachable servers
//! (`analysis.rs`) behind [`PropagationChecker`].

mod analysis;
mod checker;
mod servers;
mod types;

pub use checker::PropagationChecker;
pub use types::{
    ConsensusValue, DnsServer, Inconsistency, NameserverDetails, NameserverIpInconsistency,
    PropagationResult, UnreachableServer,
};
