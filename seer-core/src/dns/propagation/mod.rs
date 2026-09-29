//! DNS propagation checking: queries one record type against a list of
//! public, unfiltered recursive resolvers concurrently (`servers.rs`), one
//! direct query per server, then groups the answers into a consensus,
//! per-server inconsistencies and unreachable servers (`analysis.rs`) behind
//! [`PropagationChecker`]. [`PropagationResult::verdict`] and
//! [`PropagationResult::server_verdict`] are the one reading of a result
//! that every renderer shares.

mod analysis;
mod checker;
mod servers;
mod types;

pub use checker::PropagationChecker;
/// One server's result in a [`PropagationResult`] (named apart from the
/// DNS comparison's own `ServerResult`).
pub use types::ServerResult as PropagationServerResult;
pub use types::{
    ConsensusValue, DnsServer, Inconsistency, NameserverDetails, NameserverIpInconsistency,
    PropagationResult, PropagationVerdict, ServerVerdict, UnreachableServer,
};
