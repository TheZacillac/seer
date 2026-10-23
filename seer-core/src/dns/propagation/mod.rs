//! DNS propagation checking: queries one record type against a list of
//! public, unfiltered recursive resolvers concurrently (`servers.rs`), one
//! direct query per server, then groups the answers into a consensus,
//! per-server inconsistencies and unreachable servers (`analysis.rs`) behind
//! [`PropagationChecker`]. Each server is held to its own budget (two
//! per-query timeouts plus a second). An NS check then asks every responding
//! server for the addresses of the nameserver hostnames it saw (at most 13,
//! the most-reported first) under one more budget for the whole phase; a
//! lookup it cuts off is "no data", and the NS answers stay as they arrived.
//! [`PropagationResult::verdict`] and
//! [`PropagationResult::server_verdict`] are the one reading of a result
//! that every renderer shares.

mod analysis;
mod checker;
mod servers;
mod types;

pub(super) use checker::read_reply;
pub use checker::PropagationChecker;
/// One server's result in a [`PropagationResult`] (named apart from the
/// DNS comparison's own `ServerResult`).
pub use types::ServerResult as PropagationServerResult;
pub use types::{
    ConsensusValue, DnsServer, Inconsistency, NameserverDetails, NameserverIpInconsistency,
    PropagationResult, PropagationVerdict, ServerVerdict, UnreachableServer,
};
