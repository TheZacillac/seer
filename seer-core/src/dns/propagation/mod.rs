mod analysis;
mod checker;
mod servers;
mod types;

pub use checker::PropagationChecker;
pub use types::{
    ConsensusValue, DnsServer, Inconsistency, NameserverIpInconsistency, PropagationResult,
    UnreachableServer,
};
