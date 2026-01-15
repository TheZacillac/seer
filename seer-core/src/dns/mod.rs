mod propagation;
mod records;
mod resolver;

pub use propagation::{DnsServer, PropagationChecker, PropagationResult};
pub use records::{DnsRecord, RecordType};
pub use resolver::DnsResolver;
