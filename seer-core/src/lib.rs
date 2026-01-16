pub mod bulk;
pub mod colors;
pub mod dns;
pub mod error;
pub mod lookup;
pub mod output;
pub mod rdap;
pub mod status;
pub mod validation;
pub mod whois;

pub use error::{Result, SeerError};
pub use validation::{normalize_domain, validate_domain_safe};

pub use dns::{DnsRecord, DnsResolver, PropagationResult, RecordType};
pub use lookup::{LookupResult, SmartLookup};
pub use rdap::{RdapClient, RdapResponse};
pub use status::{CertificateInfo, DomainExpiration, StatusClient, StatusResponse};
pub use whois::{WhoisClient, WhoisResponse};

pub use bulk::{BulkExecutor, BulkOperation, BulkResult};
pub use output::{OutputFormat, OutputFormatter};
