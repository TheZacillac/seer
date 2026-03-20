pub mod availability;
pub mod bulk;
pub mod cache;
pub mod colors;
pub mod config;
pub mod dns;
pub mod error;
pub mod lookup;
pub mod output;
pub mod rdap;
pub mod retry;
pub mod status;
pub mod validation;
pub mod whois;

pub use availability::{AvailabilityChecker, AvailabilityResult};
pub use cache::{SingleValueCache, TtlCache};
pub use config::SeerConfig;
pub use error::{Result, SeerError};
pub use retry::{NetworkRetryClassifier, RetryClassifier, RetryExecutor, RetryPolicy};
pub use validation::{normalize_domain, validate_domain_safe};

pub use dns::{
    DnsFollower, DnsRecord, DnsResolver, DnssecChecker, DnssecReport, FollowConfig,
    FollowIteration, FollowResult, PropagationResult, RecordType,
};
pub use lookup::{LookupProgressCallback, LookupResult, SmartLookup};
pub use rdap::{RdapClient, RdapResponse};
pub use status::{CertificateInfo, DnsResolution, DomainExpiration, StatusClient, StatusResponse};
pub use whois::{WhoisClient, WhoisResponse};

pub use bulk::{BulkExecutor, BulkOperation, BulkResult};
pub use output::{OutputFormat, OutputFormatter};
