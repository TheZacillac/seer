pub mod availability;
pub mod bulk;
pub mod caa;
pub mod cache;
pub mod colors;
pub mod config;
pub mod confusables;
pub mod diff;
pub mod dns;
pub mod domain_info;
pub mod drift;
pub mod error;
pub mod history;
pub mod logging;
pub mod lookup;
pub mod net;
pub mod output;
pub mod posture;
pub mod rdap;
pub mod retry;
pub mod ssl;
pub mod status;
pub mod subdomains;
pub mod tld;
pub mod validation;
pub mod watchlist;
pub mod whois;

pub use availability::{AvailabilityChecker, AvailabilityResult};
pub use cache::{SingleValueCache, TtlCache};
pub use config::SeerConfig;
pub use error::{Result, SeerError};
pub use retry::{NetworkRetryClassifier, RetryClassifier, RetryExecutor, RetryPolicy};
pub use validation::normalize_domain;

pub use dns::{
    AuthenticationTier, DnsComparator, DnsComparison, DnsFollower, DnsRecord, DnsResolver,
    DnssecChecker, DnssecReport, FollowConfig, FollowIteration, FollowResult, PropagationResult,
    RecordType, RrsigInfo, MAX_FOLLOW_INTERVAL_SECS, MAX_FOLLOW_ITERATIONS,
};
pub use lookup::{LookupProgressCallback, LookupResult, SmartLookup};
pub use rdap::{RdapClient, RdapResponse};
pub use status::{CertificateInfo, DnsResolution, DomainExpiration, StatusClient, StatusResponse};
pub use tld::{all_tlds, lookup_tld, TldInfo};
pub use whois::{WhoisClient, WhoisResponse};

pub use bulk::{BulkExecutor, BulkOperation, BulkResult};
pub use caa::{CaaPolicy, CaaRecord, IssuerCaaMatch};
pub use confusables::{
    find_confusables, generate_candidates, ConfusableCandidate, ConfusableReport,
    RegisteredLookalike,
};
pub use diff::{DomainDiff, DomainDiffer};
pub use domain_info::{
    describe_epp_status, DomainInfo, DomainInfoSource, ExpiryStatus, StatusDescription,
};
pub use drift::{drift_from_history, DriftReport, FieldChange};
pub use history::{HistoryEntry, LookupHistory};
pub use output::{OutputFormat, OutputFormatter};
pub use posture::{
    lookup_email_posture, BimiPolicy, DanePolicy, DmarcPolicy, EmailPosture, MtaStsPolicy,
    PostureVerdict, SpfPolicy,
};
pub use ssl::{CertDetail, CertWarning, CertWarningSeverity, SslChecker, SslReport};
pub use subdomains::{
    classify_subdomains, ClassifiedSubdomain, SubdomainBaseline, SubdomainBaselineDiff,
    SubdomainBaselines, SubdomainClassification, SubdomainEnumerator, SubdomainResult,
    SubdomainStatus,
};
pub use watchlist::{check_watchlist, WatchReport, WatchResult, Watchlist};
