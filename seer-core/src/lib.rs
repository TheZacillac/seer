/// Declares lazily compiled `static` regexes, one `NAME = r"pattern";` per
/// entry (doc comments and a visibility may precede each). Patterns are
/// literals, so an invalid one panics on first use — which every parser's
/// tests exercise.
macro_rules! static_regex {
    ($($(#[$meta:meta])* $vis:vis $name:ident = $re:literal;)+) => {
        $(
            $(#[$meta])*
            $vis static $name: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
                regex::Regex::new($re).expect(concat!("invalid regex ", stringify!($name)))
            });
        )+
    };
}

pub mod availability;
pub mod bulk;
pub mod caa;
pub mod cache;
#[cfg(feature = "cli")]
pub mod colors;
pub mod config;
pub mod confusables;
mod dates;
pub mod diff;
pub mod dns;
#[cfg(feature = "cli")]
pub mod doctor;
pub mod domain_info;
#[cfg(feature = "cli")]
pub mod drift;
pub mod error;
#[cfg(feature = "cli")]
mod fsutil;
pub mod headers;
#[cfg(feature = "cli")]
pub mod history;
mod http;
#[cfg(feature = "cli")]
pub mod logging;
pub mod lookup;
pub mod net;
#[cfg(feature = "cli")]
pub mod output;
pub mod posture;
mod psl;
pub mod rdap;
pub mod retry;
pub mod ssl;
pub mod status;
pub mod subdomains;
pub mod takeover;
pub mod tld;
mod tls;
pub mod validation;
#[cfg(feature = "cli")]
pub mod watchlist;
#[cfg(feature = "cli")]
pub mod webhook;
pub mod whois;

pub use availability::{AvailabilityChecker, AvailabilityResult};
pub use cache::TtlCache;
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
#[cfg(feature = "cli")]
pub use drift::{DriftReport, FieldChange};
pub use headers::{
    audit_headers, CookieFinding, Disclosure, HeaderFinding, HeaderReport, HeaderVerdict,
    DEFAULT_HEADER_TIMEOUT,
};
#[cfg(feature = "cli")]
pub use history::{HistoryEntry, LookupHistory};
#[cfg(feature = "cli")]
pub use output::{OutputFormat, OutputFormatter};
pub use posture::{
    lookup_email_posture, BimiPolicy, DanePolicy, DmarcPolicy, EmailPosture, MtaStsPolicy,
    PostureVerdict, SpfPolicy,
};
pub use ssl::{CertDetail, CertWarning, CertWarningSeverity, SslChecker, SslReport};
pub use subdomains::{
    classify_subdomains, ClassifiedSubdomain, SubdomainClassification, SubdomainEnumerator,
    SubdomainResult, SubdomainStatus,
};
#[cfg(feature = "cli")]
pub use subdomains::{SubdomainBaseline, SubdomainBaselineDiff, SubdomainBaselines};
pub use takeover::{scan_takeover, TakeoverFinding, TakeoverReport, TakeoverVerdict};
#[cfg(feature = "cli")]
pub use watchlist::{
    check_watchlist_with, check_watchlist_with_config, WatchReport, WatchResult, Watchlist,
};
