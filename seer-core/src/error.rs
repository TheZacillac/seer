use thiserror::Error;

#[derive(Error, Debug)]
pub enum SeerError {
    #[error("WHOIS lookup failed: {0}")]
    WhoisError(String),

    #[error("WHOIS server not found for TLD: {0}")]
    WhoisServerNotFound(String),

    #[error("WHOIS connection failed: {0}")]
    WhoisConnectionFailed(#[from] std::io::Error),

    #[error("RDAP lookup failed: {0}")]
    RdapError(String),

    #[error("RDAP bootstrap failed: {0}")]
    RdapBootstrapError(String),

    #[error("DNS resolution failed: {0}")]
    DnsError(String),

    #[error("DNS resolver error: {0}")]
    DnsResolverError(#[from] hickory_resolver::error::ResolveError),

    #[error("Invalid domain name: {0}")]
    InvalidDomain(String),

    #[error("Invalid IP address: {0}")]
    InvalidIpAddress(String),

    #[error("Invalid record type: {0}")]
    InvalidRecordType(String),

    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("JSON parsing failed: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Rate limited: {0}")]
    RateLimited(String),

    #[error("Bulk operation failed: {context}")]
    BulkOperationError {
        context: String,
        failures: Vec<(String, String)>,
    },

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, SeerError>;
