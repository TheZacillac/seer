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
    HttpError(String),

    #[error("Reqwest error: {0}")]
    ReqwestError(#[from] reqwest::Error),

    #[error("JSON parsing failed: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Rate limited: {0}")]
    RateLimited(String),

    #[error("Certificate error: {0}")]
    CertificateError(String),

    #[error("Bulk operation failed: {context}")]
    BulkOperationError {
        context: String,
        failures: Vec<(String, String)>,
    },

    #[error("Lookup failed for {domain}: {details}\n\nTip: Try checking the registry directly at: {registry_url}")]
    LookupFailed {
        domain: String,
        details: String,
        registry_url: String,
    },

    #[error("{0}")]
    Other(String),

    #[error("Operation failed after {attempts} attempts: {last_error}")]
    RetryExhausted { attempts: usize, last_error: String },
}

impl SeerError {
    /// Returns a sanitized error message safe for external exposure.
    /// This hides internal details like server hostnames and raw system errors.
    pub fn sanitized_message(&self) -> String {
        match self {
            SeerError::WhoisError(_) => "WHOIS lookup failed".to_string(),
            SeerError::WhoisServerNotFound(_) => "WHOIS server not found for this TLD".to_string(),
            SeerError::WhoisConnectionFailed(_) => "WHOIS connection failed".to_string(),
            SeerError::RdapError(_) => "RDAP lookup failed".to_string(),
            SeerError::RdapBootstrapError(_) => "RDAP service unavailable for this resource".to_string(),
            SeerError::DnsError(_) => "DNS resolution failed".to_string(),
            SeerError::DnsResolverError(_) => "DNS resolution failed".to_string(),
            SeerError::InvalidDomain(domain) => format!("Invalid domain name: {}", domain),
            SeerError::InvalidIpAddress(ip) => format!("Invalid IP address: {}", ip),
            SeerError::InvalidRecordType(rt) => format!("Invalid record type: {}", rt),
            SeerError::HttpError(_) => "HTTP request failed".to_string(),
            SeerError::ReqwestError(_) => "HTTP request failed".to_string(),
            SeerError::JsonError(_) => "Response parsing failed".to_string(),
            SeerError::Timeout(_) => "Operation timed out".to_string(),
            SeerError::RateLimited(_) => "Rate limited - please try again later".to_string(),
            SeerError::CertificateError(_) => "Certificate validation failed".to_string(),
            SeerError::BulkOperationError { .. } => "Bulk operation partially failed".to_string(),
            SeerError::LookupFailed { domain, .. } => format!("Lookup failed for {}", domain),
            SeerError::Other(_) => "Operation failed".to_string(),
            SeerError::RetryExhausted { attempts, .. } => {
                format!("Operation failed after {} attempts", attempts)
            }
        }
    }
}

pub type Result<T> = std::result::Result<T, SeerError>;
