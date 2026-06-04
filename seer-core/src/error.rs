use thiserror::Error;

#[derive(Error, Debug)]
pub enum SeerError {
    #[error("WHOIS lookup failed: {0}")]
    WhoisError(String),

    #[error("WHOIS server not found for TLD: {0}")]
    WhoisServerNotFound(String),

    #[error("WHOIS connection failed: {0}")]
    WhoisConnectionFailed(String),

    #[error("RDAP lookup failed: {0}")]
    RdapError(String),

    #[error("RDAP bootstrap failed: {0}")]
    RdapBootstrapError(String),

    #[error("DNS resolution failed: {0}")]
    DnsError(String),

    #[error("DNS resolver error: {0}")]
    DnsResolverError(#[from] hickory_resolver::net::NetError),

    #[error("Invalid domain name: {0}")]
    InvalidDomain(String),

    #[error("Domain not allowed: TLD '{tld}' is not in the allowlist")]
    DomainNotAllowed { domain: String, tld: String },

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

    #[error("SSL error: {0}")]
    SslError(String),

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

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("{0}")]
    Other(String),

    #[error("Operation failed after {attempts} attempts: {last_error}")]
    RetryExhausted {
        attempts: usize,
        last_error: Box<SeerError>,
    },
}

impl SeerError {
    /// Returns a sanitized error message safe for external exposure
    /// (API responses, MCP tool results, Python exceptions).
    ///
    /// Transport/network variants collapse to their CATEGORY with no inner
    /// detail, so an upstream server hostname/URL, a resolver-config fragment,
    /// a filesystem path, or a raw system error can never reach an external
    /// consumer. Full detail is still available for internal logging via the
    /// `Display` impl (`to_string()`) — log that, return this. User-input
    /// echoes (invalid domain / IP / record type / not-allowed TLD / generic
    /// input validation) are kept because they are the caller's own input and
    /// are needed to act on the error.
    pub fn sanitized_message(&self) -> String {
        match self {
            SeerError::WhoisError(_) => "WHOIS lookup failed".to_string(),
            SeerError::WhoisServerNotFound(_) => "WHOIS server not found for this TLD".to_string(),
            SeerError::WhoisConnectionFailed(_) => "WHOIS connection failed".to_string(),
            SeerError::RdapError(_) => "RDAP lookup failed".to_string(),
            SeerError::RdapBootstrapError(_) => {
                "RDAP service unavailable for this resource".to_string()
            }
            SeerError::DnsError(_) => "DNS resolution failed".to_string(),
            SeerError::DnsResolverError(_) => "DNS resolution failed".to_string(),
            SeerError::InvalidDomain(domain) => format!("Invalid domain name: {}", domain),
            SeerError::DomainNotAllowed { tld, .. } => {
                format!("Domain not allowed: TLD '{}' is not in the allowlist", tld)
            }
            SeerError::InvalidIpAddress(ip) => format!("Invalid IP address: {}", ip),
            SeerError::InvalidRecordType(rt) => format!("Invalid record type: {}", rt),
            SeerError::HttpError(_) => "HTTP request failed".to_string(),
            SeerError::ReqwestError(_) => "HTTP request failed".to_string(),
            SeerError::JsonError(_) => "Response parsing failed".to_string(),
            SeerError::Timeout(_) => "Operation timed out".to_string(),
            SeerError::RateLimited(_) => "Rate limited - please try again later".to_string(),
            SeerError::CertificateError(_) => "Certificate validation failed".to_string(),
            SeerError::SslError(_) => "SSL inspection failed".to_string(),
            SeerError::BulkOperationError { context, .. } => {
                format!("Bulk operation partially failed: {}", context)
            }
            // Drop `details` (built from upstream RDAP/WHOIS error strings).
            SeerError::LookupFailed { domain, .. } => format!("Lookup failed for {}", domain),
            SeerError::ConfigError(_) => "Configuration error".to_string(),
            // InvalidInput carries user-facing validation messages; the one
            // sensitive case (an SSRF reserved-IP rejection) is already
            // IP-redacted by `sanitize_error_for_public` on the lookup path.
            SeerError::InvalidInput(msg) => format!("Invalid input: {}", msg),
            SeerError::Other(_) => "Operation failed".to_string(),
            SeerError::RetryExhausted {
                attempts,
                last_error,
            } => {
                format!(
                    "Operation failed after {} attempts: {}",
                    attempts,
                    last_error.sanitized_message()
                )
            }
        }
    }
}

pub type Result<T> = std::result::Result<T, SeerError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_errors_sanitized_to_category_only() {
        // Strict policy: the external projection must NOT carry the inner
        // detail of transport/network errors (upstream server hostnames, URLs,
        // resolver internals, raw system errors). Full detail remains available
        // for internal logging via Display (`to_string()`).
        let cases: &[(SeerError, &str, &str)] = &[
            (
                SeerError::HttpError("CT log query failed: 502 Bad Gateway".into()),
                "HTTP request failed",
                "502",
            ),
            (
                SeerError::Timeout("connection to whois.example.com timed out".into()),
                "Operation timed out",
                "whois.example.com",
            ),
            (
                SeerError::DnsError("invalid nameserver IP: 10.1.2.3".into()),
                "DNS resolution failed",
                "10.1.2.3",
            ),
            (
                SeerError::SslError("could not resolve internal.host for SSL: refused".into()),
                "SSL inspection failed",
                "internal.host",
            ),
            (
                SeerError::WhoisConnectionFailed("connect to whois.nic.internal:43 refused".into()),
                "WHOIS connection failed",
                "internal",
            ),
            (
                SeerError::ConfigError("/home/user/.seer/secret.toml unreadable".into()),
                "Configuration error",
                ".seer",
            ),
        ];
        for (err, category, leak) in cases {
            let msg = err.sanitized_message();
            assert!(
                msg.contains(category),
                "expected category {category}; got: {msg}"
            );
            assert!(
                !msg.contains(leak),
                "detail '{leak}' must NOT leak into sanitized message; got: {msg}"
            );
        }
    }

    #[test]
    fn user_input_echoes_are_kept() {
        // The caller's own input is safe and necessary to act on the error.
        assert!(SeerError::InvalidDomain("bad_domain".into())
            .sanitized_message()
            .contains("bad_domain"));
        assert!(SeerError::InvalidRecordType("ZZZ".into())
            .sanitized_message()
            .contains("ZZZ"));
    }
}
