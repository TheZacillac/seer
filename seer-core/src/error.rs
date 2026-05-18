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
    /// Returns a sanitized error message safe for external exposure.
    /// This hides internal details like server hostnames and raw system errors.
    pub fn sanitized_message(&self) -> String {
        match self {
            // Detail is preserved across these variants for the same reasons
            // as the earlier SslError / DnsError / WhoisServerNotFound fixes:
            // Python callers and composite tools need to distinguish e.g. a
            // 502 from crt.sh, a connect-refused, a Reqwest URL parse error,
            // or a CT-log JSON deserialization failure — collapsing them all
            // to generic strings makes every transient blip look identical
            // and forces the caller to grep tracing logs. For a domain-
            // intelligence tool that hits public APIs, there is no internal
            // infrastructure detail worth hiding here; the underlying error
            // strings are constructed by us or by reqwest's Display, which
            // only reveals public URLs and standard transport errors.
            SeerError::WhoisError(detail) => format!("WHOIS lookup failed: {}", detail),
            SeerError::WhoisServerNotFound(detail) => {
                format!("WHOIS server not found for this TLD: {}", detail)
            }
            SeerError::WhoisConnectionFailed(detail) => {
                format!("WHOIS connection failed: {}", detail)
            }
            SeerError::RdapError(detail) => format!("RDAP lookup failed: {}", detail),
            SeerError::RdapBootstrapError(detail) => {
                format!("RDAP service unavailable for this resource: {}", detail)
            }
            SeerError::DnsError(detail) => format!("DNS resolution failed: {}", detail),
            SeerError::DnsResolverError(detail) => format!("DNS resolution failed: {}", detail),
            SeerError::InvalidDomain(domain) => format!("Invalid domain name: {}", domain),
            SeerError::DomainNotAllowed { tld, .. } => {
                format!("Domain not allowed: TLD '{}' is not in the allowlist", tld)
            }
            SeerError::InvalidIpAddress(ip) => format!("Invalid IP address: {}", ip),
            SeerError::InvalidRecordType(rt) => format!("Invalid record type: {}", rt),
            SeerError::HttpError(detail) => format!("HTTP request failed: {}", detail),
            SeerError::ReqwestError(detail) => format!("HTTP request failed: {}", detail),
            SeerError::JsonError(detail) => format!("Response parsing failed: {}", detail),
            SeerError::Timeout(detail) => format!("Operation timed out: {}", detail),
            SeerError::RateLimited(detail) => {
                format!("Rate limited - please try again later: {}", detail)
            }
            SeerError::CertificateError(detail) => {
                format!("Certificate validation failed: {}", detail)
            }
            SeerError::SslError(detail) => format!("SSL inspection failed: {}", detail),
            SeerError::BulkOperationError { context, .. } => {
                format!("Bulk operation partially failed: {}", context)
            }
            SeerError::LookupFailed {
                domain, details, ..
            } => {
                format!("Lookup failed for {}: {}", domain, details)
            }
            SeerError::ConfigError(msg) => format!("Configuration error: {}", msg),
            SeerError::InvalidInput(msg) => format!("Invalid input: {}", msg),
            SeerError::Other(detail) => format!("Operation failed: {}", detail),
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
    fn http_error_sanitized_includes_detail() {
        // Regression: HttpError used to collapse to the generic string
        // "HTTP request failed", which made every transient crt.sh blip,
        // every reqwest connect-refused, and every JSON deserialization
        // failure look identical from Python.
        let err = SeerError::HttpError("CT log query failed: 502 Bad Gateway".into());
        let msg = err.sanitized_message();
        assert!(
            msg.contains("HTTP request failed"),
            "expected category prefix; got: {msg}"
        );
        assert!(
            msg.contains("502 Bad Gateway"),
            "expected detail preserved; got: {msg}"
        );
    }

    #[test]
    fn timeout_sanitized_includes_detail() {
        // Timeout used to collapse to "Operation timed out" — useful as a
        // category but unactionable. With detail preserved, callers can
        // see WHICH operation timed out (whois, rdap, ssl probe, dig, etc.)
        // without grepping tracing logs.
        let err = SeerError::Timeout("connection to whois.example.com timed out".into());
        let msg = err.sanitized_message();
        assert!(msg.contains("Operation timed out"), "got: {msg}");
        assert!(msg.contains("whois.example.com"), "got: {msg}");
    }

    #[test]
    fn dns_error_sanitized_includes_detail() {
        // Regression: prior to this, DnsError(_) was collapsed to the
        // generic string "DNS resolution failed", swallowing the reason.
        // Callers — especially Python wrappers — need the detail to
        // distinguish "invalid nameserver", "record type not implemented",
        // "NXDOMAIN", "hostname did not resolve", and friends. Same fix
        // shape as the earlier SslError detail-preservation fix.
        let err = SeerError::DnsError("invalid nameserver IP: foo.example".into());
        let msg = err.sanitized_message();
        assert!(
            msg.contains("DNS resolution failed"),
            "expected category prefix; got: {msg}"
        );
        assert!(
            msg.contains("invalid nameserver IP"),
            "expected detail to be preserved; got: {msg}"
        );
    }

    #[test]
    fn ssl_error_sanitized_includes_detail() {
        // Regression: prior to this, SslError(_) was collapsed to the
        // generic string "SSL inspection failed", swallowing the reason
        // (DNS failure, handshake refused, no cert presented, etc.).
        // Callers — especially Python wrappers — need the detail to
        // distinguish "probe failed" from "certificate genuinely missing".
        let err = SeerError::SslError(
            "could not resolve example.com for SSL inspection: DNS resolution failed".into(),
        );
        let msg = err.sanitized_message();
        assert!(
            msg.contains("SSL inspection failed"),
            "expected category prefix; got: {msg}"
        );
        assert!(
            msg.contains("DNS resolution failed"),
            "expected detail to be preserved; got: {msg}"
        );
    }
}
