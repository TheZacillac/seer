use thiserror::Error;

/// Central error type for all seer-core operations.
///
/// Marked `#[non_exhaustive]` so adding a variant is not a semver break for
/// downstream consumers (matches need a wildcard arm). Third-party error
/// types (reqwest, hickory) are converted to owned data at the `From`
/// boundary instead of being embedded, so a major bump of those dependencies
/// no longer changes this public API.
#[derive(Error, Debug)]
#[non_exhaustive]
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

    /// Low-level resolver transport failure, captured as text at the
    /// `From<hickory_resolver::net::NetError>` boundary.
    #[error("DNS resolver error: {0}")]
    DnsResolverError(String),

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

    /// Transport-level HTTP failure, captured as owned data at the
    /// `From<reqwest::Error>` boundary.
    #[error("Reqwest error: {message}")]
    ReqwestError {
        /// Upstream error text (reqwest's `Display`), kept for logging.
        message: String,
        /// Whether the failure is transient (connect / timeout / 429 / 5xx),
        /// classified once while the typed error is still available. Read by
        /// the retry classifier ([`crate::retry::NetworkRetryClassifier`]).
        transient: bool,
    },

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

/// Classifies a reqwest error as transient (worth retrying): connect
/// failures, timeouts, HTTP 429 and 5xx. Other status codes and request/body
/// construction errors are permanent; unknown kinds default to transient.
///
/// Runs at the `From<reqwest::Error>` boundary — the only place the typed
/// error is still available — so the enum can store an owned flag instead of
/// the reqwest type.
fn is_transient_reqwest_error(error: &reqwest::Error) -> bool {
    // Connection errors are transient
    if error.is_connect() {
        return true;
    }

    // Timeout errors are transient
    if error.is_timeout() {
        return true;
    }

    // Check HTTP status codes
    if let Some(status) = error.status() {
        // 429 Too Many Requests - rate limited, retry with backoff
        if status.as_u16() == 429 {
            return true;
        }
        // 5xx Server errors are transient
        if status.is_server_error() {
            return true;
        }
        // 4xx Client errors (except 429) are not retryable
        return false;
    }

    // Request/body errors are generally not retryable
    if error.is_request() || error.is_body() {
        return false;
    }

    // Default: assume transient for unknown errors
    true
}

impl From<reqwest::Error> for SeerError {
    fn from(e: reqwest::Error) -> Self {
        SeerError::ReqwestError {
            message: e.to_string(),
            transient: is_transient_reqwest_error(&e),
        }
    }
}

impl From<hickory_resolver::net::NetError> for SeerError {
    fn from(e: hickory_resolver::net::NetError) -> Self {
        SeerError::DnsResolverError(e.to_string())
    }
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
            SeerError::ReqwestError { .. } => "HTTP request failed".to_string(),
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

    // ---- boundary conversion (owned payloads, classify-at-conversion) ----

    #[tokio::test]
    async fn reqwest_status_errors_classified_at_conversion() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let cases: &[(u16, bool)] = &[
            (429, true), // rate limited: retry with backoff
            (500, true), // 5xx: transient server errors
            (503, true),
            (400, false), // other 4xx: permanent
            (404, false),
        ];
        for (status, _) in cases {
            Mock::given(method("GET"))
                .and(path(format!("/s{status}")))
                .respond_with(ResponseTemplate::new(*status))
                .mount(&server)
                .await;
        }

        let client = reqwest::Client::new();
        for (status, expect_transient) in cases {
            let reqwest_err = client
                .get(format!("{}/s{}", server.uri(), status))
                .send()
                .await
                .expect("mock server is reachable")
                .error_for_status()
                .expect_err("status is an error");
            match SeerError::from(reqwest_err) {
                SeerError::ReqwestError { message, transient } => {
                    assert_eq!(
                        transient, *expect_transient,
                        "status {status} transiency misclassified"
                    );
                    // Status-code detail must survive into the owned message.
                    assert!(
                        message.contains(&status.to_string()),
                        "status {status} missing from message: {message}"
                    );
                }
                other => panic!("expected ReqwestError, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn reqwest_connect_error_classified_transient_at_conversion() {
        // Bind-and-drop to obtain a loopback port with no listener; the
        // connect is refused locally, no external network involved.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let port = listener.local_addr().expect("local addr").port();
        drop(listener);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("client builds");
        let reqwest_err = client
            .get(format!("http://127.0.0.1:{port}/"))
            .send()
            .await
            .expect_err("connect must fail");
        match SeerError::from(reqwest_err) {
            SeerError::ReqwestError { transient, .. } => {
                assert!(transient, "connect failures must classify as transient");
            }
            other => panic!("expected ReqwestError, got {other:?}"),
        }
    }

    #[test]
    fn dns_resolver_error_converts_to_owned_message() {
        // The hickory type is dropped at the boundary; its detail survives
        // as text and the Display output is unchanged from the #[from] era.
        let err: SeerError = hickory_resolver::net::NetError::Timeout.into();
        match &err {
            SeerError::DnsResolverError(msg) => {
                assert!(msg.contains("timed out"), "detail must survive: {msg}");
            }
            other => panic!("expected DnsResolverError, got {other:?}"),
        }
        assert_eq!(err.to_string(), "DNS resolver error: request timed out");
    }
}
