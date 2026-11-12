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
        /// the retry classifier ([`crate::retry::is_retryable`]).
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

/// What kind of failure a [`SeerError`] is, independent of its text.
///
/// The one classification every external surface shares: seer-py picks its
/// Python exception class from it, and the HTTP servers pick a status code
/// with [`ErrorCategory::http_status`]. Classify with
/// [`SeerError::category`]; never by matching message text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCategory {
    /// The caller's input was rejected (domain, IP, record type, allowlist).
    InvalidInput,
    /// An operation ran out of time.
    Timeout,
    /// A WHOIS server could not be connected to.
    Connection,
    /// An upstream registry or service throttled the request.
    RateLimited,
    /// No WHOIS server is known for the TLD; retrying will not help.
    WhoisServerNotFound,
    /// DNS resolution failed.
    Dns,
    /// A WHOIS, RDAP or HTTP upstream failed; may be transient.
    Upstream,
    /// Every lookup source failed for the domain.
    LookupFailed,
    /// An upstream response could not be parsed.
    Parse,
    /// Certificate or TLS inspection failed.
    Tls,
    /// Seer's own configuration is invalid.
    Config,
    /// Anything uncategorized.
    Other,
}

impl ErrorCategory {
    /// Every category. [`ErrorCategory::Other`] is last, so a consumer that
    /// walks this list with first-match-wins reaches the specific
    /// categories before the catch-all.
    pub const ALL: [ErrorCategory; 12] = [
        ErrorCategory::InvalidInput,
        ErrorCategory::Timeout,
        ErrorCategory::Connection,
        ErrorCategory::RateLimited,
        ErrorCategory::WhoisServerNotFound,
        ErrorCategory::Dns,
        ErrorCategory::Upstream,
        ErrorCategory::LookupFailed,
        ErrorCategory::Parse,
        ErrorCategory::Tls,
        ErrorCategory::Config,
        ErrorCategory::Other,
    ];

    /// The HTTP status an API answers this category with: invalid input
    /// 400, a throttled upstream 429, an unsupported TLD 404, upstream
    /// failures 502, timeouts 504, and 500 for a configuration or
    /// uncategorized failure.
    pub fn http_status(self) -> u16 {
        match self {
            ErrorCategory::InvalidInput => 400,
            ErrorCategory::Timeout => 504,
            ErrorCategory::RateLimited => 429,
            ErrorCategory::WhoisServerNotFound => 404,
            ErrorCategory::Connection
            | ErrorCategory::Dns
            | ErrorCategory::Upstream
            | ErrorCategory::LookupFailed
            | ErrorCategory::Parse
            | ErrorCategory::Tls => 502,
            ErrorCategory::Config | ErrorCategory::Other => 500,
        }
    }
}

impl SeerError {
    /// The error underneath any [`SeerError::RetryExhausted`] wrappers: the
    /// failure the retry framework gave up on. An unwrapped error is its
    /// own root cause.
    pub fn root_cause(&self) -> &SeerError {
        let mut error = self;
        while let SeerError::RetryExhausted { last_error, .. } = error {
            error = last_error.as_ref();
        }
        error
    }

    /// Classifies this error. A [`SeerError::RetryExhausted`] is classified
    /// by its [root cause](Self::root_cause), so a retried timeout is still
    /// a timeout.
    pub fn category(&self) -> ErrorCategory {
        // No wildcard arm: a new variant must be given a category here.
        match self.root_cause() {
            SeerError::InvalidInput(_)
            | SeerError::InvalidDomain(_)
            | SeerError::InvalidIpAddress(_)
            | SeerError::InvalidRecordType(_)
            | SeerError::DomainNotAllowed { .. } => ErrorCategory::InvalidInput,
            SeerError::Timeout(_) => ErrorCategory::Timeout,
            SeerError::WhoisConnectionFailed(_) => ErrorCategory::Connection,
            SeerError::RateLimited(_) => ErrorCategory::RateLimited,
            SeerError::WhoisServerNotFound(_) => ErrorCategory::WhoisServerNotFound,
            SeerError::DnsError(_) | SeerError::DnsResolverError(_) => ErrorCategory::Dns,
            SeerError::WhoisError(_)
            | SeerError::RdapError(_)
            | SeerError::RdapBootstrapError(_)
            | SeerError::HttpError(_)
            | SeerError::ReqwestError { .. } => ErrorCategory::Upstream,
            SeerError::LookupFailed { .. } => ErrorCategory::LookupFailed,
            SeerError::JsonError(_) => ErrorCategory::Parse,
            SeerError::CertificateError(_) | SeerError::SslError(_) => ErrorCategory::Tls,
            SeerError::ConfigError(_) => ErrorCategory::Config,
            // `root_cause` never returns a RetryExhausted; the arm exists
            // only because the match is exhaustive.
            SeerError::Other(_) | SeerError::RetryExhausted { .. } => ErrorCategory::Other,
        }
    }

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

    // ---- classification ----

    /// One sample of every `SeerError` variant except `RetryExhausted`,
    /// paired with the category it must report.
    fn samples() -> Vec<(SeerError, ErrorCategory)> {
        use ErrorCategory as C;
        let json = serde_json::from_str::<u8>("x").unwrap_err();
        vec![
            (SeerError::InvalidInput("x".into()), C::InvalidInput),
            (SeerError::InvalidDomain("x".into()), C::InvalidInput),
            (SeerError::InvalidIpAddress("x".into()), C::InvalidInput),
            (SeerError::InvalidRecordType("x".into()), C::InvalidInput),
            (
                SeerError::DomainNotAllowed {
                    domain: "a.zz".into(),
                    tld: "zz".into(),
                },
                C::InvalidInput,
            ),
            (SeerError::Timeout("x".into()), C::Timeout),
            (SeerError::WhoisConnectionFailed("x".into()), C::Connection),
            (SeerError::RateLimited("x".into()), C::RateLimited),
            (
                SeerError::WhoisServerNotFound("zz".into()),
                C::WhoisServerNotFound,
            ),
            (SeerError::DnsError("x".into()), C::Dns),
            (SeerError::DnsResolverError("x".into()), C::Dns),
            (SeerError::WhoisError("x".into()), C::Upstream),
            (SeerError::RdapError("x".into()), C::Upstream),
            (SeerError::RdapBootstrapError("x".into()), C::Upstream),
            (SeerError::HttpError("x".into()), C::Upstream),
            (
                SeerError::ReqwestError {
                    message: "x".into(),
                    transient: true,
                },
                C::Upstream,
            ),
            (
                SeerError::LookupFailed {
                    domain: "example.com".into(),
                    details: "x".into(),
                    registry_url: "https://registry.test".into(),
                },
                C::LookupFailed,
            ),
            (SeerError::JsonError(json), C::Parse),
            (SeerError::CertificateError("x".into()), C::Tls),
            (SeerError::SslError("x".into()), C::Tls),
            (SeerError::ConfigError("x".into()), C::Config),
            (SeerError::Other("x".into()), C::Other),
        ]
    }

    #[test]
    fn every_variant_reports_its_category() {
        for (err, expected) in samples() {
            assert_eq!(err.category(), expected, "wrong category for {err:?}");
        }
    }

    #[test]
    fn retry_wrappers_classify_and_report_by_leaf() {
        let layered = SeerError::RetryExhausted {
            attempts: 3,
            last_error: Box::new(SeerError::RetryExhausted {
                attempts: 2,
                last_error: Box::new(SeerError::Timeout("whois.internal timed out".into())),
            }),
        };
        assert_eq!(layered.category(), ErrorCategory::Timeout);
        assert_eq!(
            layered.root_cause().sanitized_message(),
            "Operation timed out"
        );
        // An unwrapped error is its own root cause.
        let plain = SeerError::DnsError("x".into());
        assert!(matches!(plain.root_cause(), SeerError::DnsError(_)));
    }

    #[test]
    fn http_statuses_match_the_published_table() {
        use ErrorCategory as C;
        let table = [
            (C::InvalidInput, 400),
            (C::Timeout, 504),
            (C::Connection, 502),
            (C::RateLimited, 429),
            (C::WhoisServerNotFound, 404),
            (C::Dns, 502),
            (C::Upstream, 502),
            (C::LookupFailed, 502),
            (C::Parse, 502),
            (C::Tls, 502),
            (C::Config, 500),
            (C::Other, 500),
        ];
        for (category, status) in table {
            assert_eq!(category.http_status(), status, "{category:?}");
        }
    }

    #[test]
    fn all_lists_every_category_once_with_other_last() {
        let all = ErrorCategory::ALL;
        let unique: std::collections::HashSet<_> = all.iter().collect();
        assert_eq!(unique.len(), all.len(), "duplicate in ALL");
        for (_, category) in samples() {
            assert!(all.contains(&category), "{category:?} missing from ALL");
        }
        // Consumers that walk ALL with first-match-wins (seer-py's exception
        // table) need the catch-all last.
        assert_eq!(all.last(), Some(&ErrorCategory::Other));
    }
}
