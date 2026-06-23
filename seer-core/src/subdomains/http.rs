//! Shared HTTP fetch + retry logic for Certificate Transparency sources.
//!
//! CT-log aggregators (crt.sh in particular) are operationally flaky: under
//! load they return a grab-bag of transient failures — 502/503/504, but also
//! **404** and **429**, and sometimes a `200` carrying an nginx/Cloudflare HTML
//! error page instead of JSON. The standard REST convention ("5xx transient,
//! 4xx your fault") does not hold here, so [`classify_status`] is deliberately
//! tuned to crt.sh's reality: 404 and 429 are treated as retryable.

use std::time::Duration;

use futures::StreamExt;
use once_cell::sync::Lazy;
use reqwest::StatusCode;
use tracing::debug;

use crate::error::{Result, SeerError};

/// Default timeout for a single CT-log request (connect + full streaming read).
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Retry budget. CT aggregators are down often enough that a thin 3-attempt
/// budget exhausts before a bad spell clears; 4 attempts with capped
/// exponential backoff rides over most transient failures before the caller
/// falls through to the next source.
const MAX_ATTEMPTS: u32 = 4;
const RETRY_BASE_BACKOFF: Duration = Duration::from_millis(500);
const MAX_BACKOFF: Duration = Duration::from_secs(8);

/// Upper bound on how long we'll honor a server's `Retry-After` before giving
/// up on that source — a hostile or broken server can't park us indefinitely.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(30);

/// Maximum response size for CT log queries (10 MB).
const MAX_CT_RESPONSE_SIZE: usize = 10 * 1024 * 1024;

/// Shared HTTP client for CT log queries (connection pooling).
///
/// Redirects are disabled: a compromised or hijacked CT aggregator could
/// otherwise issue a 30x response that reqwest would follow by default, turning
/// the hardcoded CT-log fetch into an SSRF primitive. With `Policy::none()` any
/// redirect surfaces as a non-success status instead of a silent re-target.
///
/// Wrapped in `Option` so a reqwest builder failure surfaces as a typed
/// `SeerError::HttpError` via `client()` instead of a process panic at first
/// use (library code must not `.expect()` on shared state).
static HTTP_CLIENT: Lazy<Option<reqwest::Client>> = Lazy::new(|| {
    reqwest::Client::builder()
        .timeout(DEFAULT_TIMEOUT)
        .user_agent("seer-domain-tool")
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .ok()
});

/// Returns a reference to the shared CT-log HTTP client, or a typed error if
/// the builder failed at initialization time.
fn client() -> Result<&'static reqwest::Client> {
    HTTP_CLIENT
        .as_ref()
        .ok_or_else(|| SeerError::HttpError("failed to initialize HTTP client".into()))
}

/// How a CT-log HTTP status should be treated by the retry loop.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum StatusClass {
    /// 2xx — use the body.
    Ok,
    /// Transient for CT aggregators — retry (incl. 404, 429, and all 5xx).
    Retry,
    /// A genuine client error (400/403/...) — retrying won't help.
    Terminal,
}

/// Classify a CT-log HTTP status. Unlike a generic REST client, **404 and 429
/// are retryable** here: crt.sh serves both as transient infrastructure
/// hiccups (overloaded backend / rate limiting), not as "this domain has no
/// data" — an empty result set comes back as `200` with an empty JSON array.
pub(crate) fn classify_status(status: StatusCode) -> StatusClass {
    if status.is_success() {
        StatusClass::Ok
    } else if status.is_server_error()
        || status == StatusCode::NOT_FOUND
        || status == StatusCode::TOO_MANY_REQUESTS
    {
        StatusClass::Retry
    } else {
        StatusClass::Terminal
    }
}

/// True if `body` plausibly contains a JSON document (first non-whitespace byte
/// is `[` or `{`). crt.sh sometimes answers `200` with an HTML error page; that
/// body should be retried, not handed to the JSON parser as a terminal failure.
pub(crate) fn looks_like_json(body: &[u8]) -> bool {
    matches!(
        body.iter().find(|b| !b.is_ascii_whitespace()),
        Some(b'[') | Some(b'{')
    )
}

/// Parse a `Retry-After` header value containing delay-seconds. HTTP-date form
/// is not supported (CT aggregators use delta-seconds); capped at
/// `MAX_RETRY_AFTER`.
fn parse_retry_after(value: &str) -> Option<Duration> {
    let secs: u64 = value.trim().parse().ok()?;
    Some(Duration::from_secs(secs).min(MAX_RETRY_AFTER))
}

enum FetchOutcome {
    Retryable {
        err: SeerError,
        retry_after: Option<Duration>,
    },
    Terminal(SeerError),
}

/// Fetch `url`, retrying up to `MAX_ATTEMPTS` times on transient failures.
/// Honors a server-supplied `Retry-After` in preference to exponential backoff.
pub(crate) async fn fetch_with_retry(url: &str) -> Result<Vec<u8>> {
    let mut last_err: Option<SeerError> = None;
    for attempt in 0..MAX_ATTEMPTS {
        match fetch_once(url).await {
            Ok(body) => return Ok(body),
            Err(FetchOutcome::Terminal(e)) => return Err(e),
            Err(FetchOutcome::Retryable { err, retry_after }) => {
                debug!(
                    attempt = attempt + 1,
                    max_attempts = MAX_ATTEMPTS,
                    error = %err,
                    "Transient CT log failure, retrying"
                );
                last_err = Some(err);
                if attempt + 1 < MAX_ATTEMPTS {
                    let backoff = retry_after.unwrap_or_else(|| {
                        (RETRY_BASE_BACKOFF * 2u32.pow(attempt)).min(MAX_BACKOFF)
                    });
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        SeerError::HttpError("CT log query failed with no recorded error".into())
    }))
}

/// Single-attempt fetch. Splits failures into retryable vs terminal so
/// `fetch_with_retry` can decide whether another attempt is worth making.
async fn fetch_once(url: &str) -> std::result::Result<Vec<u8>, FetchOutcome> {
    let response = client()
        .map_err(FetchOutcome::Terminal)?
        .get(url)
        .send()
        .await
        .map_err(|e| FetchOutcome::Retryable {
            err: SeerError::HttpError(format!("CT log query failed: {}", e)),
            retry_after: None,
        })?;

    let status = response.status();
    match classify_status(status) {
        StatusClass::Ok => {}
        class => {
            let err = SeerError::HttpError(format!("CT log returned status {}", status));
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(parse_retry_after);
            return Err(if class == StatusClass::Retry {
                FetchOutcome::Retryable { err, retry_after }
            } else {
                FetchOutcome::Terminal(err)
            });
        }
    }

    if let Some(content_length) = response.content_length() {
        if content_length as usize > MAX_CT_RESPONSE_SIZE {
            return Err(FetchOutcome::Terminal(SeerError::HttpError(format!(
                "CT log response too large: {} bytes (limit: {} bytes)",
                content_length, MAX_CT_RESPONSE_SIZE
            ))));
        }
    }

    // Stream the body with an incremental size check so a server that omits
    // (or lies about) Content-Length cannot force us to buffer an unbounded
    // payload. Wrapped in a total-duration timeout so a server that trickles
    // bytes forever cannot hang the caller.
    let mut body: Vec<u8> = Vec::new();
    let mut stream = response.bytes_stream();
    let streamed = tokio::time::timeout(DEFAULT_TIMEOUT, async {
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| FetchOutcome::Retryable {
                err: SeerError::HttpError(format!("Failed to read CT log response: {}", e)),
                retry_after: None,
            })?;
            if body.len() + chunk.len() > MAX_CT_RESPONSE_SIZE {
                return Err(FetchOutcome::Terminal(SeerError::HttpError(format!(
                    "CT log response too large (exceeds {} bytes)",
                    MAX_CT_RESPONSE_SIZE
                ))));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    })
    .await;

    let body = match streamed {
        Ok(Ok(body)) => body,
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(FetchOutcome::Retryable {
                err: SeerError::Timeout(format!(
                    "CT log body read timed out after {:?}",
                    DEFAULT_TIMEOUT
                )),
                retry_after: None,
            })
        }
    };

    // A 200 carrying an HTML error page (crt.sh does this under load) is a
    // transient failure, not valid-but-unparseable data — retry rather than
    // surfacing a terminal parse error.
    if !looks_like_json(&body) {
        return Err(FetchOutcome::Retryable {
            err: SeerError::HttpError(
                "CT log returned a non-JSON body (likely a transient error page)".into(),
            ),
            retry_after: None,
        });
    }

    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_404_and_429_are_retryable() {
        // The core of the bug: crt.sh's 404/429 are transient, not terminal.
        assert_eq!(classify_status(StatusCode::NOT_FOUND), StatusClass::Retry);
        assert_eq!(
            classify_status(StatusCode::TOO_MANY_REQUESTS),
            StatusClass::Retry
        );
    }

    #[test]
    fn server_errors_are_retryable() {
        assert_eq!(classify_status(StatusCode::BAD_GATEWAY), StatusClass::Retry);
        assert_eq!(
            classify_status(StatusCode::SERVICE_UNAVAILABLE),
            StatusClass::Retry
        );
        assert_eq!(
            classify_status(StatusCode::GATEWAY_TIMEOUT),
            StatusClass::Retry
        );
    }

    #[test]
    fn genuine_client_errors_are_terminal() {
        assert_eq!(
            classify_status(StatusCode::BAD_REQUEST),
            StatusClass::Terminal
        );
        assert_eq!(
            classify_status(StatusCode::FORBIDDEN),
            StatusClass::Terminal
        );
    }

    #[test]
    fn success_is_ok() {
        assert_eq!(classify_status(StatusCode::OK), StatusClass::Ok);
    }

    #[test]
    fn looks_like_json_accepts_arrays_and_objects() {
        assert!(looks_like_json(b"[{\"a\":1}]"));
        assert!(looks_like_json(b"  \n\t {\"a\":1}"));
    }

    #[test]
    fn looks_like_json_rejects_html_error_pages() {
        assert!(!looks_like_json(
            b"<html><body>502 Bad Gateway</body></html>"
        ));
        assert!(!looks_like_json(b""));
    }

    #[test]
    fn retry_after_parses_seconds_and_caps() {
        assert_eq!(parse_retry_after("0"), Some(Duration::ZERO));
        assert_eq!(parse_retry_after(" 5 "), Some(Duration::from_secs(5)));
        assert_eq!(parse_retry_after("not-a-number"), None);
        // Capped at MAX_RETRY_AFTER.
        assert_eq!(parse_retry_after("99999"), Some(MAX_RETRY_AFTER));
    }
}
