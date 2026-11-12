//! The one error type handlers return, and its HTTP form.
//!
//! Every failure leaves the server as `{"detail": "<text>"}` with
//! `Cache-Control: no-store`. A [`SeerError`] gets its status from
//! `ErrorCategory::http_status()` and its text from the root cause's
//! `sanitized_message()`; the full error goes to the log, never the client.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use seer_core::{contract, SeerError};

/// A failure a handler or middleware reports to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    status: StatusCode,
    detail: String,
    /// Seconds for the `Retry-After` header, when retrying will help.
    retry_after: Option<u64>,
}

impl ApiError {
    fn new(status: StatusCode, detail: impl Into<String>) -> Self {
        Self {
            status,
            detail: contract::clean_message(&detail.into()),
            retry_after: None,
        }
    }

    /// 400: the request's own input was rejected at the edge.
    pub fn invalid(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, detail)
    }

    /// 401: no key, a wrong key, or a route the caller's tier may not use.
    pub fn unauthorized(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, detail)
    }

    /// 404: no such route.
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "Not Found")
    }

    /// 405: the route exists but only answers `GET`.
    pub fn method_not_allowed() -> Self {
        Self::new(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed")
    }

    /// 429: this caller is over a route's rate limit. `retry_after` is how
    /// long until the limiter would admit another request.
    pub fn rate_limited(retry_after: std::time::Duration) -> Self {
        // Whole seconds, rounded up, and at least one: `Retry-After: 0`
        // invites an immediate retry that would be refused again.
        let seconds = retry_after.as_millis().div_ceil(1000).max(1);
        Self {
            retry_after: Some(u64::try_from(seconds).unwrap_or(u64::MAX)),
            ..Self::new(StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded")
        }
    }

    /// 503: every slot stayed busy until the request's deadline. Nothing
    /// was started, so retrying is safe.
    pub fn busy() -> Self {
        Self {
            retry_after: Some(1),
            ..Self::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "Server busy; retry shortly",
            )
        }
    }

    /// 504: the lookup did not finish before the request's deadline.
    pub fn timeout() -> Self {
        Self::new(StatusCode::GATEWAY_TIMEOUT, "Request timed out")
    }

    /// 500: a fault in the server itself. Carries no detail.
    pub fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
    }

    /// The HTTP status this error is answered with.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The text placed in the response's `detail` field.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl From<SeerError> for ApiError {
    fn from(error: SeerError) -> Self {
        let category = error.category();
        let status = StatusCode::from_u16(category.http_status())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        // The full error stays in the log; the client gets the sanitized
        // root cause.
        if status.is_server_error() {
            tracing::warn!(%error, ?category, status = status.as_u16(), "request failed");
        } else {
            tracing::info!(%error, ?category, status = status.as_u16(), "request rejected");
        }
        Self::new(status, error.root_cause().sanitized_message())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(serde_json::json!({ "detail": self.detail }));
        let mut response = (self.status, body).into_response();
        let headers = response.headers_mut();
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if self.status == StatusCode::UNAUTHORIZED {
            headers.insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        if let Some(seconds) = self.retry_after {
            headers.insert(header::RETRY_AFTER, HeaderValue::from(seconds));
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::reply;
    use axum::http::header;
    use axum::response::IntoResponse;
    use seer_core::ErrorCategory;

    #[test]
    fn a_core_error_takes_its_category_status_and_sanitized_text() {
        let error = ApiError::from(SeerError::Timeout("whois.internal:43 timed out".into()));
        assert_eq!(error.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(error.detail(), "Operation timed out");
    }

    #[test]
    fn a_retried_error_reports_its_root_cause() {
        let error = ApiError::from(SeerError::RetryExhausted {
            attempts: 3,
            last_error: Box::new(SeerError::RateLimited("registry said slow down".into())),
        });
        assert_eq!(error.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(error.detail(), "Rate limited - please try again later");
    }

    #[test]
    fn every_category_maps_to_cores_status() {
        let samples = [
            (
                SeerError::InvalidDomain("x".into()),
                ErrorCategory::InvalidInput,
            ),
            (SeerError::Timeout("x".into()), ErrorCategory::Timeout),
            (
                SeerError::WhoisConnectionFailed("x".into()),
                ErrorCategory::Connection,
            ),
            (
                SeerError::RateLimited("x".into()),
                ErrorCategory::RateLimited,
            ),
            (
                SeerError::WhoisServerNotFound("zz".into()),
                ErrorCategory::WhoisServerNotFound,
            ),
            (SeerError::DnsError("x".into()), ErrorCategory::Dns),
            (SeerError::RdapError("x".into()), ErrorCategory::Upstream),
            (SeerError::SslError("x".into()), ErrorCategory::Tls),
            (SeerError::ConfigError("x".into()), ErrorCategory::Config),
            (SeerError::Other("x".into()), ErrorCategory::Other),
        ];
        for (error, category) in samples {
            assert_eq!(
                ApiError::from(error).status().as_u16(),
                category.http_status()
            );
        }
    }

    #[test]
    fn own_errors_have_fixed_statuses() {
        assert_eq!(ApiError::invalid("bad").status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            ApiError::unauthorized("no").status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(ApiError::not_found().status(), StatusCode::NOT_FOUND);
        assert_eq!(ApiError::not_found().detail(), "Not Found");
        assert_eq!(
            ApiError::method_not_allowed().status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            ApiError::internal().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn detail_text_is_cleaned() {
        assert_eq!(ApiError::invalid("a\r\n\x1b[31mb").detail(), "a[31mb");
    }

    #[tokio::test]
    async fn the_response_is_a_detail_object_that_is_never_cached() {
        let reply = reply(ApiError::invalid("bad domain").into_response()).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert_eq!(reply.json, serde_json::json!({ "detail": "bad domain" }));
        assert_eq!(reply.headers[header::CACHE_CONTROL], "no-store");
        assert!(reply.headers.get(header::WWW_AUTHENTICATE).is_none());
    }

    #[tokio::test]
    async fn a_401_names_the_bearer_scheme() {
        let reply = reply(ApiError::unauthorized("API key required").into_response()).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.headers[header::WWW_AUTHENTICATE], "Bearer");
    }

    #[tokio::test]
    async fn a_rate_limit_refusal_says_when_to_retry() {
        // Rounded up to whole seconds, and never zero.
        for (wait, expected) in [(11_200, "12"), (60_000, "60"), (1, "1"), (0, "1")] {
            let error = ApiError::rate_limited(std::time::Duration::from_millis(wait));
            assert_eq!(error.status(), StatusCode::TOO_MANY_REQUESTS);
            let reply = reply(error.into_response()).await;
            assert_eq!(reply.headers[header::RETRY_AFTER], expected, "{wait} ms");
            assert_eq!(
                reply.json,
                serde_json::json!({ "detail": "Rate limit exceeded" })
            );
            assert_eq!(reply.headers[header::CACHE_CONTROL], "no-store");
        }
    }

    #[tokio::test]
    async fn busy_and_timeout_have_their_own_statuses() {
        let busy = reply(ApiError::busy().into_response()).await;
        assert_eq!(busy.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(busy.headers[header::RETRY_AFTER], "1");
        assert_eq!(
            busy.json,
            serde_json::json!({ "detail": "Server busy; retry shortly" })
        );

        let timeout = reply(ApiError::timeout().into_response()).await;
        assert_eq!(timeout.status, StatusCode::GATEWAY_TIMEOUT);
        assert!(timeout.headers.get(header::RETRY_AFTER).is_none());
        assert_eq!(
            timeout.json,
            serde_json::json!({ "detail": "Request timed out" })
        );
    }
}
