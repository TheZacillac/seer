//! SSRF-guarded JSON webhook delivery (used by `seer watch --webhook`).
//!
//! Watch mode can notify an operator-supplied HTTP endpoint when a watched
//! domain changes state. That URL is user configuration, which makes this an
//! outbound-request primitive — so it gets the same SSRF envelope as every
//! other outbound leg of seer (RDAP, WHOIS, status):
//!
//! - Only `http`/`https` URLs with a host are accepted.
//! - The host resolves through [`crate::net::resolve_public_host`] — the
//!   single source of truth for reserved-range policy — and every resolved
//!   address must be public. Loopback, RFC1918, link-local (incl. the cloud
//!   metadata endpoint), CGNAT, NAT64/6to4 encodings, etc. are refused
//!   before any connect.
//! - The validated addresses are pinned on the HTTP client via
//!   `resolve_to_addrs`, closing the TOCTOU window between validation and
//!   connect (DNS-rebinding defense). Pinning is a builder-time decision that
//!   depends on the resolved addresses, which is why the reqwest client is
//!   built per delivery instead of stored on the struct.
//! - Redirects are disabled: a 3xx `Location` is a fresh, unvalidated URL, so
//!   following it would bypass the guard entirely (redirect-based SSRF). A
//!   redirecting webhook endpoint surfaces as a failed delivery instead.
//!
//! Deliveries are single-attempt and timeout-bounded; retry/backoff policy
//! belongs to the caller (watch mode), matching the `status` module's stance
//! on not masking flakiness. A non-2xx response surfaces as an error carrying
//! only the HTTP status — never the response body, which is untrusted remote
//! content and must not leak into logs or terminal output.

use std::time::Duration;

use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};

use crate::error::{Result, SeerError};

/// Default per-delivery timeout (connect + write + response headers).
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Connect-phase cap, kept no larger than the overall timeout so a sub-5s
/// configured timeout stays internally consistent (mirrors the RDAP client).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Outcome of a successful webhook delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookDelivery {
    /// HTTP status code returned by the endpoint (always 2xx on success).
    pub status: u16,
}

/// SSRF-guarded HTTP client that POSTs JSON payloads to a webhook URL.
///
/// See the module docs for the security posture (host validation, IP
/// pinning, redirects disabled).
#[derive(Debug, Clone)]
pub struct WebhookClient {
    /// Per-delivery timeout (default [`DEFAULT_TIMEOUT`]).
    timeout: Duration,
    /// When true, skips the reserved-IP SSRF validation so tests can target a
    /// 127.0.0.1 wiremock fixture. Not settable outside `#[cfg(test)]` builds
    /// — production deliveries always validate and pin resolved IPs.
    allow_private: bool,
}

impl Default for WebhookClient {
    fn default() -> Self {
        Self::new()
    }
}

impl WebhookClient {
    /// Creates a webhook client with default settings (10s timeout).
    pub fn new() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            allow_private: false,
        }
    }

    /// Builds a client honoring `~/.seer/config.toml` settings.
    ///
    /// Reads `timeouts.http_secs` (already clamped to 1–120s by
    /// [`crate::config::SeerConfig::load`]) — webhook delivery is an HTTP
    /// operation, so it shares the HTTP timeout knob. Sugar over
    /// [`WebhookClient::with_timeout`].
    pub fn from_config(config: &crate::config::SeerConfig) -> Self {
        Self::new().with_timeout(config.http_timeout())
    }

    /// Sets the per-delivery timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Test-only: allow deliveries to loopback/private addresses (mock servers).
    #[cfg(test)]
    pub(crate) fn allowing_private_hosts(mut self) -> Self {
        self.allow_private = true;
        self
    }

    /// POSTs `payload` as JSON to `url`.
    ///
    /// # Arguments
    /// * `url` - Webhook endpoint; must be `http`/`https` with a public host
    /// * `payload` - Any serializable value; sent as the JSON request body
    ///
    /// # Returns
    /// * `Ok(WebhookDelivery)` - the endpoint answered 2xx
    /// * `Err(SeerError::InvalidInput)` - bad URL shape or SSRF-blocked host
    /// * `Err(SeerError::JsonError)` - payload failed to serialize
    /// * `Err(SeerError::HttpError)` - endpoint answered non-2xx (the error
    ///   names the status; the response body is untrusted and never read)
    /// * `Err(SeerError::ReqwestError)` - transport failure (connect/timeout)
    pub async fn post_json<T: Serialize + ?Sized>(
        &self,
        url: &str,
        payload: &T,
    ) -> Result<WebhookDelivery> {
        let (host, port) = parse_webhook_url(url)?;

        // Serialize before any network work so a bad payload fails fast
        // (no DNS lookup, no connect) with a typed JsonError.
        let body = serde_json::to_vec(payload)?;

        let connect_timeout = CONNECT_TIMEOUT.min(self.timeout);
        let mut builder = Client::builder()
            .timeout(self.timeout)
            .connect_timeout(connect_timeout)
            .user_agent(concat!("Seer/", env!("CARGO_PKG_VERSION")))
            // SSRF defense: a redirect target is an unvalidated URL — never
            // follow it (see module docs). Applies to the test seam too, so
            // tests exercise the same no-redirect behavior as production.
            .redirect(reqwest::redirect::Policy::none());

        if !self.allow_private {
            // SSRF protection: refuse reserved/private hosts and pin the
            // validated addresses so reqwest cannot re-resolve the hostname
            // to a different (potentially private) address. If the host is
            // an IP literal the resolved vec already holds it, so
            // `resolve_to_addrs` is still correct.
            let resolved = crate::net::resolve_public_host(&host, port).await?;
            builder = builder.resolve_to_addrs(&host, &resolved);
        }

        let client = builder
            .build()
            .map_err(|e| SeerError::HttpError(format!("failed to build HTTP client: {}", e)))?;

        let response = client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            // Carry the status only — the response body is untrusted remote
            // content and is deliberately never read.
            return Err(SeerError::HttpError(format!(
                "webhook delivery failed: HTTP {}",
                status
            )));
        }

        Ok(WebhookDelivery {
            status: status.as_u16(),
        })
    }
}

/// Validates webhook URL shape (scheme + host presence) and extracts
/// `(host, port)` for the SSRF guard.
///
/// Uses `host()` (not `host_str()`) so an IPv6 literal comes back
/// unbracketed and hits the shared guard's IP-literal short-circuit —
/// same approach as the RDAP client's URL parsing.
fn parse_webhook_url(url: &str) -> Result<(String, u16)> {
    let parsed = Url::parse(url)
        .map_err(|e| SeerError::InvalidInput(format!("invalid webhook URL '{}': {}", url, e)))?;

    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(SeerError::InvalidInput(format!(
            "webhook URL must use http or https, got '{}'",
            scheme
        )));
    }

    let host = match parsed.host() {
        Some(url::Host::Domain(d)) => d.to_string(),
        Some(url::Host::Ipv4(ip)) => ip.to_string(),
        Some(url::Host::Ipv6(ip)) => ip.to_string(),
        None => {
            return Err(SeerError::InvalidInput(format!(
                "webhook URL '{}' has no host",
                url
            )))
        }
    };

    // `port_or_known_default` always answers for http/https; the fallback
    // arm is unreachable but keeps the expression total.
    let port = parsed
        .port_or_known_default()
        .unwrap_or(if scheme == "http" { 80 } else { 443 });

    Ok((host, port))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    //! Hermetic tests: wiremock serves scripted responses on 127.0.0.1,
    //! reached through the `#[cfg(test)]`-only `allowing_private_hosts`
    //! seam. The production-path tests need no network at all (IP-literal
    //! short-circuit / URL-shape rejection / pre-network serialization).

    use super::*;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[derive(Serialize)]
    struct Payload {
        domain: String,
        event: String,
    }

    /// A payload whose Serialize impl always fails, to exercise the
    /// fail-fast serialization path.
    struct Unserializable;

    impl Serialize for Unserializable {
        fn serialize<S: serde::Serializer>(
            &self,
            _serializer: S,
        ) -> std::result::Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("cannot serialize"))
        }
    }

    #[tokio::test]
    async fn delivers_json_payload_and_returns_status() {
        let server = MockServer::start().await;
        // The mock only matches when the exact JSON body AND the
        // application/json content type arrive; anything else 404s and the
        // unwrap below fails — so this asserts the payload round-trips.
        Mock::given(method("POST"))
            .and(path("/hook"))
            .and(header("content-type", "application/json"))
            .and(body_json(serde_json::json!({
                "domain": "example.com",
                "event": "expiry",
            })))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let client = WebhookClient::new().allowing_private_hosts();
        let payload = Payload {
            domain: "example.com".to_string(),
            event: "expiry".to_string(),
        };
        let delivery = client
            .post_json(&format!("{}/hook", server.uri()), &payload)
            .await
            .unwrap();
        assert_eq!(delivery.status, 200);
        server.verify().await;
    }

    #[tokio::test]
    async fn non_2xx_is_error_naming_status_not_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal-secret-detail"))
            .mount(&server)
            .await;

        let client = WebhookClient::new().allowing_private_hosts();
        let err = client
            .post_json(&format!("{}/hook", server.uri()), &serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, SeerError::HttpError(_)), "got {err:?}");
        let msg = err.to_string();
        assert!(msg.contains("500"), "error must name the status: {msg}");
        assert!(
            !msg.contains("internal-secret-detail"),
            "untrusted response body must not leak into the error: {msg}"
        );
    }

    #[tokio::test]
    async fn redirect_is_not_followed() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(
                ResponseTemplate::new(301)
                    .insert_header("location", format!("{}/elsewhere", server.uri()).as_str()),
            )
            .expect(1)
            .mount(&server)
            .await;
        // The redirect target must never be hit, by any method.
        Mock::given(path("/elsewhere"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        let client = WebhookClient::new().allowing_private_hosts();
        let err = client
            .post_json(&format!("{}/hook", server.uri()), &serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, SeerError::HttpError(_)), "got {err:?}");
        assert!(
            err.to_string().contains("301"),
            "error must carry the 3xx status: {err}"
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn production_client_refuses_loopback_url() {
        let server = MockServer::start().await;
        // No request may ever reach the server through the production path.
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        let client = WebhookClient::new(); // no seam: production validation
        let err = client
            .post_json(&format!("{}/hook", server.uri()), &serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, SeerError::InvalidInput(_)), "got {err:?}");
        server.verify().await;
    }

    #[tokio::test]
    async fn production_client_refuses_private_ip_literal() {
        // IP-literal short-circuit in the shared guard — no DNS involved.
        let client = WebhookClient::new();
        for url in [
            "http://10.0.0.1/hook",
            "https://169.254.169.254/latest/meta-data",
            "http://[::1]/hook",
        ] {
            let err = client
                .post_json(url, &serde_json::json!({}))
                .await
                .unwrap_err();
            assert!(
                matches!(err, SeerError::InvalidInput(_)),
                "{url} must be refused, got {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn rejects_non_http_scheme() {
        let client = WebhookClient::new();
        let err = client
            .post_json("ftp://example.com/hook", &serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, SeerError::InvalidInput(_)), "got {err:?}");
        assert!(
            err.to_string().contains("http"),
            "error should point at the scheme requirement: {err}"
        );
    }

    #[tokio::test]
    async fn rejects_hostless_url() {
        let client = WebhookClient::new();
        let err = client
            .post_json("http:///hook", &serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, SeerError::InvalidInput(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn serialization_failure_fails_fast_before_any_network() {
        // Production client + a routable-looking URL: the JsonError must
        // surface BEFORE DNS resolution/connect (serialization precedes the
        // SSRF resolve in post_json), keeping this test hermetic.
        let client = WebhookClient::new();
        let err = client
            .post_json("https://webhook.example.com/hook", &Unserializable)
            .await
            .unwrap_err();
        assert!(matches!(err, SeerError::JsonError(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn timeout_bounds_delivery() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
            .mount(&server)
            .await;

        let client = WebhookClient::new()
            .allowing_private_hosts()
            .with_timeout(Duration::from_millis(100));
        let err = client
            .post_json(&format!("{}/hook", server.uri()), &serde_json::json!({}))
            .await
            .unwrap_err();
        match err {
            SeerError::ReqwestError { transient, .. } => {
                assert!(transient, "timeouts must classify as transient");
            }
            other => panic!("expected ReqwestError from timeout, got {other:?}"),
        }
    }
}
