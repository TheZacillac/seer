//! SSRF-guarded HTTP GET with manual redirect following.
//!
//! seer's HTTP probes share this fetch: the header audit ([`crate::headers`])
//! grades the response headers, takeover detection ([`crate::takeover`])
//! matches the response body against provider fingerprints, and
//! [`crate::status`] reports the status code and page title. All fetch a host
//! derived from user input, which makes this an outbound-request primitive and
//! puts it under the same envelope as every other outbound leg of seer:
//!
//! - Redirects are followed **manually**, one hop at a time, and every hop is
//!   re-validated through [`crate::net::validate_http_url`]. reqwest's built-in
//!   redirect policy would follow a `Location` without re-running the guard,
//!   which is the classic redirect-based SSRF bypass. The hop count is capped
//!   and already-visited URLs abort the chain as a loop.
//! - The validated addresses are pinned per hop via `resolve_to_addrs`, closing
//!   the TOCTOU window between validation and connect (DNS-rebinding defense).
//!   Pinning depends on the resolved addresses, so the client is built per hop.
//! - The body is read from a stream with an incremental cap, so a server that
//!   omits or lies about `Content-Length` cannot force an unbounded buffer, and
//!   the read is wrapped in a total-duration timeout so a server that trickles
//!   bytes forever cannot hang the caller.
//! - TLS verification is left at reqwest's validating default. Unlike
//!   [`crate::ssl`], which relaxes verification *because* inspecting a bad
//!   certificate is its purpose, these probes draw security conclusions from
//!   the response and must not accept a MITM's version of it.
//!
//! Fetches are single-attempt: like [`crate::status`], these are point-in-time
//! observations and a retry would mask exactly the flakiness a probe exists to
//! surface. Response bodies and header values are untrusted remote content —
//! callers must sanitize before display (the output formatters do).

use std::collections::HashSet;
use std::time::Duration;

use futures::StreamExt;
use reqwest::Url;

use crate::error::{Result, SeerError};

/// Default per-hop timeout (connect + response headers + body read).
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum redirect hops followed before giving up.
const MAX_REDIRECTS: usize = 5;

/// Default cap on the response body retained for inspection. Provider
/// fingerprints and `<title>`-style markers all live in the first few KB;
/// 64 KB is generous while keeping a hostile server from ballooning memory
/// across a concurrent scan.
const DEFAULT_MAX_BODY: usize = 64 * 1024;

/// A fetched HTTP response, reduced to what the security probes need.
#[derive(Debug, Clone)]
pub(crate) struct FetchedResponse {
    /// The URL that finally answered (after any redirects).
    pub final_url: String,
    pub status: u16,
    /// Response headers with **lowercased** names, in wire order. A `Vec`
    /// rather than a map because `set-cookie` legitimately repeats and each
    /// occurrence must be graded separately.
    pub headers: Vec<(String, String)>,
    /// Body, lossily decoded as UTF-8 and truncated to the configured cap.
    pub body: String,
    /// Number of redirect hops followed to reach `final_url`.
    pub redirects: usize,
}

impl FetchedResponse {
    /// First value for `name` (which must be lowercase), or `None`.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Every value for `name` (which must be lowercase), in wire order.
    pub fn header_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.headers
            .iter()
            .filter(move |(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// SSRF-guarded HTTP GET client. See the module docs for the security posture.
#[derive(Debug, Clone)]
pub(crate) struct GuardedFetcher {
    timeout: Duration,
    max_body: usize,
    /// When true, skips SSRF validation/pinning so tests can target a
    /// 127.0.0.1 wiremock fixture. Not settable outside `#[cfg(test)]` builds
    /// — production fetches always validate and pin every hop.
    allow_private: bool,
}

impl GuardedFetcher {
    pub fn new() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            max_body: DEFAULT_MAX_BODY,
            allow_private: false,
        }
    }

    /// Sets the per-hop timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the cap on the retained response body.
    pub fn with_max_body(mut self, max_body: usize) -> Self {
        self.max_body = max_body;
        self
    }

    /// Test-only: allow fetches against loopback/private addresses.
    #[cfg(test)]
    pub fn allowing_private_hosts(mut self) -> Self {
        self.allow_private = true;
        self
    }

    /// GETs `url`, following up to [`MAX_REDIRECTS`] hops with the guard
    /// re-applied at each one, and reads the final body under the cap.
    ///
    /// # Errors
    /// * [`SeerError::HttpError`] — bad URL shape, SSRF-blocked host, redirect
    ///   loop, too many hops, or a transport failure.
    pub async fn get(&self, url: &str) -> Result<FetchedResponse> {
        let (response, redirects) = self.send(url).await?;
        let status = response.status().as_u16();
        let final_url = response.url().to_string();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_ascii_lowercase(),
                    // A header value that isn't valid UTF-8 is still worth
                    // reporting as present; lossy-decode rather than drop.
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        let body = self.read_body(response).await?;

        Ok(FetchedResponse {
            final_url,
            status,
            headers,
            body,
            redirects,
        })
    }

    /// The guarded request half of [`GuardedFetcher::get`]: returns the final
    /// (non-redirect) response with its body still unread, plus the number of
    /// hops followed. For callers that want the body only for some responses —
    /// read it through [`GuardedFetcher::read_body`] so the cap still applies.
    pub async fn send(&self, url: &str) -> Result<(reqwest::Response, usize)> {
        let mut url = Url::parse(url)
            .map_err(|e| SeerError::HttpError(format!("invalid URL '{}': {}", url, e)))?;
        let mut visited: HashSet<String> = HashSet::new();

        for hop in 0..=MAX_REDIRECTS {
            if !visited.insert(url.as_str().to_string()) {
                return Err(SeerError::HttpError("redirect loop detected".to_string()));
            }

            // No auto-redirects (see the module docs): each hop is re-guarded.
            let mut builder =
                crate::net::client_builder(self.timeout).user_agent(crate::net::USER_AGENT);

            if !self.allow_private {
                let addrs = crate::net::validate_http_url(&url).await?;
                let host = url
                    .host_str()
                    .ok_or_else(|| SeerError::HttpError("missing URL host".to_string()))?;
                builder = builder.resolve_to_addrs(host, &addrs);
            }

            let client = builder
                .build()
                .map_err(|e| SeerError::HttpError(format!("failed to build HTTP client: {}", e)))?;

            let response = client
                .get(url.clone())
                .send()
                .await
                .map_err(|e| SeerError::HttpError(e.to_string()))?;

            if response.status().is_redirection() {
                let location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| {
                        SeerError::HttpError("redirect missing location header".to_string())
                    })?;
                // Resolve relative Locations against the current URL; fall back
                // to an absolute parse. The result is re-validated at the top
                // of the next iteration before any connect.
                url = url
                    .join(location)
                    .or_else(|_| Url::parse(location))
                    .map_err(|e| SeerError::HttpError(format!("invalid redirect URL: {}", e)))?;
                continue;
            }

            return Ok((response, hop));
        }

        Err(SeerError::HttpError("too many redirects".to_string()))
    }

    /// Streams at most `self.max_body` bytes of the response body, bounded by
    /// an overall read timeout, and decodes them lossily as UTF-8.
    pub async fn read_body(&self, response: reqwest::Response) -> Result<String> {
        let body = read_body_capped(response, self.max_body, self.timeout, Overflow::Truncate)
            .await
            .map_err(|e| match e {
                // A truncated body is still usable for fingerprinting, but a
                // read that never terminates is a failure.
                BodyReadError::TimedOut => {
                    SeerError::Timeout(format!("HTTP body read timed out after {:?}", self.timeout))
                }
                other => SeerError::HttpError(format!("body chunk: {other}")),
            })?;
        Ok(String::from_utf8_lossy(&body).into_owned())
    }
}

/// What [`read_body_capped`] does once a body outgrows its cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Overflow {
    /// Keep the first `cap` bytes and stop reading (inspection probes).
    Truncate,
    /// Fail with [`BodyReadError::TooLarge`] (parsers need the whole document).
    Reject,
}

/// Why a capped body read failed; each caller maps it into its own error
/// domain (and, for retrying callers, its own transient/terminal split).
#[derive(Debug, thiserror::Error)]
pub(crate) enum BodyReadError {
    /// A chunk failed to arrive (connection reset, reqwest's own deadline).
    #[error("{0}")]
    Chunk(reqwest::Error),
    /// The body outgrew the cap under [`Overflow::Reject`].
    #[error("body exceeds the size cap")]
    TooLarge,
    /// The whole read outlasted its deadline.
    #[error("body read timed out")]
    TimedOut,
}

/// Streams `response`'s body under a byte `cap` and one overall `timeout`.
///
/// Streaming (rather than `bytes()`) means a server that omits or lies about
/// `Content-Length` cannot force an unbounded buffer, and the deadline stops a
/// server that trickles bytes forever from hanging the caller. A truncating
/// read stops as soon as the cap is reached, without waiting on more data.
pub(crate) async fn read_body_capped(
    response: reqwest::Response,
    cap: usize,
    timeout: Duration,
    overflow: Overflow,
) -> std::result::Result<Vec<u8>, BodyReadError> {
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    let read = tokio::time::timeout(timeout, async {
        while overflow == Overflow::Reject || body.len() < cap {
            let Some(chunk) = stream.next().await else {
                break;
            };
            let chunk = chunk.map_err(BodyReadError::Chunk)?;
            let room = cap.saturating_sub(body.len());
            if chunk.len() <= room {
                body.extend_from_slice(&chunk);
            } else if overflow == Overflow::Truncate {
                body.extend_from_slice(&chunk[..room]);
            } else {
                return Err(BodyReadError::TooLarge);
            }
        }
        Ok(())
    })
    .await;

    match read {
        Ok(Ok(())) => Ok(body),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(BodyReadError::TimedOut),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    //! Hermetic tests: wiremock serves scripted responses on 127.0.0.1, reached
    //! through the `#[cfg(test)]`-only `allowing_private_hosts` seam. The
    //! production-path tests need no network (IP-literal short-circuit and
    //! URL-shape rejection both fail before any connect).

    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn returns_status_headers_and_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("X-Frame-Options", "DENY")
                    .set_body_string("hello world"),
            )
            .mount(&server)
            .await;

        let resp = GuardedFetcher::new()
            .allowing_private_hosts()
            .get(&format!("{}/", server.uri()))
            .await
            .unwrap();

        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "hello world");
        assert_eq!(resp.redirects, 0);
        // Header names are normalized to lowercase for lookup.
        assert_eq!(resp.header("x-frame-options"), Some("DENY"));
    }

    #[tokio::test]
    async fn collects_repeated_set_cookie_headers() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .append_header("Set-Cookie", "a=1; Secure")
                    .append_header("Set-Cookie", "b=2; HttpOnly"),
            )
            .mount(&server)
            .await;

        let resp = GuardedFetcher::new()
            .allowing_private_hosts()
            .get(&format!("{}/", server.uri()))
            .await
            .unwrap();

        let cookies: Vec<&str> = resp.header_all("set-cookie").collect();
        assert_eq!(cookies.len(), 2, "both Set-Cookie values must survive");
        assert!(cookies.contains(&"a=1; Secure"));
        assert!(cookies.contains(&"b=2; HttpOnly"));
    }

    #[tokio::test]
    async fn follows_redirects_and_reports_hop_count() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/start"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/end"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/end"))
            .respond_with(ResponseTemplate::new(200).set_body_string("arrived"))
            .mount(&server)
            .await;

        let resp = GuardedFetcher::new()
            .allowing_private_hosts()
            .get(&format!("{}/start", server.uri()))
            .await
            .unwrap();

        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "arrived");
        assert_eq!(resp.redirects, 1);
        assert!(resp.final_url.ends_with("/end"), "got {}", resp.final_url);
    }

    #[tokio::test]
    async fn redirect_loop_is_detected() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/loop"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/loop"))
            .mount(&server)
            .await;

        let err = GuardedFetcher::new()
            .allowing_private_hosts()
            .get(&format!("{}/loop", server.uri()))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("redirect loop"), "got: {err}");
    }

    #[tokio::test]
    async fn body_is_capped() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/big"))
            .respond_with(ResponseTemplate::new(200).set_body_string("x".repeat(10_000)))
            .mount(&server)
            .await;

        let resp = GuardedFetcher::new()
            .allowing_private_hosts()
            .with_max_body(128)
            .get(&format!("{}/big", server.uri()))
            .await
            .unwrap();
        assert_eq!(resp.body.len(), 128, "body must be truncated at the cap");
    }

    #[tokio::test]
    async fn rejecting_read_accepts_the_cap_and_refuses_one_byte_more() {
        let server = MockServer::start().await;
        Mock::given(path("/body"))
            .respond_with(ResponseTemplate::new(200).set_body_string("x".repeat(100)))
            .mount(&server)
            .await;
        let url = format!("{}/body", server.uri());
        let read = |cap| {
            let url = url.clone();
            async move {
                let resp = reqwest::get(url).await.unwrap();
                read_body_capped(resp, cap, DEFAULT_TIMEOUT, Overflow::Reject).await
            }
        };

        assert_eq!(read(100).await.unwrap().len(), 100);
        assert!(matches!(read(99).await, Err(BodyReadError::TooLarge)));
    }

    #[tokio::test]
    async fn production_client_refuses_loopback() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        // No seam: the production guard must refuse before any request.
        let err = GuardedFetcher::new()
            .get(&format!("{}/", server.uri()))
            .await
            .unwrap_err();
        assert!(matches!(err, SeerError::HttpError(_)), "got {err:?}");
        server.verify().await;

        // The fixture listens on a random port, which the port rule already
        // refuses — so also prove the *loopback* guard itself fires on the
        // standard ports, where the port rule passes.
        for url in ["http://127.0.0.1/", "https://127.0.0.1/"] {
            let err = GuardedFetcher::new().get(url).await.unwrap_err();
            assert!(matches!(err, SeerError::HttpError(_)), "got {err:?}");
            assert!(
                !err.to_string().contains("non-standard port"),
                "{url} must be refused by the reserved-range check: {err}"
            );
        }
    }

    #[tokio::test]
    async fn production_client_refuses_private_and_metadata_literals() {
        let fetcher = GuardedFetcher::new();
        for url in [
            "http://10.0.0.1/",
            "https://169.254.169.254/latest/meta-data",
            "http://[::1]/",
        ] {
            let err = fetcher.get(url).await.unwrap_err();
            assert!(
                matches!(err, SeerError::HttpError(_)),
                "{url} must be refused, got {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn rejects_non_http_scheme_and_nonstandard_port() {
        let fetcher = GuardedFetcher::new();
        let err = fetcher.get("ftp://example.com/").await.unwrap_err();
        assert!(err.to_string().contains("scheme"), "got: {err}");

        // A non-80/443 port would turn a redirect chain into a port scanner.
        let err = fetcher.get("http://example.com:8080/").await.unwrap_err();
        assert!(err.to_string().contains("port"), "got: {err}");
    }

    #[tokio::test]
    async fn rejects_embedded_credentials() {
        let err = GuardedFetcher::new()
            .get("https://user:pass@example.com/")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("credentials"), "got: {err}");
    }
}
