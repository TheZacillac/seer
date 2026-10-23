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
//!   omits or lies about `Content-Length` cannot force an unbounded buffer.
//! - One deadline, the configured timeout, bounds the whole fetch: every
//!   hop's SSRF resolution, connect and response, and the body read. Hops
//!   share what is left of it rather than each getting a fresh timeout, so a
//!   chain of slow redirects (or a server trickling its body) cannot multiply
//!   the wait. A fetch that never redirects behaves as before: one request
//!   under one timeout.
//! - Failures are classified ([`SendError`]): a connect failure on the first
//!   hop that reached the network is distinguishable from an unknown (a
//!   timeout, a local no-route error — this host has no route — or a redirect
//!   target that would not connect), and the traced variants keep the
//!   redirect chain.
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

/// Default fetch deadline: the whole redirect walk plus the body read.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Deadline for tests that connect to a closed loopback port and expect a
/// refusal. Windows retries a refused SYN and reports ECONNREFUSED only after
/// about 2s, so a shorter deadline turns the refusal into a timeout (which
/// classifies as [`SendError::Other`], not `Connect`).
#[cfg(test)]
pub(crate) const CLOSED_PORT_TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum redirect hops followed before giving up.
const MAX_REDIRECTS: usize = 5;

/// Default cap on the response body retained for inspection. Provider
/// fingerprints and `<title>`-style markers all live in the first few KB;
/// 64 KB is generous while keeping a hostile server from ballooning memory
/// across a concurrent scan.
const DEFAULT_MAX_BODY: usize = 64 * 1024;

/// The status line and headers of a guarded response, reduced to what the
/// security probes need.
#[derive(Debug, Clone)]
pub(crate) struct ResponseHead {
    /// The URL that finally answered (after any redirects).
    pub final_url: String,
    pub status: u16,
    /// Response headers with lowercase names (as the `http` crate stores
    /// them), in wire order. A `Vec` rather than a map because `set-cookie`
    /// legitimately repeats and each occurrence must be graded separately.
    pub headers: Vec<(String, String)>,
    /// Number of redirect hops followed to reach `final_url`.
    pub redirects: usize,
}

impl ResponseHead {
    fn of(response: &reqwest::Response, redirects: usize) -> Self {
        Self {
            final_url: response.url().to_string(),
            status: response.status().as_u16(),
            headers: response
                .headers()
                .iter()
                .map(|(name, value)| {
                    (
                        name.as_str().to_owned(),
                        // A header value that isn't valid UTF-8 is still worth
                        // reporting as present; lossy-decode rather than drop.
                        String::from_utf8_lossy(value.as_bytes()).into_owned(),
                    )
                })
                .collect(),
            redirects,
        }
    }

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

/// A fetched HTTP response: its head plus the capped body.
#[derive(Debug, Clone)]
pub(crate) struct FetchedResponse {
    pub head: ResponseHead,
    /// Body, lossily decoded as UTF-8 and truncated to the configured cap.
    pub body: String,
}

/// Why a guarded request failed, split so a probe can tell "the connection
/// to the requested URL failed" (refused, remote unreachable, TLS handshake
/// failure) from everything else (SSRF refusal, bad URL, redirect loop, any
/// timeout, a local no-route error, a failed redirect hop), which is an
/// unknown, not a negative result. A timeout is [`SendError::Other`]: it may
/// be packet loss, so it proves nothing about the host; nor does a local
/// no-route error (this host has no route to the address, e.g. an IPv6
/// address without IPv6 transit). Nor does a redirect target that fails to
/// connect: the requested host answered, so it is reachable.
#[derive(Debug)]
pub(crate) enum SendError {
    /// The connection to the requested URL (the first hop) failed: refused,
    /// remote unreachable, or a TLS handshake failure.
    Connect(SeerError),
    /// Any other failure, including timeouts, local no-route errors and any
    /// failure on a later redirect hop.
    Other(SeerError),
}

impl From<SendError> for SeerError {
    fn from(e: SendError) -> Self {
        match e {
            SendError::Connect(error) | SendError::Other(error) => error,
        }
    }
}

/// A guarded fetch plus the URLs it attempted, in order. The chain is kept
/// even when a later hop fails: a probe may only need to know where the
/// first hop pointed.
#[derive(Debug)]
pub(crate) struct Traced<T> {
    pub chain: Vec<String>,
    pub result: std::result::Result<T, SendError>,
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

    /// Sets the fetch deadline (the whole redirect walk plus the body read).
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
        let deadline = self.deadline();
        let mut chain = Vec::new();
        let response = self.send_until(url, &mut chain, deadline).await?;
        let head = ResponseHead::of(&response, chain.len().saturating_sub(1));
        let body = self.read_body_until(response, deadline).await?;
        Ok(FetchedResponse { head, body })
    }

    /// The guarded request half of [`GuardedFetcher::get`]: returns the final
    /// response (a 3xx only when it carries no `Location`) with its body still
    /// unread, plus the number of hops followed. For callers that want the
    /// body only for some responses — read it through
    /// [`GuardedFetcher::read_body`] so the cap still applies. The response's
    /// client carries what is left of the fetch deadline as its total
    /// timeout, which spans the body, so a later read stays within it.
    pub async fn send(&self, url: &str) -> Result<(reqwest::Response, usize)> {
        let mut chain = Vec::new();
        let response = self.send_until(url, &mut chain, self.deadline()).await?;
        Ok((response, chain.len().saturating_sub(1)))
    }

    /// [`GuardedFetcher::get_traced`] for callers that grade only the status
    /// and headers: the body is never read, so one that stalls or resets
    /// cannot fail the fetch. Also reports the URLs attempted and keeps the
    /// connect/other split. See [`Traced`].
    pub async fn get_head_traced(&self, url: &str) -> Traced<ResponseHead> {
        let mut chain = Vec::new();
        let result = self
            .send_until(url, &mut chain, self.deadline())
            .await
            .map(|response| ResponseHead::of(&response, chain.len().saturating_sub(1)));
        Traced { chain, result }
    }

    /// [`GuardedFetcher::get`] that also reports the URLs attempted and keeps
    /// the connect/other split. See [`Traced`].
    pub async fn get_traced(&self, url: &str) -> Traced<FetchedResponse> {
        let deadline = self.deadline();
        let mut chain = Vec::new();
        let result = match self.send_until(url, &mut chain, deadline).await {
            Ok(response) => {
                let head = ResponseHead::of(&response, chain.len().saturating_sub(1));
                self.read_body_until(response, deadline)
                    .await
                    .map(|body| FetchedResponse { head, body })
                    .map_err(SendError::Other)
            }
            Err(e) => Err(e),
        };
        Traced { chain, result }
    }

    /// The deadline for a fetch starting now.
    fn deadline(&self) -> tokio::time::Instant {
        tokio::time::Instant::now() + self.timeout
    }

    /// [`GuardedFetcher::walk`] bounded by `deadline`; running out is a
    /// timeout ([`SendError::Other`]). `chain` keeps the URLs attempted.
    async fn send_until(
        &self,
        url: &str,
        chain: &mut Vec<String>,
        deadline: tokio::time::Instant,
    ) -> std::result::Result<reqwest::Response, SendError> {
        match tokio::time::timeout_at(deadline, self.walk(url, chain, deadline)).await {
            Ok(result) => result,
            Err(_) => Err(SendError::Other(SeerError::Timeout(format!(
                "HTTP fetch timed out after {:?}",
                self.timeout
            )))),
        }
    }

    /// The redirect walk behind every fetch: records each URL in `chain`
    /// before requesting it and classifies a failed connect. Each hop's
    /// client gets what is left of `deadline` as its total timeout.
    async fn walk(
        &self,
        url: &str,
        chain: &mut Vec<String>,
        deadline: tokio::time::Instant,
    ) -> std::result::Result<reqwest::Response, SendError> {
        let mut url = Url::parse(url).map_err(|e| {
            SendError::Other(SeerError::HttpError(format!(
                "invalid URL '{}': {}",
                url, e
            )))
        })?;
        let mut visited: HashSet<String> = HashSet::new();

        for hop in 0..=MAX_REDIRECTS {
            if !visited.insert(url.as_str().to_string()) {
                return Err(SendError::Other(SeerError::HttpError(
                    "redirect loop detected".to_string(),
                )));
            }
            chain.push(url.to_string());

            // No auto-redirects (see the module docs): each hop is re-guarded.
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let mut builder =
                crate::net::client_builder(remaining).user_agent(crate::net::USER_AGENT);

            if !self.allow_private {
                let addrs = crate::net::validate_http_url(&url)
                    .await
                    .map_err(SendError::Other)?;
                let host = url.host_str().ok_or_else(|| {
                    SendError::Other(SeerError::HttpError("missing URL host".to_string()))
                })?;
                builder = builder.resolve_to_addrs(host, &addrs);
            }

            let client = builder.build().map_err(|e| {
                SendError::Other(SeerError::HttpError(format!(
                    "failed to build HTTP client: {}",
                    e
                )))
            })?;

            let response = client
                .get(url.clone())
                .send()
                .await
                .map_err(|e| classify_send_error(e, hop == 0))?;

            // A 3xx with no `Location` has nowhere to go and is the final
            // response (RFC 9110 §15.4: `Location` is optional for 300 and
            // absent from 304).
            let location = response
                .status()
                .is_redirection()
                .then(|| response.headers().get(reqwest::header::LOCATION))
                .flatten();
            let Some(location) = location else {
                return Ok(response);
            };
            let location = location.to_str().map_err(|_| {
                SendError::Other(SeerError::HttpError(
                    "redirect location is not valid text".to_string(),
                ))
            })?;
            // Resolve relative Locations against the current URL; fall back to
            // an absolute parse. The result is re-validated at the top of the
            // next iteration before any connect.
            url = url
                .join(location)
                .or_else(|_| Url::parse(location))
                .map_err(|e| {
                    SendError::Other(SeerError::HttpError(format!("invalid redirect URL: {}", e)))
                })?;
        }

        Err(SendError::Other(SeerError::HttpError(
            "too many redirects".to_string(),
        )))
    }

    /// Streams at most `self.max_body` bytes of the response body and
    /// decodes them lossily as UTF-8. The read is bounded by the fetch
    /// deadline (see [`GuardedFetcher::send`]) and, as a backstop, by one
    /// more timeout of its own.
    pub async fn read_body(&self, response: reqwest::Response) -> Result<String> {
        self.read_body_until(response, self.deadline()).await
    }

    /// [`GuardedFetcher::read_body`] bounded by `deadline`.
    async fn read_body_until(
        &self,
        response: reqwest::Response,
        deadline: tokio::time::Instant,
    ) -> Result<String> {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let timed_out =
            || SeerError::Timeout(format!("HTTP body read timed out after {:?}", self.timeout));
        let body = read_body_capped(response, self.max_body, remaining, Overflow::Truncate)
            .await
            .map_err(|e| match e {
                // A truncated body is still usable for fingerprinting, but a
                // read that never terminates is a failure, whichever of our
                // deadline and the client's (the same one) fires first.
                BodyReadError::TimedOut => timed_out(),
                BodyReadError::Chunk(e) if e.is_timeout() => timed_out(),
                // A chunk error (a truncating read never reports TooLarge).
                other => SeerError::HttpError(format!("body chunk: {other}")),
            })?;
        Ok(String::from_utf8_lossy(&body).into_owned())
    }
}

/// Splits a failed request into [`SendError`]: only a connect failure on the
/// `first_hop` that reached the network (refused, remote unreachable, TLS
/// handshake failure) is [`SendError::Connect`]. A connect timeout and a
/// local no-route error (this host has no route, see [`is_local_failure`])
/// say nothing about the remote host, and a later hop failing says nothing
/// about the requested one (it answered with the redirect), so they are
/// [`SendError::Other`].
fn classify_send_error(e: reqwest::Error, first_hop: bool) -> SendError {
    let connect = e.is_connect() && !e.is_timeout() && !is_local_failure(&e);
    match (connect, first_hop) {
        (true, true) => SendError::Connect(SeerError::HttpError(e.to_string())),
        (true, false) => SendError::Other(SeerError::HttpError(format!(
            "redirect target unreachable: {e}"
        ))),
        (false, _) => SendError::Other(SeerError::HttpError(e.to_string())),
    }
}

/// Whether any io error in `error`'s source chain (or wrapped inside one)
/// means the packet never left this host — the DNS layer's rule,
/// `dns::delegation::is_local_no_route`.
fn is_local_failure(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut next = Some(error);
    while let Some(err) = next {
        next = match err.downcast_ref::<std::io::Error>() {
            Some(io) if crate::dns::is_local_no_route(io) => return true,
            // An io error's `source()` skips its own payload; look inside it.
            Some(io) => io
                .get_ref()
                .map(|inner| inner as &(dyn std::error::Error + 'static)),
            None => err.source(),
        };
    }
    false
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

        assert_eq!(resp.head.status, 200);
        assert_eq!(resp.body, "hello world");
        assert_eq!(resp.head.redirects, 0);
        // Header names are normalized to lowercase for lookup.
        assert_eq!(resp.head.header("x-frame-options"), Some("DENY"));
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

        let cookies: Vec<&str> = resp.head.header_all("set-cookie").collect();
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

        assert_eq!(resp.head.status, 200);
        assert_eq!(resp.body, "arrived");
        assert_eq!(resp.head.redirects, 1);
        assert!(
            resp.head.final_url.ends_with("/end"),
            "got {}",
            resp.head.final_url
        );
    }

    /// Regression: a 3xx without `Location` (a 300 choice page, a 304) was a
    /// hard error instead of the final response.
    #[tokio::test]
    async fn a_redirect_status_without_location_is_final() {
        let server = MockServer::start().await;
        for status in [300u16, 304] {
            Mock::given(method("GET"))
                .and(path(format!("/s{status}")))
                .respond_with(ResponseTemplate::new(status))
                .mount(&server)
                .await;
            let head = GuardedFetcher::new()
                .allowing_private_hosts()
                .get_head_traced(&format!("{}/s{status}", server.uri()))
                .await
                .result
                .unwrap();
            assert_eq!(head.status, status);
            assert_eq!(head.redirects, 0);
        }
    }

    /// `get_head_traced` never reads the body, so one that never arrives cannot
    /// fail the fetch.
    #[tokio::test]
    async fn get_head_traced_does_not_wait_for_the_body() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let _ = tcp.read(&mut [0u8; 1024]).await;
            // Promise a body, then stall.
            let _ = tcp
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\nx-probe: 1\r\n\r\n")
                .await;
            std::future::pending::<()>().await;
        });

        let fetcher = GuardedFetcher::new()
            .allowing_private_hosts()
            .with_timeout(Duration::from_millis(500));
        let head = fetcher
            .get_head_traced(&format!("http://{addr}/"))
            .await
            .result
            .unwrap();
        assert_eq!(head.status, 200);
        assert_eq!(head.header("x-probe"), Some("1"));
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

    #[tokio::test]
    async fn traced_fetch_records_every_hop() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/start"))
            .respond_with(ResponseTemplate::new(301).insert_header("location", "/end"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/end"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let fetcher = GuardedFetcher::new().allowing_private_hosts();
        let traced = fetcher
            .get_head_traced(&format!("{}/start", server.uri()))
            .await;
        assert_eq!(traced.result.unwrap().status, 200);
        assert_eq!(
            traced.chain,
            vec![
                format!("{}/start", server.uri()),
                format!("{}/end", server.uri())
            ]
        );
    }

    #[tokio::test]
    async fn refused_connection_is_a_connect_error() {
        // Bind then drop: the port is closed, so connecting is refused.
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let fetcher = GuardedFetcher::new()
            .with_timeout(CLOSED_PORT_TEST_TIMEOUT)
            .allowing_private_hosts();
        let traced = fetcher
            .get_head_traced(&format!("http://127.0.0.1:{port}/"))
            .await;
        assert!(
            matches!(traced.result, Err(SendError::Connect(_))),
            "{:?}",
            traced.result.err()
        );
        assert_eq!(traced.chain.len(), 1);
    }

    /// A wrapper whose `source()` is the io error, as hyper's connect error is.
    #[derive(Debug)]
    struct Wrapped(std::io::Error);
    impl std::fmt::Display for Wrapped {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("tcp connect error")
        }
    }
    impl std::error::Error for Wrapped {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    #[test]
    fn local_no_route_anywhere_in_the_chain_is_a_local_failure() {
        use std::io::{Error, ErrorKind};
        for kind in [ErrorKind::NetworkUnreachable, ErrorKind::HostUnreachable] {
            assert!(is_local_failure(&Wrapped(Error::from(kind))), "{kind:?}");
            // Also when an io error wraps the cause (as its payload).
            assert!(is_local_failure(&Error::other(Error::from(kind))));
        }
        // A remote refusal or reset reached the host: not local.
        for kind in [ErrorKind::ConnectionRefused, ErrorKind::ConnectionReset] {
            assert!(!is_local_failure(&Wrapped(Error::from(kind))), "{kind:?}");
        }
        assert!(!is_local_failure(&Error::other("no io cause")));
    }

    #[tokio::test]
    async fn an_ssrf_refused_first_hop_is_other_with_a_one_url_chain() {
        // A production fetcher (no `allowing_private_hosts`) refuses loopback
        // before any connect.
        let traced = GuardedFetcher::new()
            .get_head_traced("http://127.0.0.1/")
            .await;
        assert!(
            matches!(traced.result, Err(SendError::Other(_))),
            "{:?}",
            traced.result.err()
        );
        assert_eq!(traced.chain, vec!["http://127.0.0.1/".to_string()]);
    }

    #[tokio::test]
    async fn send_still_counts_hops() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/a"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/b"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/b"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let fetcher = GuardedFetcher::new().allowing_private_hosts();
        let (_, hops) = fetcher.send(&format!("{}/a", server.uri())).await.unwrap();
        assert_eq!(hops, 1);
    }

    /// Regression: a redirect target that refused the connection surfaced as
    /// `SendError::Connect`, so the audit called the requested host (which
    /// answered) unreachable over HTTPS.
    #[tokio::test]
    async fn a_later_hop_connect_failure_is_other() {
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("http://127.0.0.1:{port}/")),
            )
            .mount(&server)
            .await;
        let traced = GuardedFetcher::new()
            .with_timeout(CLOSED_PORT_TEST_TIMEOUT)
            .allowing_private_hosts()
            .get_head_traced(&format!("{}/", server.uri()))
            .await;
        match traced.result {
            Err(SendError::Other(e)) => {
                assert!(e.to_string().contains("redirect target"), "{e}");
            }
            other => panic!("expected SendError::Other, got {:?}", other.err()),
        }
        assert_eq!(traced.chain.len(), 2);
    }

    /// Regression: each redirect hop got a fresh full timeout, so six hops of
    /// 300ms each finished after ~1.8s under a 1s timeout.
    #[tokio::test]
    async fn one_deadline_bounds_the_whole_redirect_walk() {
        let server = MockServer::start().await;
        for n in 0..5 {
            Mock::given(method("GET"))
                .and(path(format!("/{n}")))
                .respond_with(
                    ResponseTemplate::new(302)
                        .insert_header("location", format!("/{}", n + 1))
                        .set_delay(Duration::from_millis(300)),
                )
                .mount(&server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/5"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(300)))
            .mount(&server)
            .await;

        let started = std::time::Instant::now();
        let traced = GuardedFetcher::new()
            .with_timeout(Duration::from_secs(1))
            .allowing_private_hosts()
            .get_head_traced(&format!("{}/0", server.uri()))
            .await;
        let elapsed = started.elapsed();
        assert!(
            matches!(traced.result, Err(SendError::Other(SeerError::Timeout(_)))),
            "{:?}",
            traced.result.map(|h| h.status)
        );
        assert!(elapsed < Duration::from_millis(1500), "took {elapsed:?}");
        // The hops reached before the deadline are still reported.
        assert!((2..6).contains(&traced.chain.len()), "{:?}", traced.chain);
    }

    /// The body read shares the walk's deadline: a slow redirect followed by
    /// a stalled body does not get a fresh timeout for the read.
    #[tokio::test]
    async fn the_body_read_shares_the_fetch_deadline() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut tcp, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let n = tcp.read(&mut buf).await.unwrap_or(0);
                    let reply: &[u8] = if buf[..n].starts_with(b"GET /start") {
                        tokio::time::sleep(Duration::from_millis(700)).await;
                        b"HTTP/1.1 302 Found\r\nlocation: /end\r\ncontent-length: 0\r\n\r\n"
                    } else {
                        // Promise a body, send part of it, then stall.
                        b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\npartial"
                    };
                    let _ = tcp.write_all(reply).await;
                    std::future::pending::<()>().await;
                });
            }
        });

        let started = std::time::Instant::now();
        let result = GuardedFetcher::new()
            .with_timeout(Duration::from_secs(1))
            .allowing_private_hosts()
            .get(&format!("http://{addr}/start"))
            .await;
        let elapsed = started.elapsed();
        assert!(matches!(result, Err(SeerError::Timeout(_))), "{result:?}");
        assert!(elapsed < Duration::from_millis(1400), "took {elapsed:?}");
    }
}
