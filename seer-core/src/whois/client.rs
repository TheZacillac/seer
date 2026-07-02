use std::collections::HashSet;
use std::time::Duration;

use once_cell::sync::Lazy;
use regex::Regex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, instrument, warn};

use super::parser::WhoisResponse;
use super::servers::{get_tld, get_whois_server};
use crate::cache::TtlCache;
use crate::error::{Result, SeerError};
use crate::retry::{RetryExecutor, RetryPolicy};
use crate::validation::normalize_domain;

/// Pre-compiled regexes for extracting WHOIS referral servers.
static REFERRAL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    // The value MUST be on the SAME line as the key. Use `[ \t]*` (horizontal
    // whitespace only) rather than `\s*` between the key and the capture
    // group: `\s*` matches newlines, so an EMPTY `Registrar WHOIS Server:`
    // line would otherwise swallow the line break and capture the following
    // line's content as the referral server. `[ \t]*` keeps the match anchored
    // to the key's own line, and the `(.+)` capture (where `.` excludes `\n`)
    // yields no match for an empty value.
    vec![
        Regex::new(r"(?i)Registrar WHOIS Server:[ \t]*(.+)")
            .expect("Invalid regex pattern for Registrar WHOIS Server"),
        Regex::new(r"(?i)Whois Server:[ \t]*(.+)").expect("Invalid regex pattern for Whois Server"),
        Regex::new(r"(?i)ReferralServer:[ \t]*whois://(.+)")
            .expect("Invalid regex pattern for ReferralServer"),
    ]
});

const WHOIS_PORT: u16 = 43;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15); // Increased for slow ccTLD registries
const MAX_RESPONSE_SIZE: usize = 1024 * 1024; // 1MB
const MAX_REFERRAL_DEPTH: u8 = 3;
const IANA_WHOIS_SERVER: &str = "whois.iana.org";

/// TTL for discovered WHOIS servers (24 hours)
const SERVER_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Cache for dynamically discovered WHOIS servers with TTL expiration
static DISCOVERED_SERVERS: Lazy<TtlCache<String, String>> =
    Lazy::new(|| TtlCache::new(SERVER_CACHE_TTL));

#[derive(Debug, Clone)]
pub struct WhoisClient {
    timeout: Duration,
    retry_policy: RetryPolicy,
    /// Target port for WHOIS queries. Always [`WHOIS_PORT`] in production;
    /// overridable only through the `#[cfg(test)]` seam so mock-server tests
    /// can bind an ephemeral local port.
    port: u16,
    /// When true, skips the SSRF/public-host validation so tests can point
    /// the client at a 127.0.0.1 fixture. Not settable outside `#[cfg(test)]`
    /// builds — production paths always validate.
    allow_private_hosts: bool,
}

impl Default for WhoisClient {
    fn default() -> Self {
        Self::new()
    }
}

impl WhoisClient {
    /// Creates a new WHOIS client with default settings.
    pub fn new() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            retry_policy: RetryPolicy::default(),
            port: WHOIS_PORT,
            allow_private_hosts: false,
        }
    }

    /// Builds a client honoring `~/.seer/config.toml` settings.
    ///
    /// Reads `timeouts.whois_secs` (already clamped to 1–300s by
    /// [`crate::config::SeerConfig::load`]). Sugar over
    /// [`WhoisClient::with_timeout`] — equivalent to
    /// `WhoisClient::new().with_timeout(config.whois_timeout())`.
    pub fn from_config(config: &crate::config::SeerConfig) -> Self {
        Self::new().with_timeout(config.whois_timeout())
    }

    /// Test-only: allow connections to loopback/private hosts (mock servers).
    #[cfg(test)]
    pub(crate) fn allowing_private_hosts(mut self) -> Self {
        self.allow_private_hosts = true;
        self
    }

    /// Test-only: query a non-standard port (mock servers bind ephemeral ports).
    #[cfg(test)]
    pub(crate) fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Sets the timeout for WHOIS queries.
    ///
    /// The default is 15 seconds to accommodate slow ccTLD registries.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the retry policy for transient network failures.
    ///
    /// The default policy retries up to 3 times with exponential backoff.
    pub fn with_retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry_policy = policy;
        self
    }

    /// Disables retries (single attempt only).
    pub fn without_retries(mut self) -> Self {
        self.retry_policy = RetryPolicy::no_retry();
        self
    }

    /// Performs a WHOIS lookup for a domain.
    ///
    /// Automatically discovers the appropriate WHOIS server and follows referrals
    /// to get the most detailed registration information.
    #[instrument(skip(self), fields(domain = %domain))]
    pub async fn lookup(&self, domain: &str) -> Result<WhoisResponse> {
        let start = std::time::Instant::now();
        let domain = normalize_domain(domain)?;
        let tld = get_tld(&domain).ok_or_else(|| SeerError::InvalidDomain(domain.clone()))?;

        // Try static mapping first
        let whois_server = if let Some(server) = get_whois_server(tld) {
            server.to_string()
        } else {
            let tld_lower = tld.to_lowercase();
            // Try cached discovered server (TTL-aware)
            if let Some(server) = DISCOVERED_SERVERS.get(&tld_lower) {
                debug!(tld = %tld, server = %server, "Using cached WHOIS server");
                server
            } else {
                // Query IANA to discover the WHOIS server (with retry)
                debug!(tld = %tld, "Querying IANA for WHOIS server");
                let server = self.discover_whois_server_with_retry(tld).await?;
                DISCOVERED_SERVERS.insert(tld_lower, server.clone());
                server
            }
        };

        let mut visited = HashSet::new();
        let result = self
            .lookup_with_referrals(&domain, &whois_server, 0, &mut visited)
            .await;
        let elapsed_ms = start.elapsed().as_millis();
        debug!(
            domain = %domain,
            elapsed_ms = elapsed_ms,
            "WHOIS lookup complete"
        );
        result
    }

    fn lookup_with_referrals<'a>(
        &'a self,
        domain: &'a str,
        whois_server: &'a str,
        depth: u8,
        visited: &'a mut HashSet<String>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<WhoisResponse>> + Send + 'a>>
    {
        Box::pin(async move {
            // Enforce max referral depth BEFORE querying so we consult at most
            // MAX_REFERRAL_DEPTH servers (depths 0..MAX_REFERRAL_DEPTH-1).
            if depth >= MAX_REFERRAL_DEPTH {
                warn!(depth = depth, server = %whois_server, "Max referral depth reached before query, aborting referral chain");
                return Err(SeerError::WhoisError(
                    "max WHOIS referral depth exceeded".to_string(),
                ));
            }

            // Check for circular referrals
            let server_lower = whois_server.to_lowercase();
            if visited.contains(&server_lower) {
                warn!(server = %whois_server, "Circular WHOIS referral detected");
                return Err(SeerError::WhoisError(
                    "circular WHOIS referral detected".to_string(),
                ));
            }
            visited.insert(server_lower);

            debug!(whois_server = %whois_server, depth = depth, "Querying WHOIS server");

            // Query with retry logic
            let raw_response = self.query_server_with_retry(whois_server, domain).await?;
            let current_response = WhoisResponse::parse(domain, whois_server, &raw_response);

            // Prefer registry response when it has core data (registrar, dates,
            // nameservers).  Registrar (referral) servers are often slow, rate-
            // limited, or outright block non-commercial queries (e.g. CSC's
            // whois.corporatedomains.com).  Most contact fields are GDPR-redacted
            // anyway, so the registry response is sufficient for the vast majority
            // of use cases.
            if current_response.has_core_data() {
                debug!(
                    server = %whois_server,
                    "Registry response has core data, skipping registrar referral"
                );
                return Ok(current_response);
            }

            // Registry response is thin — follow the referral for more detail
            if let Some(referral) = extract_referral_with(&raw_response, self.allow_private_hosts) {
                if referral != whois_server && !visited.contains(&referral.to_lowercase()) {
                    debug!(
                        referral_depth = depth,
                        "Registry response lacks core data, following referral to {}", referral
                    );
                    match self
                        .lookup_with_referrals(domain, &referral, depth + 1, visited)
                        .await
                    {
                        Ok(referral_response) => {
                            if referral_response.is_available()
                                || referral_response.indicates_not_found()
                            {
                                debug!(
                                    referral = %referral,
                                    "Referral server indicates domain not found, using registry response"
                                );
                                return Ok(current_response);
                            }
                            return Ok(referral_response);
                        }
                        Err(e) => {
                            debug!(referral = %referral, error = %e, "Referral lookup failed, using registry response");
                            return Ok(current_response);
                        }
                    }
                }
            }

            Ok(current_response)
        })
    }

    /// Performs a WHOIS lookup using a specific WHOIS server.
    ///
    /// Use this when you know the exact server to query, bypassing automatic
    /// server discovery and referral following.
    #[instrument(skip(self), fields(domain = %domain, server = %server))]
    pub async fn lookup_with_server(&self, domain: &str, server: &str) -> Result<WhoisResponse> {
        // Validate server before any network connection
        if server.contains('\r') || server.contains('\n') {
            return Err(SeerError::WhoisError(format!(
                "invalid WHOIS server: contains illegal characters: {}",
                server.replace('\r', "\\r").replace('\n', "\\n")
            )));
        }
        if !self.allow_private_hosts && !is_safe_whois_server(server) {
            return Err(SeerError::WhoisError(format!(
                "invalid WHOIS server: {}",
                server
            )));
        }

        let domain = normalize_domain(domain)?;
        let raw_response = self.query_server_with_retry(server, &domain).await?;
        Ok(WhoisResponse::parse(&domain, server, &raw_response))
    }

    /// Queries a WHOIS server with retry logic for transient failures.
    async fn query_server_with_retry(&self, server: &str, query: &str) -> Result<String> {
        let executor = RetryExecutor::new(self.retry_policy.clone());
        let server = server.to_string();
        let query = query.to_string();
        let timeout_duration = self.timeout;
        let port = self.port;
        let allow_private_hosts = self.allow_private_hosts;

        executor
            .execute(|| {
                let server = server.clone();
                let query = query.clone();
                async move {
                    query_server_internal_with(
                        &server,
                        &query,
                        timeout_duration,
                        port,
                        allow_private_hosts,
                    )
                    .await
                }
            })
            .await
    }

    /// Discovers the WHOIS server for a TLD by querying IANA (with retry).
    async fn discover_whois_server_with_retry(&self, tld: &str) -> Result<String> {
        let response = self.query_server_with_retry(IANA_WHOIS_SERVER, tld).await?;

        // Parse IANA response to find the whois server
        // IANA response format includes a line like: "whois:        whois.nic.xyz"
        if let Some(server) = extract_iana_whois_server(&response) {
            // Validate IANA-discovered hostname before trusting/caching it.
            // A poisoned IANA response could otherwise inject a malicious
            // WHOIS server that gets cached for 24h.
            if !is_safe_whois_server(&server) {
                warn!(server = %server, "IANA returned unsafe WHOIS server, rejecting");
                return Err(SeerError::WhoisError(format!(
                    "IANA returned unsafe WHOIS server: {}",
                    server
                )));
            }
            // SSRF guard: resolve the discovered hostname and refuse it if any
            // resolved address is in a reserved range. This prevents a malicious
            // or poisoned IANA response from caching a hostname that (via DNS
            // rebinding or otherwise) points at internal services (H1 amplifier
            // via 24h cache).
            crate::net::validate_public_host(&server, WHOIS_PORT).await?;
            return Ok(server);
        }

        // No WHOIS server found - check for registration URL in remarks
        if let Some(url) = extract_iana_registration_url(&response) {
            return Err(SeerError::WhoisServerNotFound(format!(
                "No WHOIS server for '.{}' - check whois directly via: {}",
                tld, url
            )));
        }

        Err(SeerError::WhoisServerNotFound(format!(
            "No WHOIS server found for TLD '{}'",
            tld
        )))
    }
}

/// Test-facing wrapper with the historical 3-arg signature: standard port,
/// full SSRF validation. Production goes through [`query_server_internal_with`]
/// via `WhoisClient`, whose `port`/`allow_private_hosts` fields are only
/// non-default in `#[cfg(test)]` builds.
#[cfg(test)]
async fn query_server_internal(
    server: &str,
    query: &str,
    timeout_duration: Duration,
) -> Result<String> {
    query_server_internal_with(server, query, timeout_duration, WHOIS_PORT, false).await
}

/// Like [`query_server_internal`], parameterized over port and host
/// validation so `#[cfg(test)]` mock-server tests can target 127.0.0.1 on an
/// ephemeral port. Every production call site goes through the validating
/// wrapper above or a `WhoisClient` constructed with `allow_private_hosts:
/// false` (the only kind constructible outside test builds).
async fn query_server_internal_with(
    server: &str,
    query: &str,
    timeout_duration: Duration,
    port: u16,
    allow_private_hosts: bool,
) -> Result<String> {
    // Defense in depth: reject CR/LF/NUL in the query before any TCP write.
    // normalize_domain already filters these, but we enforce here too so
    // alternate call paths cannot bypass the check.
    if query.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n') {
        return Err(SeerError::WhoisError(
            "query string must not contain CR/LF/NUL".into(),
        ));
    }

    // SSRF guard: resolve the server hostname, refuse any address in a
    // reserved/private/loopback/link-local range, and connect to the VALIDATED
    // SocketAddrs. Connecting to the resolved addresses (rather than letting
    // TcpStream::connect("host:port") re-resolve) closes the DNS-rebinding
    // TOCTOU where a hostile authoritative DNS for a referral/IANA-discovered
    // server could answer the validation lookup with a public IP and the
    // connect lookup with 127.0.0.1 / 169.254.169.254 / RFC1918.
    let addrs: Vec<std::net::SocketAddr> = if allow_private_hosts {
        tokio::net::lookup_host((server, port))
            .await
            .map_err(|e| SeerError::WhoisError(format!("failed to resolve {}: {}", server, e)))?
            .collect()
    } else {
        crate::net::resolve_public_host(server, port).await?
    };

    debug!("WHOIS query to {}", server);
    let mut stream = timeout(timeout_duration, TcpStream::connect(addrs.as_slice()))
        .await
        .map_err(|_| SeerError::Timeout(format!("connection to {} timed out", server)))?
        // Use the unconditionally-retryable variant: the substring-gated
        // WhoisError classifier misses transient connect failures whose OS
        // message lacks "connection"/"refused"/"reset"/"timeout" (e.g.
        // "Network is unreachable", "No route to host"), so those would not be
        // retried despite the configured RetryPolicy.
        .map_err(|e| {
            SeerError::WhoisConnectionFailed(format!("failed to connect to {}: {}", server, e))
        })?;

    // Send query with CRLF
    let query_bytes = format!("{}\r\n", query);
    timeout(timeout_duration, stream.write_all(query_bytes.as_bytes()))
        .await
        .map_err(|_| SeerError::Timeout("write timed out".to_string()))?
        .map_err(|e| SeerError::WhoisError(format!("failed to send query: {}", e)))?;

    // Read response with a wall-clock deadline so slow-trickle servers
    // cannot hold the connection open indefinitely.
    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + timeout_duration;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            if !response.is_empty() {
                tracing::warn!(
                    "WHOIS read deadline reached with partial response ({} bytes)",
                    response.len()
                );
                break;
            }
            return Err(SeerError::Timeout("read timed out".to_string()));
        }

        let read_result = timeout(remaining, stream.read(&mut buf)).await;

        match read_result {
            Ok(Ok(0)) => break, // EOF
            Ok(Ok(n)) => {
                response.extend_from_slice(&buf[..n]);
                if response.len() > MAX_RESPONSE_SIZE {
                    return Err(SeerError::WhoisError("response too large".to_string()));
                }
            }
            Ok(Err(e)) => {
                return Err(SeerError::WhoisError(format!("read error: {}", e)));
            }
            Err(_) => {
                // Timeout on read - if we have data, return it
                if !response.is_empty() {
                    tracing::warn!(
                        "WHOIS per-read timeout with partial response ({} bytes)",
                        response.len()
                    );
                    break;
                }
                return Err(SeerError::Timeout("read timed out".to_string()));
            }
        }
    }

    // Explicitly shutdown the TCP stream to ensure proper FIN handshake
    let _ = stream.shutdown().await;

    // Try UTF-8, fall back to Latin-1
    // Preserve valid UTF-8 (CJK ccTLD registries — JPRS, KISA, CONAC, TWNIC,
    // NIC.br — emit UTF-8) and replace only the invalid bytes, rather than
    // reinterpreting the WHOLE body as Latin-1, which would mojibake every
    // multi-byte character after a single stray byte and silently drop CJK
    // nameservers/dates from the parsed result.
    Ok(String::from_utf8(response)
        .unwrap_or_else(|e| String::from_utf8_lossy(&e.into_bytes()).into_owned()))
}

/// Extracts the WHOIS server from an IANA response.
fn extract_iana_whois_server(response: &str) -> Option<String> {
    for line in response.lines() {
        let line = line.trim();
        if line.to_lowercase().starts_with("whois:") {
            let server = line[6..].trim();
            if !server.is_empty() {
                return Some(server.to_lowercase());
            }
        }
    }
    None
}

/// Extracts the registration URL from an IANA response remarks field.
fn extract_iana_registration_url(response: &str) -> Option<String> {
    for line in response.lines() {
        let line = line.trim();
        if line.to_lowercase().starts_with("remarks:") {
            let remarks = line[8..].trim();
            // Look for URL patterns in remarks
            if let Some(url_start) = remarks.find("http") {
                let url = &remarks[url_start..];
                // Extract URL (ends at whitespace or end of line)
                let url_end = url.find(char::is_whitespace).unwrap_or(url.len());
                return Some(url[..url_end].to_string());
            }
        }
    }
    None
}

/// Checks whether a WHOIS referral server hostname is safe to connect to.
/// Rejects IP literals in private/reserved ranges, embedded ports, and
/// hostnames with characters that are not valid in DNS labels.
fn is_safe_whois_server(server: &str) -> bool {
    // Must be a plausible hostname: alphanumeric, dots, hyphens only
    if server.is_empty() || !server.contains('.') {
        return false;
    }
    if !server
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return false;
    }
    // Reject IP address literals that resolve to private/reserved ranges
    if let Ok(ip) = server.parse::<std::net::IpAddr>() {
        return !crate::validation::is_private_or_reserved_ip(&ip);
    }
    true
}

/// Test-facing wrapper preserving the historical 1-arg signature (production
/// semantics: safe-hostname filter applied).
#[cfg(test)]
fn extract_referral(response: &str) -> Option<String> {
    extract_referral_with(response, false)
}

/// Like [`extract_referral`], but `allow_private_hosts` skips the
/// safe-hostname filter so `#[cfg(test)]` mock servers (loopback, no dots)
/// can act as referral targets. Production callers pass the client's
/// `allow_private_hosts`, which is always false outside test builds.
fn extract_referral_with(response: &str, allow_private_hosts: bool) -> Option<String> {
    for re in REFERRAL_PATTERNS.iter() {
        if let Some(caps) = re.captures(response) {
            if let Some(m) = caps.get(1) {
                let server = m.as_str().trim().to_lowercase();
                if allow_private_hosts || is_safe_whois_server(&server) {
                    return Some(server);
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_config_applies_whois_timeout() {
        let mut config = crate::config::SeerConfig::default();
        config.timeouts.whois_secs = 42;
        let client = WhoisClient::from_config(&config);
        assert_eq!(client.timeout, Duration::from_secs(42));
    }

    #[test]
    fn test_normalize_domain() {
        assert_eq!(normalize_domain("example.com").unwrap(), "example.com");
        assert_eq!(normalize_domain("EXAMPLE.COM").unwrap(), "example.com");
        assert_eq!(
            normalize_domain("https://www.example.com/path").unwrap(),
            "example.com"
        );
        assert!(normalize_domain("invalid").is_err());
    }

    #[test]
    fn test_default_client_has_retry_policy() {
        let client = WhoisClient::new();
        assert_eq!(client.retry_policy.max_attempts, 3);
    }

    #[test]
    fn extract_referral_same_line_value() {
        let response = "Registrar WHOIS Server: whois.registrar.example\n";
        assert_eq!(
            extract_referral(response),
            Some("whois.registrar.example".to_string())
        );
    }

    #[test]
    fn extract_referral_empty_key_line_does_not_capture_next_line() {
        // An empty `Registrar WHOIS Server:` line must NOT capture the
        // following line's content as the referral server.
        let response = "Registrar WHOIS Server:\nwhois.victim.example\n";
        assert_eq!(
            extract_referral(response),
            None,
            "empty referral key line must not swallow the next line"
        );
    }

    #[test]
    fn test_client_without_retries() {
        let client = WhoisClient::new().without_retries();
        assert_eq!(client.retry_policy.max_attempts, 1);
    }

    #[test]
    fn test_client_custom_retry_policy() {
        let policy = RetryPolicy::new().with_max_attempts(5);
        let client = WhoisClient::new().with_retry_policy(policy);
        assert_eq!(client.retry_policy.max_attempts, 5);
    }

    #[tokio::test]
    async fn query_server_internal_rejects_crlf_in_query() {
        // CR in query should be rejected before any TCP connect.
        let err = query_server_internal(
            "whois.example.com",
            "example.com\r\nWHOIS evil.example",
            Duration::from_secs(1),
        )
        .await
        .expect_err("CRLF in query must be rejected");
        match err {
            SeerError::WhoisError(msg) => {
                assert!(msg.contains("CR/LF/NUL"), "unexpected message: {msg}");
            }
            other => panic!("expected WhoisError, got {other:?}"),
        }

        // LF-only and NUL should also be rejected.
        assert!(
            query_server_internal("whois.example.com", "a\nb", Duration::from_secs(1))
                .await
                .is_err()
        );
        assert!(
            query_server_internal("whois.example.com", "a\0b", Duration::from_secs(1))
                .await
                .is_err()
        );
    }

    #[test]
    fn iana_discovery_rejects_unsafe_server() {
        // extract_iana_whois_server returns the value verbatim (lowercased).
        // discover_whois_server_with_retry is expected to reject anything that
        // fails is_safe_whois_server before caching it.
        let synthetic = "refer: whois.iana.org\nwhois: 127.0.0.1\n";
        let extracted = extract_iana_whois_server(synthetic);
        assert_eq!(extracted.as_deref(), Some("127.0.0.1"));

        // is_safe_whois_server must reject loopback IP literals, which is
        // what the discovery wrapper now enforces before caching.
        assert!(
            !is_safe_whois_server(&extracted.unwrap()),
            "is_safe_whois_server must reject 127.0.0.1"
        );

        // Sanity: hostnames with CR/LF or illegal chars are also rejected.
        assert!(!is_safe_whois_server("whois.evil.com\r\nevil"));
        assert!(!is_safe_whois_server("whois.evil.com:4444"));

        // A legitimate hostname is accepted.
        assert!(is_safe_whois_server("whois.nic.xyz"));
    }

    // H13 regression: with MAX_REFERRAL_DEPTH = 3, exactly 3 servers should be
    // queried across a longer referral chain. Verifying this end-to-end
    // requires mocking TCP WHOIS servers. The depth check in
    // `lookup_with_referrals` now fires BEFORE `query_server_with_retry`, so
    // the sequence 0 -> 1 -> 2 (each queries) then 3 (rejected pre-query)
    // consults exactly MAX_REFERRAL_DEPTH servers. See the diff for
    // Batch 5 / H13 for the fix location.

    #[tokio::test]
    async fn whois_refuses_loopback_server() {
        // Feeding 127.0.0.1 as the server must be rejected by
        // validate_public_host BEFORE any TCP connect is attempted.
        let err = query_server_internal("127.0.0.1", "example.com", Duration::from_secs(1))
            .await
            .expect_err("loopback server must be rejected");
        match err {
            SeerError::InvalidInput(msg) => {
                assert!(
                    msg.contains("reserved") || msg.contains("127.0.0.1"),
                    "unexpected message: {msg}"
                );
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn whois_refuses_rfc1918_server() {
        // Feeding an RFC1918 address must be rejected by validate_public_host
        // BEFORE any TCP connect is attempted.
        let err = query_server_internal("10.0.0.1", "example.com", Duration::from_secs(1))
            .await
            .expect_err("RFC1918 server must be rejected");
        match err {
            SeerError::InvalidInput(msg) => {
                assert!(
                    msg.contains("reserved") || msg.contains("10.0.0.1"),
                    "unexpected message: {msg}"
                );
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn whois_refuses_link_local_metadata_server() {
        // The cloud metadata address 169.254.169.254 must also be rejected.
        let err = query_server_internal("169.254.169.254", "example.com", Duration::from_secs(1))
            .await
            .expect_err("link-local metadata server must be rejected");
        assert!(matches!(err, SeerError::InvalidInput(_)));
    }

    // ---- deterministic mock-server tests -----------------------------------
    //
    // These run a real TCP listener on 127.0.0.1 and exercise the full client
    // path (connect → query → read-to-EOF → parse → referral logic) without
    // touching the network. The SSRF guards deliberately refuse loopback, so
    // the client under test uses the `#[cfg(test)]`-only `allowing_private_hosts`
    // / `with_port` seams, which do not exist in release builds.

    /// Serves one canned WHOIS response per accepted connection, in order,
    /// then stops accepting. Returns the bound port.
    async fn spawn_mock_whois(responses: Vec<&'static str>) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            for response in responses {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = [0u8; 512];
                let _ = sock.read(&mut buf).await; // consume "domain\r\n"
                let _ = sock.write_all(response.as_bytes()).await;
                // drop(sock) → FIN → client reads to EOF
            }
        });
        port
    }

    fn mock_client(port: u16) -> WhoisClient {
        WhoisClient::new()
            .without_retries()
            .allowing_private_hosts()
            .with_port(port)
    }

    #[tokio::test]
    async fn mock_basic_lookup_parses_canned_response() {
        let port = spawn_mock_whois(vec![
            "Domain Name: EXAMPLE.COM\nRegistrar: Mock Registrar Inc.\nCreation Date: 2020-01-01T00:00:00Z\n",
        ])
        .await;
        let resp = mock_client(port)
            .lookup_with_server("example.com", "127.0.0.1")
            .await
            .unwrap();
        assert_eq!(resp.registrar.as_deref(), Some("Mock Registrar Inc."));
    }

    #[tokio::test]
    async fn mock_referral_is_followed_when_registry_response_is_thin() {
        // Registry response (127.0.0.1) lacks core data and refers to
        // "localhost"; both names resolve to the same fixture, which serves
        // the responses in connection order.
        let port = spawn_mock_whois(vec![
            "Registry data follows.\nRegistrar WHOIS Server: localhost\n",
            "Domain Name: EXAMPLE.COM\nRegistrar: Mock Registrar Two\nCreation Date: 2021-02-02T00:00:00Z\n",
        ])
        .await;
        let client = mock_client(port);
        let mut visited = HashSet::new();
        let resp = client
            .lookup_with_referrals("example.com", "127.0.0.1", 0, &mut visited)
            .await
            .unwrap();
        assert_eq!(resp.registrar.as_deref(), Some("Mock Registrar Two"));
        assert_eq!(resp.whois_server, "localhost");
    }

    #[tokio::test]
    async fn mock_circular_referral_terminates_with_last_response() {
        // A (127.0.0.1) refers to B (localhost); B refers back to A, which is
        // already in the visited set. The chain must terminate gracefully —
        // returning B's response — instead of looping or erroring.
        let port = spawn_mock_whois(vec![
            "Registry data follows.\nRegistrar WHOIS Server: localhost\n",
            "Registrar data follows.\nRegistrar WHOIS Server: 127.0.0.1\n",
        ])
        .await;
        let client = mock_client(port);
        let mut visited = HashSet::new();
        let resp = client
            .lookup_with_referrals("example.com", "127.0.0.1", 0, &mut visited)
            .await
            .unwrap();
        assert_eq!(resp.whois_server, "localhost");
    }

    #[tokio::test]
    async fn mock_silent_server_times_out() {
        // Listener accepts but never writes: the read deadline must surface
        // as SeerError::Timeout rather than hanging.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let Ok((_sock, _)) = listener.accept().await else {
                return;
            };
            tokio::time::sleep(Duration::from_secs(10)).await;
        });
        let client = mock_client(port).with_timeout(Duration::from_millis(200));
        let err = client
            .lookup_with_server("example.com", "127.0.0.1")
            .await
            .unwrap_err();
        assert!(matches!(err, SeerError::Timeout(_)), "got: {err:?}");
    }
}
