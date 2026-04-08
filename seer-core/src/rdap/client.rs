use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt;
use once_cell::sync::Lazy;
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{debug, instrument, warn};

use super::types::RdapResponse;
use crate::error::{Result, SeerError};
use crate::retry::{RetryExecutor, RetryPolicy};
use crate::validation::{describe_reserved_ip, normalize_domain};

const IANA_BOOTSTRAP_DNS: &str = "https://data.iana.org/rdap/dns.json";
const IANA_BOOTSTRAP_IPV4: &str = "https://data.iana.org/rdap/ipv4.json";
const IANA_BOOTSTRAP_IPV6: &str = "https://data.iana.org/rdap/ipv6.json";
const IANA_BOOTSTRAP_ASN: &str = "https://data.iana.org/rdap/asn.json";

/// Default timeout for RDAP queries (30 seconds).
/// RDAP servers can be slow, especially during bootstrap loading which fetches
/// from 4 IANA registries. Some regional registries also have high latency.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Connect timeout — fail fast when a host is unreachable rather than
/// waiting the full request timeout on a TCP handshake that will never complete.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// TTL for bootstrap data (24 hours)
const BOOTSTRAP_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Shared HTTP client for all RDAP operations (bootstrap + queries).
/// Reusing a single Client enables connection pooling across requests.
static RDAP_HTTP_CLIENT: Lazy<Client> = Lazy::new(|| {
    Client::builder()
        .timeout(DEFAULT_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .user_agent("Seer/1.0 (RDAP Client)")
        .pool_max_idle_per_host(10)
        .build()
        .expect("Failed to build RDAP HTTP client - invalid configuration")
});

/// Bootstrap cache with TTL support
static BOOTSTRAP_CACHE: Lazy<RwLock<Option<CachedBootstrap>>> = Lazy::new(|| RwLock::new(None));

/// Cached bootstrap data with timestamp for TTL tracking
struct CachedBootstrap {
    data: BootstrapData,
    loaded_at: Instant,
}

impl CachedBootstrap {
    fn new(data: BootstrapData) -> Self {
        Self {
            data,
            loaded_at: Instant::now(),
        }
    }

    fn is_expired(&self) -> bool {
        self.loaded_at.elapsed() > BOOTSTRAP_TTL
    }

    fn age(&self) -> Duration {
        self.loaded_at.elapsed()
    }
}

/// Parsed IANA bootstrap data.
/// Uses Arc<str> for URL strings to reduce cloning overhead when multiple
/// TLDs/prefixes share the same RDAP server URL.
struct BootstrapData {
    dns: HashMap<String, Arc<str>>,
    ipv4: Vec<(IpRange, Arc<str>)>,
    ipv6: Vec<(IpRange, Arc<str>)>,
    asn: Vec<(AsnRange, Arc<str>)>,
}

#[derive(Clone)]
struct IpRange {
    prefix: String,
}

#[derive(Clone)]
struct AsnRange {
    start: u32,
    end: u32,
}

#[derive(Deserialize)]
struct BootstrapResponse {
    services: Vec<Vec<serde_json::Value>>,
}

#[derive(Debug, Clone)]
pub struct RdapClient {
    retry_policy: RetryPolicy,
}

impl Default for RdapClient {
    fn default() -> Self {
        Self::new()
    }
}

impl RdapClient {
    /// Creates a new RDAP client with default settings.
    pub fn new() -> Self {
        Self {
            retry_policy: RetryPolicy::default(),
        }
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

    /// Ensures bootstrap data is loaded and not expired.
    /// Uses stale-while-revalidate: if refresh fails, stale data is used.
    async fn ensure_bootstrap(&self) -> Result<()> {
        // Check if we have valid (non-expired) data
        {
            let cache = BOOTSTRAP_CACHE.read().await;
            if let Some(cached) = cache.as_ref() {
                if !cached.is_expired() {
                    return Ok(());
                }
            }
        }

        // Need to load or refresh - acquire write lock
        let mut cache = BOOTSTRAP_CACHE.write().await;

        // Double-check after acquiring write lock (another task may have loaded)
        if let Some(cached) = cache.as_ref() {
            if !cached.is_expired() {
                return Ok(());
            }
        }

        // Try to load fresh data
        debug!("Loading/refreshing RDAP bootstrap data");
        match load_bootstrap_data_with_retry(&self.retry_policy).await {
            Ok(data) => {
                debug!(
                    dns_entries = data.dns.len(),
                    ipv4_entries = data.ipv4.len(),
                    ipv6_entries = data.ipv6.len(),
                    asn_entries = data.asn.len(),
                    "RDAP bootstrap loaded/refreshed"
                );
                *cache = Some(CachedBootstrap::new(data));
                Ok(())
            }
            Err(e) => {
                // Stale-while-revalidate: use stale data if refresh fails
                if let Some(cached) = cache.as_ref() {
                    warn!(
                        error = %e,
                        age_hours = cached.age().as_secs() / 3600,
                        "Bootstrap refresh failed, using stale data"
                    );
                    Ok(())
                } else {
                    // No stale data available
                    Err(e)
                }
            }
        }
    }

    /// Looks up the RDAP server URL for a domain's TLD from bootstrap data.
    fn get_rdap_url_for_domain(cache: &BootstrapData, domain: &str) -> Option<Arc<str>> {
        let tld = domain.rsplit('.').next()?;
        cache.dns.get(&tld.to_lowercase()).cloned()
    }

    /// Looks up the RDAP server URL for an IP address from bootstrap data.
    fn get_rdap_url_for_ip(cache: &BootstrapData, ip: &IpAddr) -> Option<Arc<str>> {
        match ip {
            IpAddr::V4(addr) => {
                for (range, url) in &cache.ipv4 {
                    if ipv4_matches_prefix(&range.prefix, addr) {
                        return Some(Arc::clone(url));
                    }
                }
            }
            IpAddr::V6(addr) => {
                for (range, url) in &cache.ipv6 {
                    if ipv6_matches_prefix(&range.prefix, addr) {
                        return Some(Arc::clone(url));
                    }
                }
            }
        }

        None
    }

    /// Looks up the RDAP server URL for an ASN from bootstrap data.
    fn get_rdap_url_for_asn(cache: &BootstrapData, asn: u32) -> Option<Arc<str>> {
        for (range, url) in &cache.asn {
            if asn >= range.start && asn <= range.end {
                return Some(Arc::clone(url));
            }
        }

        None
    }

    /// Looks up RDAP registration data for a domain.
    ///
    /// Uses IANA bootstrap data to find the appropriate RDAP server for the TLD.
    #[instrument(skip(self), fields(domain = %domain))]
    pub async fn lookup_domain(&self, domain: &str) -> Result<RdapResponse> {
        self.ensure_bootstrap().await?;

        let domain = normalize_domain(domain)?;

        // Extract URL while holding the lock, then release before HTTP request
        let url = {
            let cache_guard = BOOTSTRAP_CACHE.read().await;
            let cache = cache_guard.as_ref().ok_or_else(|| {
                SeerError::RdapBootstrapError("bootstrap data not loaded".to_string())
            })?;

            let base_url =
                Self::get_rdap_url_for_domain(&cache.data, &domain).ok_or_else(|| {
                    SeerError::RdapBootstrapError(format!("no RDAP server for {}", domain))
                })?;

            build_rdap_url(&base_url, &format!("domain/{}", domain))
        }; // Lock released here

        debug!(url = %url, "Querying RDAP");
        self.query_rdap_with_retry(&url).await
    }

    /// Looks up RDAP registration data for an IP address.
    ///
    /// Uses IANA bootstrap data to find the appropriate RIR (Regional Internet Registry).
    #[instrument(skip(self), fields(ip = %ip))]
    pub async fn lookup_ip(&self, ip: &str) -> Result<RdapResponse> {
        self.ensure_bootstrap().await?;

        let ip_addr: IpAddr = ip
            .parse()
            .map_err(|_| SeerError::InvalidIpAddress(ip.to_string()))?;

        // Extract URL while holding the lock, then release before HTTP request
        let url = {
            let cache_guard = BOOTSTRAP_CACHE.read().await;
            let cache = cache_guard.as_ref().ok_or_else(|| {
                SeerError::RdapBootstrapError("bootstrap data not loaded".to_string())
            })?;

            let base_url = Self::get_rdap_url_for_ip(&cache.data, &ip_addr).ok_or_else(|| {
                SeerError::RdapBootstrapError(format!("no RDAP server for {}", ip))
            })?;

            build_rdap_url(&base_url, &format!("ip/{}", ip))
        }; // Lock released here

        debug!(url = %url, "Querying RDAP");
        self.query_rdap_with_retry(&url).await
    }

    /// Looks up RDAP registration data for an Autonomous System Number (ASN).
    ///
    /// Uses IANA bootstrap data to find the appropriate RIR for the ASN range.
    #[instrument(skip(self), fields(asn = %asn))]
    pub async fn lookup_asn(&self, asn: u32) -> Result<RdapResponse> {
        self.ensure_bootstrap().await?;

        // Extract URL while holding the lock, then release before HTTP request
        let url = {
            let cache_guard = BOOTSTRAP_CACHE.read().await;
            let cache = cache_guard.as_ref().ok_or_else(|| {
                SeerError::RdapBootstrapError("bootstrap data not loaded".to_string())
            })?;

            let base_url = Self::get_rdap_url_for_asn(&cache.data, asn).ok_or_else(|| {
                SeerError::RdapBootstrapError(format!("no RDAP server for AS{}", asn))
            })?;

            build_rdap_url(&base_url, &format!("autnum/{}", asn))
        }; // Lock released here

        debug!(url = %url, "Querying RDAP");
        self.query_rdap_with_retry(&url).await
    }

    /// Returns the RDAP base URL for a given TLD, if known from bootstrap data.
    ///
    /// Loads bootstrap data if not already cached. Returns `None` if the TLD
    /// has no registered RDAP server in the IANA bootstrap registry.
    #[instrument(skip(self), fields(tld = %tld))]
    pub async fn get_rdap_base_url_for_tld(&self, tld: &str) -> Option<String> {
        if self.ensure_bootstrap().await.is_err() {
            return None;
        }

        let cache_guard = BOOTSTRAP_CACHE.read().await;
        let cache = cache_guard.as_ref()?;
        cache
            .data
            .dns
            .get(&tld.to_lowercase())
            .map(|url| url.to_string())
    }

    /// Queries an RDAP endpoint with retry logic.
    async fn query_rdap_with_retry(&self, url: &str) -> Result<RdapResponse> {
        let executor = RetryExecutor::new(self.retry_policy.clone());
        let url = url.to_string();

        executor
            .execute(|| {
                let http = RDAP_HTTP_CLIENT.clone();
                let url = url.clone();
                async move { query_rdap_internal(&http, &url).await }
            })
            .await
    }
}

/// Maximum RDAP response body size (10 MB, matching CT log response limit).
const MAX_RDAP_RESPONSE_SIZE: usize = 10 * 1024 * 1024;

/// Validates that a URL does not resolve to a reserved/private IP address (SSRF protection).
async fn validate_url_not_reserved(url: &str) -> Result<()> {
    let parsed = url::Url::parse(url)
        .map_err(|e| SeerError::RdapError(format!("invalid URL '{}': {}", url, e)))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| SeerError::RdapError(format!("URL '{}' has no host", url)))?;

    // If the host is already an IP literal, check it directly
    if let Ok(ip) = host.parse::<IpAddr>() {
        if let Some(reason) = describe_reserved_ip(&ip) {
            return Err(SeerError::RdapError(format!(
                "RDAP URL resolves to reserved IP {}: {} — request blocked (SSRF protection)",
                ip, reason
            )));
        }
        return Ok(());
    }

    let port = parsed.port_or_known_default().unwrap_or(443);
    let addr = format!("{}:{}", host, port);

    let socket_addrs: Vec<_> = tokio::net::lookup_host(&addr)
        .await
        .map_err(|e| SeerError::RdapError(format!("failed to resolve host '{}': {}", host, e)))?
        .collect();

    if socket_addrs.is_empty() {
        return Err(SeerError::RdapError(format!(
            "host '{}' resolved to no addresses",
            host
        )));
    }

    for socket_addr in &socket_addrs {
        if let Some(reason) = describe_reserved_ip(&socket_addr.ip()) {
            return Err(SeerError::RdapError(format!(
                "RDAP URL resolves to reserved IP {}: {} — request blocked (SSRF protection)",
                socket_addr.ip(),
                reason
            )));
        }
    }

    Ok(())
}

/// Internal function to query an RDAP endpoint (used by retry executor).
async fn query_rdap_internal(http: &Client, url: &str) -> Result<RdapResponse> {
    // SSRF protection: validate the URL does not resolve to a reserved/private IP
    validate_url_not_reserved(url).await?;

    let response = http
        .get(url)
        .header("Accept", "application/rdap+json")
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(SeerError::RdapError(format!(
            "query failed with status {}",
            response.status()
        )));
    }

    // Stream body with incremental size check to prevent memory exhaustion
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|e| SeerError::RdapError(format!("failed to read response: {}", e)))?;
        body.extend_from_slice(&chunk);
        if body.len() > MAX_RDAP_RESPONSE_SIZE {
            return Err(SeerError::RdapError(format!(
                "RDAP response exceeds {} byte limit",
                MAX_RDAP_RESPONSE_SIZE
            )));
        }
    }
    let rdap: RdapResponse = serde_json::from_slice(&body)?;
    Ok(rdap)
}

/// Loads IANA RDAP bootstrap data from all registries with retry.
async fn load_bootstrap_data_with_retry(policy: &RetryPolicy) -> Result<BootstrapData> {
    let executor = RetryExecutor::new(policy.clone());
    executor.execute(load_bootstrap_data).await
}

/// Loads IANA RDAP bootstrap data from all registries.
async fn load_bootstrap_data() -> Result<BootstrapData> {
    debug!("Loading RDAP bootstrap data from IANA");

    // Defense-in-depth: validate IANA bootstrap URLs don't resolve to reserved IPs
    let bootstrap_urls = [
        IANA_BOOTSTRAP_DNS,
        IANA_BOOTSTRAP_IPV4,
        IANA_BOOTSTRAP_IPV6,
        IANA_BOOTSTRAP_ASN,
    ];
    for url in &bootstrap_urls {
        validate_url_not_reserved(url).await?;
    }

    let http = &*RDAP_HTTP_CLIENT;

    let dns_future = http.get(IANA_BOOTSTRAP_DNS).send();
    let ipv4_future = http.get(IANA_BOOTSTRAP_IPV4).send();
    let ipv6_future = http.get(IANA_BOOTSTRAP_IPV6).send();
    let asn_future = http.get(IANA_BOOTSTRAP_ASN).send();

    // Use join! instead of try_join! so one slow/failing registry doesn't
    // block the others. We load whatever data is available.
    let (dns_resp, ipv4_resp, ipv6_resp, asn_resp) =
        tokio::join!(dns_future, ipv4_future, ipv6_future, asn_future);

    // Stream body with incremental size check to prevent memory exhaustion
    const MAX_BOOTSTRAP_SIZE: usize = 10 * 1024 * 1024; // 10 MB

    async fn read_bootstrap(resp: reqwest::Response) -> Result<BootstrapResponse> {
        let mut body = Vec::new();
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| {
                SeerError::RdapBootstrapError(format!("failed to read body: {}", e))
            })?;
            body.extend_from_slice(&chunk);
            if body.len() > MAX_BOOTSTRAP_SIZE {
                return Err(SeerError::RdapBootstrapError(format!(
                    "bootstrap response too large (exceeds {} bytes)",
                    MAX_BOOTSTRAP_SIZE
                )));
            }
        }
        serde_json::from_slice(&body).map_err(Into::into)
    }

    // Parse each response independently, logging failures
    let dns_data = match dns_resp {
        Ok(resp) => read_bootstrap(resp).await.ok(),
        Err(e) => {
            warn!(error = %e, "Failed to fetch DNS bootstrap from IANA");
            None
        }
    };
    let ipv4_data = match ipv4_resp {
        Ok(resp) => read_bootstrap(resp).await.ok(),
        Err(e) => {
            warn!(error = %e, "Failed to fetch IPv4 bootstrap from IANA");
            None
        }
    };
    let ipv6_data = match ipv6_resp {
        Ok(resp) => read_bootstrap(resp).await.ok(),
        Err(e) => {
            warn!(error = %e, "Failed to fetch IPv6 bootstrap from IANA");
            None
        }
    };
    let asn_data = match asn_resp {
        Ok(resp) => read_bootstrap(resp).await.ok(),
        Err(e) => {
            warn!(error = %e, "Failed to fetch ASN bootstrap from IANA");
            None
        }
    };

    // If ALL four registries failed, that's a real error
    if dns_data.is_none() && ipv4_data.is_none() && ipv6_data.is_none() && asn_data.is_none() {
        return Err(SeerError::RdapBootstrapError(
            "all IANA bootstrap registries failed".to_string(),
        ));
    }

    let mut dns = HashMap::new();
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    let mut asn = Vec::new();

    // Parse DNS bootstrap
    if let Some(dns_data) = dns_data {
        for service in dns_data.services {
            if service.len() >= 2 {
                if let (Some(tlds), Some(urls)) = (service[0].as_array(), service[1].as_array()) {
                    if let Some(url) = urls.first().and_then(|u| u.as_str()) {
                        let url_arc: Arc<str> = Arc::from(url);
                        for tld in tlds {
                            if let Some(tld_str) = tld.as_str() {
                                dns.insert(tld_str.to_lowercase(), Arc::clone(&url_arc));
                            }
                        }
                    }
                }
            }
        }
    }

    // Parse IPv4 bootstrap
    if let Some(ipv4_data) = ipv4_data {
        for service in ipv4_data.services {
            if service.len() >= 2 {
                if let (Some(prefixes), Some(urls)) =
                    (service[0].as_array(), service[1].as_array())
                {
                    if let Some(url) = urls.first().and_then(|u| u.as_str()) {
                        let url_arc: Arc<str> = Arc::from(url);
                        for prefix in prefixes {
                            if let Some(prefix_str) = prefix.as_str() {
                                ipv4.push((
                                    IpRange {
                                        prefix: prefix_str.to_string(),
                                    },
                                    Arc::clone(&url_arc),
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    // Parse IPv6 bootstrap
    if let Some(ipv6_data) = ipv6_data {
        for service in ipv6_data.services {
            if service.len() >= 2 {
                if let (Some(prefixes), Some(urls)) =
                    (service[0].as_array(), service[1].as_array())
                {
                    if let Some(url) = urls.first().and_then(|u| u.as_str()) {
                        let url_arc: Arc<str> = Arc::from(url);
                        for prefix in prefixes {
                            if let Some(prefix_str) = prefix.as_str() {
                                ipv6.push((
                                    IpRange {
                                        prefix: prefix_str.to_string(),
                                    },
                                    Arc::clone(&url_arc),
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    // Parse ASN bootstrap
    if let Some(asn_data) = asn_data {
        for service in asn_data.services {
            if service.len() >= 2 {
                if let (Some(ranges), Some(urls)) = (service[0].as_array(), service[1].as_array())
                {
                    if let Some(url) = urls.first().and_then(|u| u.as_str()) {
                        let url_arc: Arc<str> = Arc::from(url);
                        for range in ranges {
                            if let Some(range_str) = range.as_str() {
                                if let Some((start, end)) = parse_asn_range(range_str) {
                                    asn.push((AsnRange { start, end }, Arc::clone(&url_arc)));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(BootstrapData {
        dns,
        ipv4,
        ipv6,
        asn,
    })
}

/// Builds a full RDAP query URL from a base URL and path.
fn build_rdap_url(base_url: &str, path: &str) -> String {
    if base_url.ends_with('/') {
        format!("{}{}", base_url, path)
    } else {
        format!("{}/{}", base_url, path)
    }
}

fn parse_asn_range(range: &str) -> Option<(u32, u32)> {
    if let Some(pos) = range.find('-') {
        let start = range[..pos].parse().ok()?;
        let end = range[pos + 1..].parse().ok()?;
        Some((start, end))
    } else {
        let num = range.parse().ok()?;
        Some((num, num))
    }
}

fn ipv4_matches_prefix(prefix: &str, ip: &Ipv4Addr) -> bool {
    let (addr_part, mask_part) = match prefix.split_once('/') {
        Some((a, m)) => (a, Some(m)),
        None => (prefix, None),
    };

    let prefix_ip: Ipv4Addr = match addr_part.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    let mask_bits: u32 = match mask_part.and_then(|s| s.parse().ok()) {
        Some(bits) if bits <= 32 => bits,
        Some(_) => return false,
        None => 32,
    };

    let mask = if mask_bits == 0 {
        0
    } else {
        u32::MAX << (32 - mask_bits)
    };

    let ip_value = u32::from(*ip);
    let prefix_value = u32::from(prefix_ip);

    (ip_value & mask) == (prefix_value & mask)
}

fn ipv6_matches_prefix(prefix: &str, ip: &Ipv6Addr) -> bool {
    let (addr_part, mask_part) = match prefix.split_once('/') {
        Some((a, m)) => (a, Some(m)),
        None => (prefix, None),
    };

    let prefix_ip: Ipv6Addr = match addr_part.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    let mask_bits: u32 = match mask_part.and_then(|s| s.parse().ok()) {
        Some(bits) if bits <= 128 => bits,
        Some(_) => return false,
        None => 128,
    };

    let mask = if mask_bits == 0 {
        0u128
    } else {
        u128::MAX << (128 - mask_bits)
    };

    let ip_value = ipv6_to_u128(ip);
    let prefix_value = ipv6_to_u128(&prefix_ip);

    (ip_value & mask) == (prefix_value & mask)
}

fn ipv6_to_u128(ip: &Ipv6Addr) -> u128 {
    let segments = ip.segments();
    let mut value = 0u128;
    for segment in segments {
        value = (value << 16) | segment as u128;
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_client_has_retry_policy() {
        let client = RdapClient::new();
        assert_eq!(client.retry_policy.max_attempts, 3);
    }

    #[test]
    fn test_client_without_retries() {
        let client = RdapClient::new().without_retries();
        assert_eq!(client.retry_policy.max_attempts, 1);
    }

    #[test]
    fn test_client_custom_retry_policy() {
        let policy = RetryPolicy::new().with_max_attempts(5);
        let client = RdapClient::new().with_retry_policy(policy);
        assert_eq!(client.retry_policy.max_attempts, 5);
    }

    #[test]
    fn test_cached_bootstrap_expiration() {
        let data = BootstrapData {
            dns: HashMap::new(),
            ipv4: Vec::new(),
            ipv6: Vec::new(),
            asn: Vec::new(),
        };
        let cached = CachedBootstrap::new(data);
        // Fresh cache should not be expired
        assert!(!cached.is_expired());
    }

    #[test]
    fn test_ipv4_prefix_matching_partial_mask() {
        let ip_in = Ipv4Addr::new(203, 0, 114, 1);
        let ip_out = Ipv4Addr::new(203, 0, 120, 1);
        assert!(ipv4_matches_prefix("203.0.112.0/21", &ip_in));
        assert!(!ipv4_matches_prefix("203.0.112.0/21", &ip_out));
    }

    #[test]
    fn test_ipv6_prefix_matching_partial_mask() {
        let ip_in: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let ip_out: Ipv6Addr = "2001:db9::1".parse().unwrap();
        assert!(ipv6_matches_prefix("2001:db8::/33", &ip_in));
        assert!(!ipv6_matches_prefix("2001:db8::/33", &ip_out));
    }

    #[test]
    fn test_rdap_http_client_is_configured() {
        // Force lazy initialization and verify it doesn't panic
        let _client = &*RDAP_HTTP_CLIENT;
    }

    #[test]
    fn test_parse_bootstrap_empty_services() {
        // Verifies that parsing empty bootstrap data doesn't panic
        let data = BootstrapData {
            dns: HashMap::new(),
            ipv4: Vec::new(),
            ipv6: Vec::new(),
            asn: Vec::new(),
        };
        // Should return None for any lookup on empty data
        assert!(RdapClient::get_rdap_url_for_domain(&data, "example.com").is_none());
        assert!(RdapClient::get_rdap_url_for_asn(&data, 12345).is_none());
    }
}
