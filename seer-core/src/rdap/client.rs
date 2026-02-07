use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{debug, instrument, warn};

use super::types::RdapResponse;
use crate::error::{Result, SeerError};
use crate::retry::{RetryExecutor, RetryPolicy};
use crate::validation::normalize_domain;

const IANA_BOOTSTRAP_DNS: &str = "https://data.iana.org/rdap/dns.json";
const IANA_BOOTSTRAP_IPV4: &str = "https://data.iana.org/rdap/ipv4.json";
const IANA_BOOTSTRAP_IPV6: &str = "https://data.iana.org/rdap/ipv6.json";
const IANA_BOOTSTRAP_ASN: &str = "https://data.iana.org/rdap/asn.json";

/// Default timeout for RDAP queries (30 seconds).
/// RDAP servers can be slow, especially during bootstrap loading which fetches
/// from 4 IANA registries. Some regional registries also have high latency.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// TTL for bootstrap data (24 hours)
const BOOTSTRAP_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Shared HTTP client for all RDAP operations (bootstrap + queries).
/// Reusing a single Client enables connection pooling across requests.
static RDAP_HTTP_CLIENT: Lazy<Client> = Lazy::new(|| {
    Client::builder()
        .timeout(DEFAULT_TIMEOUT)
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

/// Parsed IANA bootstrap data
struct BootstrapData {
    dns: HashMap<String, String>,
    ipv4: Vec<(IpRange, String)>,
    ipv6: Vec<(IpRange, String)>,
    asn: Vec<(AsnRange, String)>,
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
    fn get_rdap_url_for_domain(cache: &BootstrapData, domain: &str) -> Option<String> {
        let tld = domain.rsplit('.').next()?;
        cache.dns.get(&tld.to_lowercase()).cloned()
    }

    /// Looks up the RDAP server URL for an IP address from bootstrap data.
    fn get_rdap_url_for_ip(cache: &BootstrapData, ip: &IpAddr) -> Option<String> {
        match ip {
            IpAddr::V4(addr) => {
                for (range, url) in &cache.ipv4 {
                    if ipv4_matches_prefix(&range.prefix, addr) {
                        return Some(url.clone());
                    }
                }
            }
            IpAddr::V6(addr) => {
                for (range, url) in &cache.ipv6 {
                    if ipv6_matches_prefix(&range.prefix, addr) {
                        return Some(url.clone());
                    }
                }
            }
        }

        None
    }

    /// Looks up the RDAP server URL for an ASN from bootstrap data.
    fn get_rdap_url_for_asn(cache: &BootstrapData, asn: u32) -> Option<String> {
        for (range, url) in &cache.asn {
            if asn >= range.start && asn <= range.end {
                return Some(url.clone());
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

            format!("{}domain/{}", ensure_trailing_slash(&base_url), domain)
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

            format!("{}ip/{}", ensure_trailing_slash(&base_url), ip)
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

            format!("{}autnum/{}", ensure_trailing_slash(&base_url), asn)
        }; // Lock released here

        debug!(url = %url, "Querying RDAP");
        self.query_rdap_with_retry(&url).await
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

/// Internal function to query an RDAP endpoint (used by retry executor).
async fn query_rdap_internal(http: &Client, url: &str) -> Result<RdapResponse> {
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

    let rdap: RdapResponse = response.json().await?;
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

    let http = &*RDAP_HTTP_CLIENT;

    let dns_future = http.get(IANA_BOOTSTRAP_DNS).send();
    let ipv4_future = http.get(IANA_BOOTSTRAP_IPV4).send();
    let ipv6_future = http.get(IANA_BOOTSTRAP_IPV6).send();
    let asn_future = http.get(IANA_BOOTSTRAP_ASN).send();

    let (dns_resp, ipv4_resp, ipv6_resp, asn_resp) =
        tokio::try_join!(dns_future, ipv4_future, ipv6_future, asn_future)?;

    let dns_data: BootstrapResponse = dns_resp.json().await?;
    let ipv4_data: BootstrapResponse = ipv4_resp.json().await?;
    let ipv6_data: BootstrapResponse = ipv6_resp.json().await?;
    let asn_data: BootstrapResponse = asn_resp.json().await?;

    let mut dns = HashMap::new();
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    let mut asn = Vec::new();

    // Parse DNS bootstrap
    for service in dns_data.services {
        if service.len() >= 2 {
            if let (Some(tlds), Some(urls)) = (service[0].as_array(), service[1].as_array()) {
                if let Some(url) = urls.first().and_then(|u| u.as_str()) {
                    let url_string = url.to_string();
                    for tld in tlds {
                        if let Some(tld_str) = tld.as_str() {
                            dns.insert(tld_str.to_lowercase(), url_string.clone());
                        }
                    }
                }
            }
        }
    }

    // Parse IPv4 bootstrap
    for service in ipv4_data.services {
        if service.len() >= 2 {
            if let (Some(prefixes), Some(urls)) = (service[0].as_array(), service[1].as_array()) {
                if let Some(url) = urls.first().and_then(|u| u.as_str()) {
                    let url_string = url.to_string();
                    for prefix in prefixes {
                        if let Some(prefix_str) = prefix.as_str() {
                            ipv4.push((
                                IpRange {
                                    prefix: prefix_str.to_string(),
                                },
                                url_string.clone(),
                            ));
                        }
                    }
                }
            }
        }
    }

    // Parse IPv6 bootstrap
    for service in ipv6_data.services {
        if service.len() >= 2 {
            if let (Some(prefixes), Some(urls)) = (service[0].as_array(), service[1].as_array()) {
                if let Some(url) = urls.first().and_then(|u| u.as_str()) {
                    let url_string = url.to_string();
                    for prefix in prefixes {
                        if let Some(prefix_str) = prefix.as_str() {
                            ipv6.push((
                                IpRange {
                                    prefix: prefix_str.to_string(),
                                },
                                url_string.clone(),
                            ));
                        }
                    }
                }
            }
        }
    }

    // Parse ASN bootstrap
    for service in asn_data.services {
        if service.len() >= 2 {
            if let (Some(ranges), Some(urls)) = (service[0].as_array(), service[1].as_array()) {
                if let Some(url) = urls.first().and_then(|u| u.as_str()) {
                    let url_string = url.to_string();
                    for range in ranges {
                        if let Some(range_str) = range.as_str() {
                            if let Some((start, end)) = parse_asn_range(range_str) {
                                asn.push((AsnRange { start, end }, url_string.clone()));
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

fn ensure_trailing_slash(url: &str) -> String {
    if url.ends_with('/') {
        url.to_string()
    } else {
        format!("{}/", url)
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
}
