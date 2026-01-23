use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::Duration;

use once_cell::sync::Lazy;
use reqwest::Client;
use serde::Deserialize;
use tracing::{debug, instrument};

use super::types::RdapResponse;
use crate::error::{Result, SeerError};
use crate::validation::normalize_domain;

const IANA_BOOTSTRAP_DNS: &str = "https://data.iana.org/rdap/dns.json";
const IANA_BOOTSTRAP_IPV4: &str = "https://data.iana.org/rdap/ipv4.json";
const IANA_BOOTSTRAP_IPV6: &str = "https://data.iana.org/rdap/ipv6.json";
const IANA_BOOTSTRAP_ASN: &str = "https://data.iana.org/rdap/asn.json";

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

static BOOTSTRAP_CACHE: Lazy<RwLock<BootstrapCache>> =
    Lazy::new(|| RwLock::new(BootstrapCache::default()));

#[derive(Default)]
struct BootstrapCache {
    dns: HashMap<String, String>,
    ipv4: Vec<(IpRange, String)>,
    ipv6: Vec<(IpRange, String)>,
    asn: Vec<(AsnRange, String)>,
    initialized: bool,
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
    http: Client,
    timeout: Duration,
}

impl Default for RdapClient {
    fn default() -> Self {
        Self::new()
    }
}

impl RdapClient {
    pub fn new() -> Self {
        let http = Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .user_agent("Seer/1.0 (RDAP Client)")
            .build()
            .expect("Failed to build HTTP client");

        Self {
            http,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    async fn ensure_bootstrap(&self) -> Result<()> {
        {
            let cache = BOOTSTRAP_CACHE
                .read()
                .map_err(|_| SeerError::RdapError("Bootstrap cache lock poisoned".to_string()))?;
            if cache.initialized {
                return Ok(());
            }
        }

        self.load_bootstrap().await
    }

    async fn load_bootstrap(&self) -> Result<()> {
        debug!("Loading RDAP bootstrap data from IANA");

        let dns_future = self.http.get(IANA_BOOTSTRAP_DNS).send();
        let ipv4_future = self.http.get(IANA_BOOTSTRAP_IPV4).send();
        let ipv6_future = self.http.get(IANA_BOOTSTRAP_IPV6).send();
        let asn_future = self.http.get(IANA_BOOTSTRAP_ASN).send();

        let (dns_resp, ipv4_resp, ipv6_resp, asn_resp) =
            tokio::try_join!(dns_future, ipv4_future, ipv6_future, asn_future)?;

        let dns_data: BootstrapResponse = dns_resp.json().await?;
        let ipv4_data: BootstrapResponse = ipv4_resp.json().await?;
        let ipv6_data: BootstrapResponse = ipv6_resp.json().await?;
        let asn_data: BootstrapResponse = asn_resp.json().await?;

        let mut cache = BOOTSTRAP_CACHE
            .write()
            .map_err(|_| SeerError::RdapError("Bootstrap cache lock poisoned".to_string()))?;

        // Parse DNS bootstrap
        for service in dns_data.services {
            if service.len() >= 2 {
                if let (Some(tlds), Some(urls)) = (service[0].as_array(), service[1].as_array()) {
                    if let Some(url) = urls.first().and_then(|u| u.as_str()) {
                        for tld in tlds {
                            if let Some(tld_str) = tld.as_str() {
                                cache.dns.insert(tld_str.to_lowercase(), url.to_string());
                            }
                        }
                    }
                }
            }
        }

        // Parse IPv4 bootstrap
        for service in ipv4_data.services {
            if service.len() >= 2 {
                if let (Some(prefixes), Some(urls)) = (service[0].as_array(), service[1].as_array())
                {
                    if let Some(url) = urls.first().and_then(|u| u.as_str()) {
                        for prefix in prefixes {
                            if let Some(prefix_str) = prefix.as_str() {
                                cache.ipv4.push((
                                    IpRange {
                                        prefix: prefix_str.to_string(),
                                    },
                                    url.to_string(),
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
                if let (Some(prefixes), Some(urls)) = (service[0].as_array(), service[1].as_array())
                {
                    if let Some(url) = urls.first().and_then(|u| u.as_str()) {
                        for prefix in prefixes {
                            if let Some(prefix_str) = prefix.as_str() {
                                cache.ipv6.push((
                                    IpRange {
                                        prefix: prefix_str.to_string(),
                                    },
                                    url.to_string(),
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
                        for range in ranges {
                            if let Some(range_str) = range.as_str() {
                                if let Some((start, end)) = parse_asn_range(range_str) {
                                    cache.asn.push((AsnRange { start, end }, url.to_string()));
                                }
                            }
                        }
                    }
                }
            }
        }

        cache.initialized = true;
        debug!(
            dns_entries = cache.dns.len(),
            ipv4_entries = cache.ipv4.len(),
            ipv6_entries = cache.ipv6.len(),
            asn_entries = cache.asn.len(),
            "RDAP bootstrap loaded"
        );

        Ok(())
    }

    fn get_rdap_url_for_domain(&self, domain: &str) -> Option<String> {
        let cache = BOOTSTRAP_CACHE.read().ok()?;
        let tld = domain.rsplit('.').next()?;
        cache.dns.get(&tld.to_lowercase()).cloned()
    }

    fn get_rdap_url_for_ip(&self, ip: &IpAddr) -> Option<String> {
        let cache = BOOTSTRAP_CACHE.read().ok()?;

        match ip {
            IpAddr::V4(addr) => {
                let octets = addr.octets();
                for (range, url) in &cache.ipv4 {
                    if ip_matches_prefix(&range.prefix, &octets) {
                        return Some(url.clone());
                    }
                }
            }
            IpAddr::V6(addr) => {
                let segments = addr.segments();
                for (range, url) in &cache.ipv6 {
                    if ipv6_matches_prefix(&range.prefix, &segments) {
                        return Some(url.clone());
                    }
                }
            }
        }

        None
    }

    fn get_rdap_url_for_asn(&self, asn: u32) -> Option<String> {
        let cache = BOOTSTRAP_CACHE.read().ok()?;

        for (range, url) in &cache.asn {
            if asn >= range.start && asn <= range.end {
                return Some(url.clone());
            }
        }

        None
    }

    #[instrument(skip(self), fields(domain = %domain))]
    pub async fn lookup_domain(&self, domain: &str) -> Result<RdapResponse> {
        self.ensure_bootstrap().await?;

        let domain = normalize_domain(domain)?;
        let base_url = self
            .get_rdap_url_for_domain(&domain)
            .ok_or_else(|| SeerError::RdapBootstrapError(format!("No RDAP server for {}", domain)))?;

        let url = format!("{}domain/{}", ensure_trailing_slash(&base_url), domain);
        debug!(url = %url, "Querying RDAP");

        let response = self
            .http
            .get(&url)
            .header("Accept", "application/rdap+json")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(SeerError::RdapError(format!(
                "RDAP query failed with status {}",
                response.status()
            )));
        }

        let rdap: RdapResponse = response.json().await?;
        Ok(rdap)
    }

    #[instrument(skip(self), fields(ip = %ip))]
    pub async fn lookup_ip(&self, ip: &str) -> Result<RdapResponse> {
        self.ensure_bootstrap().await?;

        let ip_addr: IpAddr = ip
            .parse()
            .map_err(|_| SeerError::InvalidIpAddress(ip.to_string()))?;

        let base_url = self
            .get_rdap_url_for_ip(&ip_addr)
            .ok_or_else(|| SeerError::RdapBootstrapError(format!("No RDAP server for {}", ip)))?;

        let url = format!("{}ip/{}", ensure_trailing_slash(&base_url), ip);
        debug!(url = %url, "Querying RDAP");

        let response = self
            .http
            .get(&url)
            .header("Accept", "application/rdap+json")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(SeerError::RdapError(format!(
                "RDAP query failed with status {}",
                response.status()
            )));
        }

        let rdap: RdapResponse = response.json().await?;
        Ok(rdap)
    }

    #[instrument(skip(self), fields(asn = %asn))]
    pub async fn lookup_asn(&self, asn: u32) -> Result<RdapResponse> {
        self.ensure_bootstrap().await?;

        let base_url = self
            .get_rdap_url_for_asn(asn)
            .ok_or_else(|| SeerError::RdapBootstrapError(format!("No RDAP server for AS{}", asn)))?;

        let url = format!("{}autnum/{}", ensure_trailing_slash(&base_url), asn);
        debug!(url = %url, "Querying RDAP");

        let response = self
            .http
            .get(&url)
            .header("Accept", "application/rdap+json")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(SeerError::RdapError(format!(
                "RDAP query failed with status {}",
                response.status()
            )));
        }

        let rdap: RdapResponse = response.json().await?;
        Ok(rdap)
    }
}

// Domain normalization is now handled by the shared validation module

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

fn ip_matches_prefix(prefix: &str, octets: &[u8; 4]) -> bool {
    let parts: Vec<&str> = prefix.split('/').collect();
    if parts.is_empty() {
        return false;
    }

    let prefix_octets: Vec<u8> = parts[0]
        .split('.')
        .filter_map(|s| s.parse().ok())
        .collect();

    if prefix_octets.is_empty() {
        return false;
    }

    // Validate and clamp mask_bits to valid IPv4 range (0-32)
    let mask_bits: usize = parts
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(8)
        .min(32);
    let full_octets = mask_bits / 8;

    for (i, &octet) in octets.iter().enumerate().take(full_octets.min(prefix_octets.len())) {
        if prefix_octets.get(i) != Some(&octet) {
            return false;
        }
    }

    true
}

fn ipv6_matches_prefix(prefix: &str, segments: &[u16; 8]) -> bool {
    let parts: Vec<&str> = prefix.split('/').collect();
    if parts.is_empty() {
        return false;
    }

    // Parse IPv6 prefix (simplified)
    let prefix_str = parts[0];
    if let Ok(addr) = prefix_str.parse::<std::net::Ipv6Addr>() {
        let prefix_segments = addr.segments();
        // Validate and clamp mask_bits to valid IPv6 range (0-128)
        let mask_bits: usize = parts
            .get(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(48)
            .min(128);
        let full_segments = mask_bits / 16;

        for (i, &segment) in segments.iter().enumerate().take(full_segments.min(8)) {
            if prefix_segments[i] != segment {
                return false;
            }
        }

        return true;
    }

    false
}
