use std::sync::LazyLock;

use super::types::DnsServer;

/// Built-in list of public DNS resolvers for propagation checking.
/// Constructed once on first access; callers that need ownership call
/// `default_dns_servers().to_vec()`.
///
/// Only advertised public services that answer anyone over plain UDP, and
/// their unfiltered addresses where they offer one (Quad9 `9.9.9.10`, AdGuard
/// `94.140.14.140`): a filtering resolver blocks malicious names on purpose,
/// which would read as a propagation inconsistency. ISP resolvers that serve
/// only their own customers refuse or ignore outside queries, so they are
/// left out. Most of these services are anycast — they answer from the site
/// nearest the querier — so `location` is where the operator is based, and
/// what the list samples is the separate caches of independent operators.
static DEFAULT_DNS_SERVERS: LazyLock<Vec<DnsServer>> = LazyLock::new(|| {
    [
        // (name, ip, location, provider)
        ("Google", "8.8.8.8", NA, "Google"),
        ("Cloudflare", "1.1.1.1", NA, "Cloudflare"),
        ("OpenDNS", "208.67.222.222", NA, "Cisco"),
        ("Level3", "4.2.2.1", NA, "Lumen"),
        (
            "Hurricane Electric",
            "74.82.42.42",
            NA,
            "Hurricane Electric",
        ),
        ("UltraDNS", "64.6.64.6", NA, "Vercara"),
        ("Control D", "76.76.2.0", NA, "Windscribe"),
        ("Quad9", "9.9.9.10", EU, "Quad9"),
        ("DNS4EU", "86.54.11.100", EU, "DNS4EU"),
        ("AdGuard", "94.140.14.140", EU, "AdGuard"),
        ("DNS.SB", "185.222.222.222", EU, "xTom"),
        ("CZ.NIC ODVR", "193.17.47.1", EU, "CZ.NIC"),
        ("Yandex", "77.88.8.8", EU, "Yandex"),
        ("114DNS", "114.114.114.114", AP, "114DNS"),
        ("DNSPod", "119.29.29.29", AP, "Tencent"),
        ("Volcengine", "180.184.1.1", AP, "ByteDance"),
        ("360 DNS", "101.226.4.6", AP, "Qihoo 360"),
        ("HiNet", "168.95.1.1", AP, "Chunghwa Telecom"),
        ("KT", "168.126.63.1", AP, "KT Corporation"),
        ("LG U+", "164.124.101.2", AP, "LG Uplus"),
    ]
    .into_iter()
    .map(|(name, ip, location, provider)| DnsServer::new(name, ip, location, provider))
    .collect()
});

const NA: &str = "North America";
const EU: &str = "Europe";
const AP: &str = "Asia Pacific";

/// Returns the default list of global DNS servers for propagation checking.
/// The list is built once and handed out as a borrow. Callers needing an
/// owned `Vec` (e.g. `PropagationChecker` which allows mutation) can call
/// `.to_vec()` on the returned slice.
pub fn default_dns_servers() -> &'static [DnsServer] {
    &DEFAULT_DNS_SERVERS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_dns_servers() {
        let servers = default_dns_servers();
        assert!(servers.len() >= 20, "Should have at least 20 DNS servers");

        let locations: Vec<&str> = servers.iter().map(|s| s.location.as_str()).collect();
        for region in [NA, EU, AP] {
            assert!(locations.contains(&region), "no server in {region}");
        }
    }

    /// Every entry is a public IP literal, listed once: the SSRF guard would
    /// refuse a reserved one at query time, and a duplicate would count one
    /// operator's cache twice.
    #[test]
    fn default_servers_are_unique_public_ips() {
        let mut seen = std::collections::HashSet::new();
        for server in default_dns_servers() {
            let ip: std::net::IpAddr = server.ip.parse().expect("IP literal");
            assert!(!crate::net::is_reserved_ip(ip), "{} is reserved", server.ip);
            assert!(seen.insert(ip), "{} listed twice", server.ip);
        }
    }
}
