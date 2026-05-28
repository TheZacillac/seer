use once_cell::sync::Lazy;

use super::types::DnsServer;

/// Built-in list of global DNS servers for propagation checking.
/// Constructed once on first access; callers that need ownership call
/// `default_dns_servers().to_vec()`.
static DEFAULT_DNS_SERVERS: Lazy<Vec<DnsServer>> = Lazy::new(|| {
    vec![
        // North America
        DnsServer::new("Google", "8.8.8.8", "North America", "Google"),
        DnsServer::new("Cloudflare", "1.1.1.1", "North America", "Cloudflare"),
        DnsServer::new(
            "OpenDNS",
            "208.67.222.222",
            "North America",
            "Cisco OpenDNS",
        ),
        DnsServer::new("Quad9", "9.9.9.9", "North America", "Quad9"),
        DnsServer::new("Level3", "4.2.2.1", "North America", "Lumen"),
        // Europe
        DnsServer::new("DNS.Watch", "84.200.69.80", "Europe", "DNS.Watch"),
        DnsServer::new("Mullvad", "194.242.2.2", "Europe", "Mullvad"),
        DnsServer::new("dns0.eu", "193.110.81.0", "Europe", "dns0.eu"),
        DnsServer::new("Yandex", "77.88.8.8", "Europe", "Yandex"),
        DnsServer::new("UncensoredDNS", "91.239.100.100", "Europe", "UncensoredDNS"),
        // Asia Pacific
        DnsServer::new("AliDNS", "223.5.5.5", "Asia Pacific", "Alibaba"),
        DnsServer::new("114DNS", "114.114.114.114", "Asia Pacific", "114DNS"),
        DnsServer::new("Tencent DNSPod", "119.29.29.29", "Asia Pacific", "Tencent"),
        DnsServer::new("TWNIC", "101.101.101.101", "Asia Pacific", "TWNIC"),
        DnsServer::new("HiNet", "168.95.1.1", "Asia Pacific", "Chunghwa Telecom"),
        // Latin America
        DnsServer::new("Claro Brasil", "200.248.178.54", "Latin America", "Claro"),
        DnsServer::new(
            "Telefonica Brasil",
            "200.176.2.10",
            "Latin America",
            "Telefonica",
        ),
        DnsServer::new("Antel Uruguay", "200.40.30.245", "Latin America", "Antel"),
        DnsServer::new("Telmex Mexico", "200.33.146.217", "Latin America", "Telmex"),
        DnsServer::new(
            "CenturyLink LATAM",
            "200.75.51.132",
            "Latin America",
            "CenturyLink",
        ),
        // Africa
        DnsServer::new("Liquid Telecom", "41.63.64.74", "Africa", "Liquid Telecom"),
        DnsServer::new("SEACOM", "196.216.2.1", "Africa", "SEACOM"),
        DnsServer::new("Safaricom Kenya", "196.201.214.40", "Africa", "Safaricom"),
        DnsServer::new("MTN South Africa", "196.11.180.20", "Africa", "MTN"),
        DnsServer::new("Telecom Egypt", "196.205.152.10", "Africa", "Telecom Egypt"),
        // Middle East
        DnsServer::new("Etisalat UAE", "213.42.20.20", "Middle East", "Etisalat"),
        DnsServer::new("STC Saudi", "212.118.129.106", "Middle East", "STC"),
        DnsServer::new("Bezeq Israel", "192.115.106.81", "Middle East", "Bezeq"),
        DnsServer::new(
            "Turk Telekom",
            "195.175.39.39",
            "Middle East",
            "Turk Telekom",
        ),
        DnsServer::new("Ooredoo Qatar", "212.77.192.10", "Middle East", "Ooredoo"),
    ]
});

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
        assert!(
            servers.len() >= 20,
            "Should have at least 20 global DNS servers"
        );

        // Verify regions are covered
        let locations: Vec<&str> = servers.iter().map(|s| s.location.as_str()).collect();
        assert!(locations.contains(&"North America"));
        assert!(locations.contains(&"Europe"));
        assert!(locations.contains(&"Asia Pacific"));
        assert!(locations.contains(&"Latin America"));
        assert!(locations.contains(&"Africa"));
        assert!(locations.contains(&"Middle East"));
    }
}
