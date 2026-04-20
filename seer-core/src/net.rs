//! Shared SSRF protection helpers.
//!
//! `validate_public_host` rejects any hostname/IP that resolves to a reserved,
//! loopback, link-local, private, multicast, benchmarking, documentation, or
//! cloud-metadata address range. Used by every outbound leg of seer to ensure
//! user-supplied domains cannot be weaponized as an SSRF primitive.

use std::net::IpAddr;
use tokio::net::lookup_host;

use crate::error::{Result, SeerError};

/// Reject an IP address if it belongs to any range that is not appropriate
/// for outbound queries from a public-facing tool.
///
/// This covers: loopback, private (RFC1918), link-local (incl. 169.254.169.254
/// cloud metadata), multicast, unspecified, documentation, benchmarking,
/// IPv6 ULA, and IPv6 link-local.
pub fn is_reserved_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_documentation()
                // 100.64.0.0/10 — carrier-grade NAT / shared address space.
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64)
                // 192.0.0.0/24 — IETF reserved.
                || (v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 0)
                // 198.18.0.0/15 — network benchmark.
                || (v4.octets()[0] == 198 && (v4.octets()[1] == 18 || v4.octets()[1] == 19))
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                // Unique-local fc00::/7
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // Link-local fe80::/10
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // IPv4-mapped (::ffff:0:0/96) — check embedded IPv4
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| is_reserved_ip(IpAddr::V4(v4)))
        }
    }
}

/// Resolve a hostname and verify every resolved address is public.
/// Port is required because DNS resolution is done through `lookup_host`.
///
/// Returns `Ok(())` when all resolved IPs are public; `Err(SeerError::InvalidInput)`
/// otherwise. Does NOT follow CNAMEs explicitly — relies on the OS resolver.
pub async fn validate_public_host(host: &str, port: u16) -> Result<()> {
    // Short-circuit: IP literal parse
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_reserved_ip(ip) {
            return Err(SeerError::InvalidInput(format!(
                "refusing to connect to reserved address: {}",
                ip
            )));
        }
        return Ok(());
    }

    let addrs: Vec<_> = lookup_host((host, port))
        .await
        .map_err(|e| SeerError::InvalidInput(format!("DNS resolution failed for {host}: {e}")))?
        .collect();

    if addrs.is_empty() {
        return Err(SeerError::InvalidInput(format!(
            "no addresses resolved for {host}"
        )));
    }

    for sa in &addrs {
        if is_reserved_ip(sa.ip()) {
            return Err(SeerError::InvalidInput(format!(
                "{host} resolves to reserved address {}",
                sa.ip()
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rejects_loopback_v4() {
        assert!(is_reserved_ip("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn rejects_metadata_v4() {
        assert!(is_reserved_ip("169.254.169.254".parse().unwrap()));
    }

    #[test]
    fn rejects_rfc1918() {
        assert!(is_reserved_ip("10.0.0.1".parse().unwrap()));
        assert!(is_reserved_ip("172.16.0.1".parse().unwrap()));
        assert!(is_reserved_ip("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn rejects_cgnat() {
        assert!(is_reserved_ip("100.64.0.1".parse().unwrap()));
    }

    #[test]
    fn rejects_benchmarking() {
        assert!(is_reserved_ip("198.18.0.1".parse().unwrap()));
    }

    #[test]
    fn rejects_ipv6_loopback() {
        assert!(is_reserved_ip("::1".parse().unwrap()));
    }

    #[test]
    fn rejects_ipv6_ula() {
        assert!(is_reserved_ip("fd00::1".parse().unwrap()));
    }

    #[test]
    fn rejects_ipv4_mapped_loopback() {
        assert!(is_reserved_ip("::ffff:127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn allows_public_v4() {
        assert!(!is_reserved_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_reserved_ip("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn allows_public_v6() {
        assert!(!is_reserved_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    #[tokio::test]
    async fn validate_rejects_ip_literal_loopback() {
        let err = validate_public_host("127.0.0.1", 80).await.unwrap_err();
        assert!(matches!(err, SeerError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn validate_rejects_ip_literal_metadata() {
        let err = validate_public_host("169.254.169.254", 80)
            .await
            .unwrap_err();
        assert!(matches!(err, SeerError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn validate_allows_public_ip_literal() {
        validate_public_host("8.8.8.8", 53).await.unwrap();
    }
}
