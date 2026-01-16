//! Domain validation and SSRF protection utilities

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::{Result, SeerError};

/// Normalize and validate a domain name
///
/// This function:
/// - Removes http:// and https:// prefixes
/// - Removes www. prefix
/// - Removes trailing slashes and paths
/// - Converts to lowercase
/// - Validates format (must contain dots, only alphanumeric/hyphens/dots)
/// - Does NOT perform SSRF checks (use `validate_domain_safe` for network operations)
pub fn normalize_domain(domain: &str) -> Result<String> {
    let domain = domain.trim().to_lowercase();

    // Remove protocol
    let domain = domain
        .strip_prefix("http://")
        .or_else(|| domain.strip_prefix("https://"))
        .unwrap_or(&domain);

    // Remove trailing slash and path
    let domain = domain.split('/').next().unwrap_or(domain);

    // Remove www. prefix
    let domain = domain.strip_prefix("www.").unwrap_or(domain);

    // Validate domain format
    if domain.is_empty() || !domain.contains('.') {
        return Err(SeerError::InvalidDomain(domain.to_string()));
    }

    // Basic validation - alphanumeric, hyphens, and dots
    let valid = domain
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    if !valid {
        return Err(SeerError::InvalidDomain(domain.to_string()));
    }

    // Check for consecutive dots or dots at start/end
    if domain.contains("..") || domain.starts_with('.') || domain.ends_with('.') {
        return Err(SeerError::InvalidDomain(domain.to_string()));
    }

    // Check for hyphens at start/end of labels
    for label in domain.split('.') {
        if label.is_empty() || label.starts_with('-') || label.ends_with('-') {
            return Err(SeerError::InvalidDomain(domain.to_string()));
        }
    }

    Ok(domain.to_string())
}

/// Check if an IP address is in a private or reserved range
///
/// This includes:
/// - Private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
/// - Loopback (127.0.0.0/8, ::1/128)
/// - Link-local (169.254.0.0/16, fe80::/10)
/// - Cloud metadata (169.254.169.254)
/// - Unique local addresses (fc00::/7)
/// - Documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
/// - Multicast and broadcast
pub fn is_private_or_reserved_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => is_private_or_reserved_ipv4(ipv4),
        IpAddr::V6(ipv6) => is_private_or_reserved_ipv6(ipv6),
    }
}

/// Check if an IPv4 address is private or reserved
fn is_private_or_reserved_ipv4(ip: &Ipv4Addr) -> bool {
    // Standard private/loopback/link-local checks
    if ip.is_private() || ip.is_loopback() || ip.is_link_local() {
        return true;
    }

    let octets = ip.octets();

    // Cloud metadata service (169.254.169.254)
    if octets[0] == 169 && octets[1] == 254 && octets[2] == 169 && octets[3] == 254 {
        return true;
    }

    // Broader link-local range (169.254.0.0/16) - already covered by is_link_local()
    // But explicitly check cloud metadata range
    if octets[0] == 169 && octets[1] == 254 {
        return true;
    }

    // Documentation ranges
    // 192.0.2.0/24 (TEST-NET-1)
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
        return true;
    }
    // 198.51.100.0/24 (TEST-NET-2)
    if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
        return true;
    }
    // 203.0.113.0/24 (TEST-NET-3)
    if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
        return true;
    }

    // Broadcast
    if ip.is_broadcast() {
        return true;
    }

    // Unspecified (0.0.0.0)
    if ip.is_unspecified() {
        return true;
    }

    // Multicast (224.0.0.0/4)
    if octets[0] >= 224 && octets[0] <= 239 {
        return true;
    }

    // Reserved (240.0.0.0/4)
    if octets[0] >= 240 {
        return true;
    }

    false
}

/// Check if an IPv6 address is private or reserved
fn is_private_or_reserved_ipv6(ip: &Ipv6Addr) -> bool {
    // Loopback (::1)
    if ip.is_loopback() {
        return true;
    }

    // Unspecified (::)
    if ip.is_unspecified() {
        return true;
    }

    let segments = ip.segments();

    // Unique local addresses (fc00::/7)
    if (segments[0] & 0xfe00) == 0xfc00 {
        return true;
    }

    // Link-local (fe80::/10)
    if (segments[0] & 0xffc0) == 0xfe80 {
        return true;
    }

    // Multicast (ff00::/8)
    if segments[0] >> 8 == 0xff {
        return true;
    }

    // IPv4-mapped IPv6 addresses (::ffff:0:0/96)
    // Check if it maps to a private IPv4
    if ip.to_ipv4_mapped().is_some_and(|ipv4| is_private_or_reserved_ipv4(&ipv4)) {
        return true;
    }

    false
}

/// Validate that a domain is safe to query (SSRF protection)
///
/// This function:
/// 1. Normalizes the domain
/// 2. Resolves it to IP addresses
/// 3. Checks that none of the IPs are in private/reserved ranges
///
/// Use this before making HTTP/TLS connections to user-supplied domains.
pub async fn validate_domain_safe(domain: &str) -> Result<String> {
    // First normalize the domain
    let normalized = normalize_domain(domain)?;

    // Resolve the domain to IP addresses
    let addr = format!("{}:443", normalized);
    let socket_addrs = tokio::net::lookup_host(&addr)
        .await
        .map_err(|e| SeerError::InvalidDomain(format!("Failed to resolve domain: {}", e)))?;

    // Check all resolved IPs
    for socket_addr in socket_addrs {
        let ip = socket_addr.ip();
        if is_private_or_reserved_ip(&ip) {
            return Err(SeerError::InvalidDomain(format!(
                "Domain '{}' resolves to private or reserved IP: {}. This is blocked for security reasons.",
                normalized, ip
            )));
        }
    }

    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_domain() {
        assert_eq!(normalize_domain("example.com").unwrap(), "example.com");
        assert_eq!(normalize_domain("EXAMPLE.COM").unwrap(), "example.com");
        assert_eq!(
            normalize_domain("https://www.example.com/path").unwrap(),
            "example.com"
        );
        assert_eq!(
            normalize_domain("http://example.com/").unwrap(),
            "example.com"
        );
        assert_eq!(
            normalize_domain("  WWW.EXAMPLE.COM  ").unwrap(),
            "example.com"
        );

        // Invalid domains
        assert!(normalize_domain("").is_err());
        assert!(normalize_domain("nodots").is_err());
        assert!(normalize_domain("example..com").is_err());
        assert!(normalize_domain(".example.com").is_err());
        assert!(normalize_domain("example.com.").is_err());
        assert!(normalize_domain("-example.com").is_err());
        assert!(normalize_domain("example-.com").is_err());
    }

    #[test]
    fn test_is_private_or_reserved_ipv4() {
        // Private networks
        assert!(is_private_or_reserved_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private_or_reserved_ip(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_private_or_reserved_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));

        // Loopback
        assert!(is_private_or_reserved_ip(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));

        // Link-local
        assert!(is_private_or_reserved_ip(&IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));

        // Cloud metadata
        assert!(is_private_or_reserved_ip(&IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))));

        // Public IP (should not be blocked)
        assert!(!is_private_or_reserved_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_private_or_reserved_ip(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }

    #[test]
    fn test_is_private_or_reserved_ipv6() {
        // Loopback
        assert!(is_private_or_reserved_ip(&IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))));

        // Unique local
        assert!(is_private_or_reserved_ip(&IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1))));

        // Link-local
        assert!(is_private_or_reserved_ip(&IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))));

        // Public IPv6 (should not be blocked)
        assert!(!is_private_or_reserved_ip(&IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888))));
    }
}
