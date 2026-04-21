//! Bootstrap helpers for RDAP URL validation and IANA range matching.
//!
//! These are pure functions with no dependency on the RDAP client or its
//! global statics. Extracted from `client.rs` to keep that file focused on
//! the per-query client and the bootstrap-cache coordination logic.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::{Result, SeerError};

/// Validates a bootstrap-service URL from IANA (or any trusted publisher).
///
/// Enforces:
/// * scheme is `https` (plaintext http would allow MITM redirection to a
///   hostile RDAP server)
/// * host is a registered domain name, not an IP literal (IANA publishes
///   DNS names, so a literal indicates corrupted or spoofed bootstrap data)
/// * host is non-empty and free of whitespace/control characters
pub(super) fn validate_bootstrap_url(s: &str) -> Result<url::Url> {
    let parsed = url::Url::parse(s)
        .map_err(|e| SeerError::RdapError(format!("bad bootstrap URL {}: {}", s, e)))?;
    if parsed.scheme() != "https" {
        return Err(SeerError::RdapError(format!(
            "bootstrap URL must be https, got {}",
            parsed.scheme()
        )));
    }
    let host = parsed
        .host()
        .ok_or_else(|| SeerError::RdapError(format!("bootstrap URL has no host: {}", s)))?;
    match host {
        url::Host::Ipv4(_) | url::Host::Ipv6(_) => {
            return Err(SeerError::RdapError(format!(
                "bootstrap URL must not be an IP literal: {}",
                s
            )));
        }
        url::Host::Domain(d) => {
            if d.is_empty() || d.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return Err(SeerError::RdapError(format!(
                    "bootstrap URL has invalid host: {}",
                    s
                )));
            }
        }
    }
    Ok(parsed)
}

/// Parses an ASN range spec from the IANA bootstrap (e.g. `"15169"` or
/// `"13312-15359"`) into an inclusive `(start, end)` pair.
pub(super) fn parse_asn_range(range: &str) -> Option<(u32, u32)> {
    if let Some(pos) = range.find('-') {
        let start = range[..pos].parse().ok()?;
        let end = range[pos + 1..].parse().ok()?;
        Some((start, end))
    } else {
        let num = range.parse().ok()?;
        Some((num, num))
    }
}

/// Returns `true` when the IPv4 address falls inside the CIDR prefix spec.
pub(super) fn ipv4_matches_prefix(prefix: &str, ip: &Ipv4Addr) -> bool {
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

/// Returns `true` when the IPv6 address falls inside the CIDR prefix spec.
pub(super) fn ipv6_matches_prefix(prefix: &str, ip: &Ipv6Addr) -> bool {
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
    fn test_validate_bootstrap_url_accepts_https() {
        let url = validate_bootstrap_url("https://rdap.example.com/").unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("rdap.example.com"));
    }

    #[test]
    fn test_validate_bootstrap_url_rejects_http() {
        let err = validate_bootstrap_url("http://rdap.example.com/").unwrap_err();
        assert!(
            matches!(err, SeerError::RdapError(ref s) if s.contains("https")),
            "expected https-scheme error, got: {:?}",
            err
        );
    }

    #[test]
    fn test_validate_bootstrap_url_rejects_ftp() {
        let err = validate_bootstrap_url("ftp://rdap.example.com/").unwrap_err();
        assert!(matches!(err, SeerError::RdapError(_)));
    }

    #[test]
    fn test_validate_bootstrap_url_rejects_ip_literal_v4() {
        let err = validate_bootstrap_url("https://192.0.2.1/").unwrap_err();
        assert!(
            matches!(err, SeerError::RdapError(ref s) if s.contains("IP literal")),
            "expected IP-literal error, got: {:?}",
            err
        );
    }

    #[test]
    fn test_validate_bootstrap_url_rejects_ip_literal_v6() {
        let err = validate_bootstrap_url("https://[2001:db8::1]/").unwrap_err();
        assert!(
            matches!(err, SeerError::RdapError(ref s) if s.contains("IP literal")),
            "expected IP-literal error, got: {:?}",
            err
        );
    }

    #[test]
    fn test_validate_bootstrap_url_rejects_garbage() {
        let err = validate_bootstrap_url("not a url").unwrap_err();
        assert!(matches!(err, SeerError::RdapError(_)));
    }
}
