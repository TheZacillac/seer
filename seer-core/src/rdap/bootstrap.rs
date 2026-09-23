//! Bootstrap helpers for RDAP URL validation and IANA range matching.
//!
//! These are pure functions with no dependency on the RDAP client or its
//! global statics. Extracted from `client.rs` to keep that file focused on
//! the per-query client and the bootstrap-cache coordination logic.

use std::net::IpAddr;

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

/// Returns `true` when `ip` falls inside the CIDR prefix spec. A prefix of
/// the other address family never matches; a missing or unparsable mask means
/// a full-length (single-address) match, and an over-long mask never matches.
pub(super) fn ip_matches_prefix(prefix: &str, ip: IpAddr) -> bool {
    let (addr_part, mask_part) = match prefix.split_once('/') {
        Some((a, m)) => (a, Some(m)),
        None => (prefix, None),
    };

    // Both families compared as u128; IPv4 occupies the low 32 bits.
    let (ip_value, prefix_value, width) = match (ip, addr_part.parse::<IpAddr>()) {
        (IpAddr::V4(ip), Ok(IpAddr::V4(p))) => (u32::from(ip).into(), u32::from(p).into(), 32),
        (IpAddr::V6(ip), Ok(IpAddr::V6(p))) => (u128::from(ip), u128::from(p), 128),
        _ => return false,
    };

    let mask_bits: u32 = match mask_part.and_then(|s| s.parse().ok()) {
        Some(bits) if bits <= width => bits,
        Some(_) => return false,
        None => width,
    };

    // Clears the host bits; a /0 shifts everything out and matches all.
    let mask = u128::MAX.checked_shl(width - mask_bits).unwrap_or(0);
    (ip_value & mask) == (prefix_value & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(prefix: &str, ip: &str) -> bool {
        ip_matches_prefix(prefix, ip.parse().unwrap())
    }

    #[test]
    fn test_ipv4_prefix_matching_partial_mask() {
        assert!(matches("203.0.112.0/21", "203.0.114.1"));
        assert!(!matches("203.0.112.0/21", "203.0.120.1"));
    }

    #[test]
    fn test_ipv6_prefix_matching_partial_mask() {
        assert!(matches("2001:db8::/33", "2001:db8::1"));
        assert!(!matches("2001:db8::/33", "2001:db9::1"));
    }

    #[test]
    fn test_prefix_matching_edge_masks_and_families() {
        // /0 matches every address of its family, and only its family.
        assert!(matches("0.0.0.0/0", "198.51.100.7"));
        assert!(matches("::/0", "2001:db8::1"));
        assert!(!matches("0.0.0.0/0", "2001:db8::1"));
        assert!(!matches("::/0", "198.51.100.7"));
        // Full-length masks, including a missing or unparsable one.
        assert!(matches("198.51.100.7/32", "198.51.100.7"));
        assert!(!matches("198.51.100.7", "198.51.100.8"));
        assert!(matches("198.51.100.7/x", "198.51.100.7"));
        assert!(!matches("198.51.100.7/x", "198.51.100.8"));
        // A mask wider than the family never matches.
        assert!(!matches("198.51.100.0/33", "198.51.100.7"));
        assert!(!matches("2001:db8::/129", "2001:db8::1"));
        // An unparsable prefix address never matches.
        assert!(!matches("not-an-ip/8", "10.0.0.1"));
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
