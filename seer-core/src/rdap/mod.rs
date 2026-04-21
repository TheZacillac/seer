mod bootstrap;
mod client;
mod types;

pub use client::RdapClient;
pub use types::{ContactInfo, RdapResponse};

use std::net::IpAddr;

use crate::error::{Result, SeerError};

/// Classified RDAP routing decision for a free-form query string.
///
/// Separated from [`auto_lookup`] so the routing rules can be covered by
/// pure unit tests that do not require network or an [`RdapClient`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RdapRoute {
    /// Query was an IP literal (v4 or v6).
    Ip(IpAddr),
    /// Query matched the `AS<digits>` form with no embedded dots.
    Asn(u32),
    /// Anything else — dispatched to domain lookup.
    Domain(String),
}

/// Classifies a free-form RDAP query into an [`RdapRoute`].
///
/// Rules (applied in order):
///
/// 1. If `query` parses as an [`IpAddr`], route to [`RdapRoute::Ip`].
/// 2. If `query` (case-insensitive) starts with `AS`, the remainder is all
///    ASCII digits, and the trimmed query contains no `.`, route to
///    [`RdapRoute::Asn`].
/// 3. Otherwise, route to [`RdapRoute::Domain`].
///
/// The `contains('.')` guard is the load-bearing check that prevents real
/// domains like `as1234.io` from being misclassified as an ASN query — a
/// regression that existed while RDAP auto-routing lived in the Python
/// `rdap()` wrapper.
pub fn classify(query: &str) -> Result<RdapRoute> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Err(SeerError::InvalidInput("empty RDAP query".to_string()));
    }

    // 1) IP literal (v4 or v6).
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(RdapRoute::Ip(ip));
    }

    // 2) ASN: "AS<digits>" with no '.' anywhere in the trimmed query.
    //    The no-dot check prevents misrouting real domains that start with
    //    "AS" (e.g. as1234.io).
    let upper = trimmed.to_uppercase();
    if let Some(rest) = upper.strip_prefix("AS") {
        if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) && !trimmed.contains('.') {
            let asn: u32 = rest
                .parse()
                .map_err(|_| SeerError::InvalidInput(format!("invalid ASN: {query}")))?;
            return Ok(RdapRoute::Asn(asn));
        }
    }

    // 3) Fallback: domain lookup.
    Ok(RdapRoute::Domain(trimmed.to_string()))
}

/// Auto-routing RDAP lookup.
///
/// Classifies `query` with [`classify`] and dispatches to the appropriate
/// method on the supplied [`RdapClient`]. This replaces the previous
/// Python-side dispatcher, which used `int()`-style sniffing and would
/// silently misroute `AS`-prefixed domains like `as1234.io` to the ASN
/// endpoint.
pub async fn auto_lookup(client: &RdapClient, query: &str) -> Result<RdapResponse> {
    match classify(query)? {
        RdapRoute::Ip(_ip) => client.lookup_ip(query.trim()).await,
        RdapRoute::Asn(asn) => client.lookup_asn(asn).await,
        RdapRoute::Domain(domain) => client.lookup_domain(&domain).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_ipv4() {
        assert!(matches!(classify("8.8.8.8").unwrap(), RdapRoute::Ip(_)));
        assert!(matches!(classify("1.1.1.1").unwrap(), RdapRoute::Ip(_)));
    }

    #[test]
    fn classifies_ipv6() {
        assert!(matches!(
            classify("2606:4700:4700::1111").unwrap(),
            RdapRoute::Ip(_)
        ));
    }

    #[test]
    fn classifies_asn_upper() {
        assert_eq!(classify("AS1234").unwrap(), RdapRoute::Asn(1234));
    }

    #[test]
    fn classifies_asn_lower() {
        assert_eq!(classify("as1234").unwrap(), RdapRoute::Asn(1234));
    }

    #[test]
    fn classifies_asn_mixed_case() {
        assert_eq!(classify("As15169").unwrap(), RdapRoute::Asn(15169));
    }

    #[test]
    fn as_prefix_domain_routes_to_domain() {
        // Regression: as1234.io is a real domain, not ASN. The `.` in the
        // query must force the domain route.
        assert_eq!(
            classify("as1234.io").unwrap(),
            RdapRoute::Domain("as1234.io".to_string())
        );
        assert_eq!(
            classify("AS1234.IO").unwrap(),
            RdapRoute::Domain("AS1234.IO".to_string())
        );
    }

    #[test]
    fn asn_with_trailing_junk_routes_to_domain() {
        // "AS1234x" is not digits-only after the prefix; fall through to domain.
        assert_eq!(
            classify("AS1234x").unwrap(),
            RdapRoute::Domain("AS1234x".to_string())
        );
    }

    #[test]
    fn bare_as_routes_to_domain() {
        // "AS" alone has an empty digit tail; not an ASN.
        assert_eq!(classify("AS").unwrap(), RdapRoute::Domain("AS".to_string()));
    }

    #[test]
    fn normal_domain_routes_to_domain() {
        assert_eq!(
            classify("example.com").unwrap(),
            RdapRoute::Domain("example.com".to_string())
        );
    }

    #[test]
    fn trims_whitespace() {
        assert_eq!(classify("  AS64500  ").unwrap(), RdapRoute::Asn(64500));
        assert_eq!(
            classify("  example.com  ").unwrap(),
            RdapRoute::Domain("example.com".to_string())
        );
    }

    #[test]
    fn empty_query_errors() {
        assert!(matches!(
            classify("").unwrap_err(),
            SeerError::InvalidInput(_)
        ));
        assert!(matches!(
            classify("   ").unwrap_err(),
            SeerError::InvalidInput(_)
        ));
    }

    #[test]
    fn asn_overflow_errors() {
        // u32::MAX is 4294967295; anything larger must error.
        assert!(matches!(
            classify("AS99999999999999").unwrap_err(),
            SeerError::InvalidInput(_)
        ));
    }
}
