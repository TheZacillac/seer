//! Domain validation and SSRF protection utilities

use std::collections::HashSet;
use std::net::IpAddr;

use std::sync::LazyLock;

use crate::error::{Result, SeerError};

/// Domain allowlist loaded from the `SEER_DOMAIN_ALLOWLIST` environment
/// variable. Entries match by label-boundary suffix (see
/// [`domain_matches_allowlist`]): `com` permits all `*.com`, and `example.com`
/// permits `example.com` and its subdomains. When unset, all domains are
/// allowed.
static DOMAIN_ALLOWLIST: LazyLock<Option<HashSet<String>>> = LazyLock::new(|| {
    let set: HashSet<String> = std::env::var("SEER_DOMAIN_ALLOWLIST")
        .ok()?
        .split(',')
        .map(normalize_allowlist_entry)
        .filter(|s| !s.is_empty())
        .collect();

    if set.is_empty() {
        None
    } else {
        Some(set)
    }
});

/// Normalizes a single allowlist entry: trims, lowercases, and converts an IDN
/// entry to its ASCII A-label. This must mirror the IDN handling in
/// [`normalize_domain`] so an internationalized entry matches the punycode form
/// that queries are normalized to (an entry that fails IDN conversion is kept
/// as-is and simply won't match).
fn normalize_allowlist_entry(entry: &str) -> String {
    let lowered = entry.trim().to_lowercase();
    if lowered.is_ascii() {
        lowered
    } else {
        domain_to_ascii(&lowered).unwrap_or(lowered)
    }
}

/// Normalizes and validates a domain name.
///
/// This function:
/// - Removes http:// and https:// prefixes
/// - Removes www. prefix (only when a registrable name remains — `www.com`
///   is itself a domain and is kept whole)
/// - Removes trailing slashes and paths
/// - Converts to lowercase
/// - Converts internationalized domain names (IDN) to Punycode (ASCII)
/// - Validates format (must contain dots, only alphanumeric/hyphens/dots)
/// - Does NOT perform SSRF checks. For network operations, resolve and
///   validate via `crate::net::resolve_public_host` (or `validate_public_host`),
///   which returns the vetted `SocketAddr`s to connect to — closing the
///   resolve-then-connect (DNS-rebinding) window.
///
/// The `www.` strip is right for registration-level questions (WHOIS, RDAP,
/// availability, history keys), where `www.example.com` means
/// `example.com`. It is wrong wherever the exact name matters — a DNS record
/// query or a per-host probe — because `www` routinely carries its own
/// records (typically a CNAME). Use [`normalize_host`] there.
pub fn normalize_domain(domain: &str) -> Result<String> {
    normalize(domain, true)
}

/// Normalizes and validates a hostname exactly like [`normalize_domain`], but
/// keeps a leading `www.` label.
///
/// For operations about one specific DNS name rather than its registration:
/// record lookups (`dig www.example.com CNAME` must query `www`, not the
/// apex), propagation/follow/compare, and per-host probes such as takeover
/// detection, where `www` is the single most commonly CNAME'd host.
pub fn normalize_host(host: &str) -> Result<String> {
    normalize(host, false)
}

fn normalize(domain: &str, strip_www: bool) -> Result<String> {
    let domain = domain.trim().to_lowercase();

    // Remove protocol
    let domain = domain
        .strip_prefix("http://")
        .or_else(|| domain.strip_prefix("https://"))
        .unwrap_or(&domain);

    // Remove trailing slash, path, query parameters, and fragments
    let domain = domain.split('/').next().unwrap_or(domain);
    let domain = domain.split('?').next().unwrap_or(domain);
    let domain = domain.split('#').next().unwrap_or(domain);

    // Strip userinfo (`user:pass@host`) — take the host portion after the
    // last '@'. This runs after path stripping so a stray '@' in a path
    // segment can't affect the host.
    let domain = domain.rsplit('@').next().unwrap_or(domain);

    // Strip a trailing port (`host:8443`) but only when it is `:` followed
    // entirely by digits, so we never truncate anything else (and IPv6
    // literals, which are not valid here anyway, won't match this shape).
    let domain = match domain.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => domain,
    };

    // Strip a single trailing dot (FQDN form: `example.com.` → `example.com`).
    // DNS libraries and copy-paste from `dig` output routinely include the
    // root-label dot; rejecting it would force callers to pre-clean inputs
    // that are otherwise valid. Done before the `www.` strip so `www.com.`
    // is judged on its real label count.
    let domain = domain.strip_suffix('.').unwrap_or(domain);

    // Remove www. prefix — but only when what remains still has a dot.
    // `www.com`, `www.net`, … are registered domains in their own right;
    // stripping them would leave a bare TLD and reject a valid query.
    let domain = match domain.strip_prefix("www.") {
        Some(rest) if strip_www && rest.contains('.') => rest,
        _ => domain,
    };

    // Validate domain format
    if domain.is_empty() || !domain.contains('.') {
        return Err(SeerError::InvalidDomain(domain.to_string()));
    }

    // Convert internationalized domain names (IDN) to ASCII/Punycode
    let domain = if !domain.is_ascii() {
        domain_to_ascii(domain)?
    } else {
        domain.to_string()
    };

    // Basic validation - alphanumeric, hyphens, dots, and underscores
    // Underscores are valid in DNS names (RFC 8552) and required for service
    // records like _dmarc., _domainkey., _sip._tcp., etc.
    let valid = domain
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_');
    if !valid {
        return Err(SeerError::InvalidDomain(domain.to_string()));
    }

    // Check for consecutive dots or dots at start/end
    if domain.contains("..") || domain.starts_with('.') || domain.ends_with('.') {
        return Err(SeerError::InvalidDomain(domain.to_string()));
    }

    // RFC 1035: total domain name length ≤ 253 characters
    if domain.len() > 253 {
        return Err(SeerError::InvalidDomain(domain.to_string()));
    }

    // Check label constraints
    for label in domain.split('.') {
        // Labels must be non-empty and not start/end with hyphens
        if label.is_empty() || label.starts_with('-') || label.ends_with('-') {
            return Err(SeerError::InvalidDomain(domain.to_string()));
        }
        // RFC 1035: each label ≤ 63 characters
        if label.len() > 63 {
            return Err(SeerError::InvalidDomain(domain.to_string()));
        }
    }

    // Check against the allowlist (if configured) using suffix matching.
    if let Some(ref allowlist) = *DOMAIN_ALLOWLIST {
        if !domain_matches_allowlist(&domain, allowlist) {
            let tld = domain.rsplit('.').next().unwrap_or(&domain).to_string();
            return Err(SeerError::DomainNotAllowed {
                domain: domain.to_string(),
                tld,
            });
        }
    }

    Ok(domain.to_string())
}

/// Returns true if `domain` is permitted by `allowlist` using label-boundary
/// suffix matching: an entry matches the domain itself or any subdomain of it.
///
/// This fixes the misleading control where `SEER_DOMAIN_ALLOWLIST` only compared
/// the final label, so a full-domain entry like `example.com` matched nothing
/// (issue #61). A bare-TLD entry (e.g. `com`) still matches all `*.com` domains,
/// so existing TLD-style configs keep working; a full-domain entry (e.g.
/// `example.com`) now matches `example.com` and `sub.example.com` as the name
/// implies. Both `domain` and the entries are already lowercased.
fn domain_matches_allowlist(domain: &str, allowlist: &HashSet<String>) -> bool {
    allowlist.iter().any(|entry| {
        if domain == entry.as_str() {
            return true;
        }
        // Subdomain match: `domain` ends with ".<entry>" on a label boundary.
        domain.len() > entry.len()
            && domain.ends_with(entry.as_str())
            && domain.as_bytes()[domain.len() - entry.len() - 1] == b'.'
    })
}

/// Converts an internationalized domain name to ASCII (Punycode).
pub(crate) fn domain_to_ascii(domain: &str) -> Result<String> {
    idna::domain_to_ascii(domain).map_err(|_| {
        SeerError::InvalidDomain(format!("invalid internationalized domain: {}", domain))
    })
}

/// Returns a human-readable reason why an IP is blocked, or `None` if it is
/// safe.  Intended for error messages — callers should still use
/// [`crate::net::is_reserved_ip`], the single source of truth for SSRF range
/// checks, for the fast boolean check.
pub fn describe_reserved_ip(ip: &IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_unspecified() {
                return Some("unspecified address (0.0.0.0) — domain has no routable IP");
            }
            if v4.is_loopback() {
                return Some("loopback address (127.0.0.0/8)");
            }
            if v4.is_private() {
                return Some("private network (RFC 1918)");
            }
            // The metadata endpoint sits inside 169.254.0.0/16, so it must be
            // checked before the generic link-local branch or it is never
            // reported by name.
            let o = v4.octets();
            if o[0] == 169 && o[1] == 254 && o[2] == 169 && o[3] == 254 {
                return Some("cloud metadata endpoint (169.254.169.254)");
            }
            if v4.is_link_local() {
                return Some("link-local address (169.254.0.0/16)");
            }
            if (o[0] == 192 && o[1] == 0 && o[2] == 2)
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)
            {
                return Some("documentation/test range (RFC 5737)");
            }
            if v4.is_broadcast() {
                return Some("broadcast address (255.255.255.255)");
            }
            if o[0] >= 224 && o[0] <= 239 {
                return Some("multicast address (224.0.0.0/4)");
            }
            if o[0] >= 240 {
                return Some("reserved address (240.0.0.0/4)");
            }
            // Catch-all: any range the canonical checker blocks but for which we
            // have no specific wording (CGNAT 100.64/10, IETF 192.0.0.0/24,
            // benchmark 198.18/15, 0.0.0.0/8, …) is still refused — never
            // under-block relative to net::is_reserved_ip.
            if crate::net::is_reserved_ip(IpAddr::V4(*v4)) {
                return Some("reserved/special-purpose address range");
            }
            None
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return Some("IPv6 loopback (::1)");
            }
            if v6.is_unspecified() {
                return Some("IPv6 unspecified address (::) — domain has no routable IP");
            }
            let seg = v6.segments();
            if (seg[0] & 0xfe00) == 0xfc00 {
                return Some("IPv6 unique local address (fc00::/7)");
            }
            if (seg[0] & 0xffc0) == 0xfe80 {
                return Some("IPv6 link-local address (fe80::/10)");
            }
            if (seg[0] & 0xffc0) == 0xfec0 {
                return Some("IPv6 site-local address (fec0::/10)");
            }
            if seg[0] >> 8 == 0xff {
                return Some("IPv6 multicast (ff00::/8)");
            }
            if let Some(v4) = v6.to_ipv4_mapped() {
                if crate::net::is_reserved_ip(IpAddr::V4(v4)) {
                    return Some("IPv4-mapped IPv6 address in private/reserved range");
                }
            }
            // Catch-all for 6to4 / NAT64 / IPv4-compatible / documentation and
            // any other range the canonical checker blocks.
            if crate::net::is_reserved_ip(IpAddr::V6(*v6)) {
                return Some("reserved/special-purpose IPv6 range");
            }
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_entry_idn_is_punycoded() {
        // IDN allowlist entries are converted to their A-label so they match
        // the punycode query produced by `normalize_domain`.
        assert_eq!(normalize_allowlist_entry("münchen.de"), "xn--mnchen-3ya.de");
        assert_eq!(normalize_allowlist_entry(" Example.COM "), "example.com");
    }

    #[test]
    fn allowlist_matches_idn_after_normalization() {
        let mut set = HashSet::new();
        set.insert(normalize_allowlist_entry("münchen.de"));
        // `normalize_domain("münchen.de")` yields the A-label below.
        assert!(domain_matches_allowlist("xn--mnchen-3ya.de", &set));
    }

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

        // Query parameters and fragments
        assert_eq!(
            normalize_domain("example.com?query=1").unwrap(),
            "example.com"
        );
        assert_eq!(
            normalize_domain("example.com#section").unwrap(),
            "example.com"
        );
        assert_eq!(
            normalize_domain("https://example.com/path?q=1#frag").unwrap(),
            "example.com"
        );

        // Underscore domains (DNS service records)
        assert_eq!(
            normalize_domain("_dmarc.example.com").unwrap(),
            "_dmarc.example.com"
        );
        assert_eq!(
            normalize_domain("selector1._domainkey.example.com").unwrap(),
            "selector1._domainkey.example.com"
        );
        assert_eq!(
            normalize_domain("_sip._tcp.example.com").unwrap(),
            "_sip._tcp.example.com"
        );

        // Invalid domains
        assert!(normalize_domain("").is_err());
        assert!(normalize_domain("nodots").is_err());
        assert!(normalize_domain("example..com").is_err());
        assert!(normalize_domain(".example.com").is_err());
        assert!(normalize_domain("-example.com").is_err());
        assert!(normalize_domain("example-.com").is_err());

        // Port and userinfo are stripped from the host.
        assert_eq!(
            normalize_domain("https://example.com:8443/admin").unwrap(),
            "example.com"
        );
        assert_eq!(normalize_domain("example.com:443").unwrap(), "example.com");
        assert_eq!(
            normalize_domain("https://user@example.com/").unwrap(),
            "example.com"
        );
        assert_eq!(
            normalize_domain("https://user:pass@example.com:8443/path").unwrap(),
            "example.com"
        );

        // FQDN form is accepted: single trailing dot is stripped.
        assert_eq!(normalize_domain("example.com.").unwrap(), "example.com");
        assert_eq!(
            normalize_domain("https://example.com.").unwrap(),
            "example.com"
        );
        // Double trailing dot is still invalid (would leave a trailing dot
        // after stripping just one).
        assert!(normalize_domain("example.com..").is_err());
    }

    #[test]
    fn www_is_not_stripped_when_it_would_leave_a_bare_tld() {
        // `www.com` / `www.net` are real registered domains; stripping `www.`
        // used to leave `com` and reject the query outright.
        assert_eq!(normalize_domain("www.com").unwrap(), "www.com");
        assert_eq!(normalize_domain("WWW.NET.").unwrap(), "www.net");
        assert_eq!(normalize_domain("https://www.io/x").unwrap(), "www.io");
        // A registrable name after the strip still normalizes to the apex.
        assert_eq!(normalize_domain("www.example.com.").unwrap(), "example.com");
    }

    #[test]
    fn normalize_host_keeps_www() {
        // Per-name operations (DNS record queries, takeover probes) must see
        // `www` itself — it usually has its own CNAME.
        assert_eq!(
            normalize_host("HTTPS://WWW.Example.com:443/path").unwrap(),
            "www.example.com"
        );
        assert_eq!(normalize_host("www.com").unwrap(), "www.com");
        // Everything else matches normalize_domain.
        assert_eq!(
            normalize_host("sub.example.com.").unwrap(),
            "sub.example.com"
        );
        assert_eq!(normalize_host("münchen.de").unwrap(), "xn--mnchen-3ya.de");
        assert!(normalize_host("nodots").is_err());
        assert!(normalize_host("bad_label-.com").is_err());
    }

    #[test]
    fn describe_reserved_ip_names_the_metadata_endpoint() {
        // 169.254.169.254 is link-local too; the specific wording must win.
        assert_eq!(
            describe_reserved_ip(&"169.254.169.254".parse().unwrap()),
            Some("cloud metadata endpoint (169.254.169.254)")
        );
        assert_eq!(
            describe_reserved_ip(&"169.254.1.1".parse().unwrap()),
            Some("link-local address (169.254.0.0/16)")
        );
    }

    #[test]
    fn test_normalize_idn_domain() {
        // German: münchen.de -> xn--mnchen-3ya.de
        let result = normalize_domain("münchen.de").unwrap();
        assert_eq!(result, "xn--mnchen-3ya.de");

        // Japanese: 例え.jp -> xn--r8jz45g.jp
        let result = normalize_domain("例え.jp").unwrap();
        assert_eq!(result, "xn--r8jz45g.jp");

        // Chinese: 中文.com -> xn--fiq228c.com
        let result = normalize_domain("中文.com").unwrap();
        assert_eq!(result, "xn--fiq228c.com");

        // With protocol prefix
        let result = normalize_domain("https://münchen.de/path").unwrap();
        assert_eq!(result, "xn--mnchen-3ya.de");

        // Cyrillic, including uppercase input (lowercased before conversion)
        assert_eq!(
            normalize_domain("пример.рф").unwrap(),
            "xn--e1afmkfd.xn--p1ai"
        );
        assert_eq!(
            normalize_domain("ПРИМЕР.РФ").unwrap(),
            "xn--e1afmkfd.xn--p1ai"
        );

        // Already-punycode input passes through unchanged
        assert_eq!(
            normalize_domain("xn--e1afmkfd.xn--p1ai").unwrap(),
            "xn--e1afmkfd.xn--p1ai"
        );
    }

    #[test]
    fn test_allowlist_not_set_allows_all() {
        // When SEER_DOMAIN_ALLOWLIST is not set, all domains pass
        // This test verifies the default behavior (no env var)
        assert!(normalize_domain("example.com").is_ok());
        assert!(normalize_domain("example.xyz").is_ok());
        assert!(normalize_domain("example.co.uk").is_ok());
    }

    #[test]
    fn allowlist_suffix_matching() {
        // #61: a full-domain entry must match the domain and its subdomains
        // (the previous code only matched the final label, so "example.com"
        // matched nothing), while a bare-TLD entry stays backward compatible.
        let full: HashSet<String> = ["example.com".to_string()].into_iter().collect();
        assert!(domain_matches_allowlist("example.com", &full));
        assert!(domain_matches_allowlist("sub.example.com", &full));
        assert!(
            !domain_matches_allowlist("notexample.com", &full),
            "label boundary"
        );
        assert!(!domain_matches_allowlist("example.org", &full));

        let tld: HashSet<String> = ["com".to_string()].into_iter().collect();
        assert!(
            domain_matches_allowlist("example.com", &tld),
            "bare TLD still works"
        );
        assert!(domain_matches_allowlist("a.b.com", &tld));
        assert!(domain_matches_allowlist("com", &tld));
        assert!(!domain_matches_allowlist("example.org", &tld));
        assert!(
            !domain_matches_allowlist("scam", &tld),
            "must not match mid-label"
        );
    }

    #[test]
    fn reserved_ip_check_blocks_private_ranges_only() {
        for ip in [
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "169.254.169.254",
            "::1",
            "fc00::1",
            "fe80::1",
        ] {
            assert!(crate::net::is_reserved_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"] {
            assert!(!crate::net::is_reserved_ip(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn describe_reserved_ip_agrees_with_net_on_previously_divergent_ranges() {
        // These were blocked by net::is_reserved_ip but NOT by the old
        // validation checker that guards the RDAP + HTTP-redirect paths.
        for ip in [
            "100.64.0.1",
            "198.18.0.1",
            "192.0.0.1",
            "0.1.2.3",
            "240.0.0.1",
        ] {
            let addr: IpAddr = ip.parse().unwrap();
            assert!(
                describe_reserved_ip(&addr).is_some(),
                "{ip} must be reported reserved"
            );
            assert!(crate::net::is_reserved_ip(addr), "{ip} bool check");
        }
        // IPv6 transition forms embedding the metadata IP (169.254.169.254).
        for ip in ["64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::", "::a9fe:a9fe"] {
            let addr: IpAddr = ip.parse().unwrap();
            assert!(
                describe_reserved_ip(&addr).is_some(),
                "{ip} must be reported reserved"
            );
        }
        // A genuinely public address is still allowed through.
        assert!(describe_reserved_ip(&"8.8.8.8".parse().unwrap()).is_none());
    }
}
