//! Shared SSRF protection helpers.
//!
//! `validate_public_host` rejects any hostname/IP that resolves to a reserved,
//! loopback, link-local, private, multicast, benchmarking, documentation, or
//! cloud-metadata address range. Used by every outbound leg of seer to ensure
//! user-supplied domains cannot be weaponized as an SSRF primitive.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use hickory_resolver::config::{ResolveHosts, ResolverConfig, GOOGLE};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::TokioResolver;
use once_cell::sync::Lazy;
use tokio::net::lookup_host;
use tracing::warn;

use crate::error::{Result, SeerError};

/// Fallback resolver used when the OS resolver (`getaddrinfo`) fails.
///
/// Points at Google DNS (8.8.8.8 / 8.8.4.4) so seer keeps working on hosts
/// with a broken or misconfigured system resolver — a common failure mode
/// on corporate Macs, active VPNs, or systems where a local dnsmasq /
/// stubby is down. `use_hosts_file = false` because the hosts file is a
/// system-DNS concept and we only consult the fallback when system DNS
/// has already failed.
///
/// Security posture: the fallback only engages when `getaddrinfo` returned
/// an error (not a result). A successful getaddrinfo — including one that
/// returns a reserved IP — is still trusted and still blocked by the
/// reserved-IP check. The pre-existing time-of-check/time-of-use window
/// between validation and the actual outbound connect is unchanged.
static FALLBACK_RESOLVER: Lazy<TokioResolver> = Lazy::new(|| {
    let mut builder = TokioResolver::builder_with_config(
        ResolverConfig::udp_and_tcp(&GOOGLE),
        TokioRuntimeProvider::default(),
    );
    {
        let opts = builder.options_mut();
        opts.timeout = Duration::from_secs(5);
        opts.attempts = 2;
        opts.use_hosts_file = ResolveHosts::Never;
    }
    builder
        .build()
        .expect("hickory fallback resolver build is infallible with no TLS features")
});

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
/// Port is required because the primary resolution path goes through
/// `lookup_host`, which resolves services by `(host, port)`.
///
/// Uses the OS resolver (`getaddrinfo`) as the primary path and falls back
/// to hickory (Google DNS) only when the OS resolver returns an error —
/// see [`FALLBACK_RESOLVER`] for the security rationale.
///
/// Returns `Ok(())` when all resolved IPs are public; `Err(SeerError::InvalidInput)`
/// otherwise. Does NOT follow CNAMEs explicitly — relies on whichever
/// resolver answered.
pub async fn validate_public_host(host: &str, port: u16) -> Result<()> {
    resolve_public_host(host, port).await.map(|_| ())
}

/// Resolve a hostname to its public socket addresses, with hickory fallback.
///
/// Same security envelope as [`validate_public_host`] (OS resolver primary,
/// hickory fallback on OS error, reserved-IP rejection) but returns the
/// resolved [`SocketAddr`]s so callers can pass them to
/// [`tokio::net::TcpStream::connect`] without a second DNS round-trip.
///
/// Use this from any outbound-connect path so a broken system resolver
/// (corporate Macs, active VPNs, Tailscale Split-DNS claiming a domain
/// MagicDNS can't answer) doesn't take the path down.
pub async fn resolve_public_host(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    // Short-circuit: IP literal parse
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_reserved_ip(ip) {
            return Err(SeerError::InvalidInput(format!(
                "refusing to connect to reserved address: {}",
                ip
            )));
        }
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    let addrs: Vec<SocketAddr> = match lookup_host((host, port)).await {
        Ok(iter) => iter.collect(),
        Err(os_err) => {
            // OS resolver failed — fall back to hickory (Google DNS) so a
            // broken system resolver doesn't take the whole tool down.
            warn!(
                host = %host,
                error = %os_err,
                "system DNS resolution failed; retrying via hickory fallback"
            );
            match FALLBACK_RESOLVER.lookup_ip(host).await {
                Ok(resp) => resp.iter().map(|ip| SocketAddr::new(ip, port)).collect(),
                Err(fallback_err) => {
                    return Err(SeerError::InvalidInput(format!(
                        "DNS resolution failed for {host}: {os_err} (fallback: {fallback_err})"
                    )));
                }
            }
        }
    };

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

    Ok(addrs)
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

    /// Live-network sanity check for the fallback branch.
    ///
    /// The trailing dot forces an absolute lookup so `getaddrinfo` skips
    /// the host's search-domain list (otherwise a local resolver may
    /// append a search domain and rewrite an NXDOMAIN into a real hit —
    /// e.g. ISP wildcard captive-portal behavior). `.invalid` is reserved
    /// by RFC 2606 and must NXDOMAIN in upstream DNS, so hickory's Google
    /// DNS will also fail. When both fail, the guard returns an
    /// `InvalidInput` error whose text mentions the fallback, which
    /// proves the fallback actually ran (not just the primary path).
    #[tokio::test]
    #[ignore = "requires network — hits Google DNS via hickory fallback"]
    async fn validate_rejects_unresolvable_via_fallback() {
        let err = validate_public_host("nonexistent.host.invalid.", 443)
            .await
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("DNS resolution failed"), "got: {msg}");
        assert!(msg.contains("fallback"), "got: {msg}");
    }
}
