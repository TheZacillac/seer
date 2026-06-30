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
use tracing::debug;

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
static FALLBACK_RESOLVER: Lazy<Option<TokioResolver>> = Lazy::new(|| {
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
    // Mirror the `Lazy<Option<…>>` pattern used for the shared HTTP clients
    // rather than `.expect()` in a library initializer: the build is infallible
    // today (no TLS features), but a `None` here degrades to a typed DNS error
    // at the call site instead of a process panic if that ever changes.
    builder.build().ok()
});

/// Upper bound on the primary OS-resolver (`getaddrinfo`) lookup in
/// [`resolve_public_host`]. `getaddrinfo` has no built-in deadline; this cap
/// stops a single hostile/black-holed hostname from hanging a worker thread
/// indefinitely. Matches the fallback resolver's 5s per-attempt budget.
const PRIMARY_RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Reject an IP address if it belongs to any range that is not appropriate
/// for outbound queries from a public-facing tool.
///
/// This is the single source of truth for SSRF range checks across every
/// outbound leg (RDAP, WHOIS, status, DNS). It covers, for IPv4: loopback,
/// private (RFC1918), link-local (incl. 169.254.169.254 metadata), multicast,
/// broadcast, unspecified, 0.0.0.0/8, documentation (RFC5737), CGNAT
/// (100.64/10), IETF 192.0.0.0/24, benchmark (198.18/15), and class-E
/// (240/4); and for IPv6: loopback, multicast, unspecified, ULA (fc00::/7),
/// link-local (fe80::/10), site-local (fec0::/10), documentation
/// (2001:db8::/32), 6to4 (2002::/16),
/// NAT64 (64:ff9b::/96), and the IPv4-mapped/-compatible forms (re-checking
/// the embedded IPv4).
pub fn is_reserved_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_documentation()
                // 0.0.0.0/8 — "this network" (RFC 1122).
                || o[0] == 0
                // 240.0.0.0/4 — reserved (former class E).
                || o[0] >= 240
                // 100.64.0.0/10 — carrier-grade NAT / shared address space.
                || (o[0] == 100 && (o[1] & 0xC0) == 64)
                // 192.0.0.0/24 — IETF protocol assignments.
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                // 198.18.0.0/15 — network benchmark.
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_multicast() || v6.is_unspecified() {
                return true;
            }
            let seg = v6.segments();
            // Unique-local fc00::/7
            if (seg[0] & 0xfe00) == 0xfc00 {
                return true;
            }
            // Link-local fe80::/10
            if (seg[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            // Site-local fec0::/10 (RFC 3879, deprecated but still a non-global,
            // internal-only range a malicious AAAA could point at).
            if (seg[0] & 0xffc0) == 0xfec0 {
                return true;
            }
            // Documentation 2001:db8::/32
            if seg[0] == 0x2001 && seg[1] == 0x0db8 {
                return true;
            }
            // 6to4 2002::/16 — embeds an IPv4 a 6to4 relay can reach (e.g.
            // 2002:a9fe:a9fe:: -> 169.254.169.254); block the whole prefix.
            if seg[0] == 0x2002 {
                return true;
            }
            // NAT64 well-known prefix 64:ff9b::/96 — a NAT64 gateway translates
            // the embedded IPv4, including private/metadata ranges.
            if seg[0] == 0x0064
                && seg[1] == 0xff9b
                && seg[2] == 0
                && seg[3] == 0
                && seg[4] == 0
                && seg[5] == 0
            {
                return true;
            }
            // NAT64 RFC 8215 local-use prefix 64:ff9b:1::/48 — same translation
            // risk as the well-known /96; block the whole /48 (issue #52).
            if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2] == 0x0001 {
                return true;
            }
            // IPv4-mapped (::ffff:0:0/96) — re-check the embedded IPv4.
            if v6
                .to_ipv4_mapped()
                .is_some_and(|v4| is_reserved_ip(IpAddr::V4(v4)))
            {
                return true;
            }
            // IPv4-compatible (::/96, deprecated) — high 96 bits zero, low 32
            // an IPv4. `to_ipv4_mapped()` does NOT catch this form, so re-check
            // the embedded IPv4 (catches ::169.254.169.254). :: and ::1 are
            // already handled above.
            if seg[0] == 0
                && seg[1] == 0
                && seg[2] == 0
                && seg[3] == 0
                && seg[4] == 0
                && seg[5] == 0
            {
                let embedded = std::net::Ipv4Addr::from(((seg[6] as u32) << 16) | seg[7] as u32);
                if is_reserved_ip(IpAddr::V4(embedded)) {
                    return true;
                }
            }
            false
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

    // Cap the primary OS-resolver (`getaddrinfo`) lookup: it has no built-in
    // deadline and can hang indefinitely against a black-holed authoritative
    // server, which would pin a worker/dispatch thread forever (a cheap DoS).
    // On timeout we treat it like an OS-resolver error and fall through to the
    // hickory fallback, which is itself bounded (opts.timeout / attempts).
    let addrs: Vec<SocketAddr> = match tokio::time::timeout(
        PRIMARY_RESOLVE_TIMEOUT,
        lookup_host((host, port)),
    )
    .await
    {
        Ok(Ok(iter)) => iter.collect(),
        os_failure => {
            // OS resolver could not answer (error or timeout) — fall back to
            // hickory (Google DNS) so a broken/hung system resolver doesn't
            // take the whole tool down. Logged at debug! because the fallback
            // is transparent by design; NXDOMAIN for a host that genuinely
            // doesn't exist (e.g. a stale WHOIS server entry) lands here too,
            // so warn! would cry wolf on benign negative answers. If BOTH
            // resolvers fail, the InvalidInput error below is the
            // load-bearing signal.
            let os_err = match os_failure {
                Ok(Err(e)) => e.to_string(),
                _ => format!(
                    "OS resolver timed out after {}s",
                    PRIMARY_RESOLVE_TIMEOUT.as_secs()
                ),
            };
            debug!(
                host = %host,
                error = %os_err,
                "OS resolver could not resolve host; trying hickory fallback"
            );
            let Some(resolver) = FALLBACK_RESOLVER.as_ref() else {
                return Err(SeerError::InvalidInput(format!(
                    "DNS resolution failed for {host}: {os_err} (no fallback resolver available)"
                )));
            };
            match resolver.lookup_ip(host).await {
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
            // Keep the resolved IP out of the client-facing error: echoing it
            // turned the SSRF guard into an internal-DNS oracle (a caller could
            // learn that `internal.corp.example` resolves to 10.1.2.3). The
            // detailed reason stays in the server logs only (issue #49).
            debug!(
                host = %host,
                resolved_ip = %sa.ip(),
                "refusing host: resolves to a reserved (non-public) address"
            );
            return Err(SeerError::InvalidInput(format!(
                "{host} is not permitted (resolves to a non-public address)"
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
    fn rejects_ipv6_site_local() {
        // fec0::/10 (RFC 3879, deprecated) is a non-global internal range.
        assert!(is_reserved_ip("fec0::1".parse().unwrap()));
        assert!(is_reserved_ip("feff::1".parse().unwrap()));
    }

    #[test]
    fn rejects_ipv4_mapped_loopback() {
        assert!(is_reserved_ip("::ffff:127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn rejects_ipv4_mapped_cgnat() {
        // ::ffff:100.64.0.1 must inherit the embedded IPv4's CGNAT block.
        assert!(is_reserved_ip("::ffff:100.64.0.1".parse().unwrap()));
    }

    #[test]
    fn rejects_class_e_reserved() {
        assert!(is_reserved_ip("240.0.0.1".parse().unwrap()));
        assert!(is_reserved_ip("250.1.2.3".parse().unwrap()));
    }

    #[test]
    fn rejects_this_network_0_8() {
        // 0.0.0.0/8 "this network" (RFC 1122), not just 0.0.0.0.
        assert!(is_reserved_ip("0.1.2.3".parse().unwrap()));
    }

    #[test]
    fn rejects_ipv6_nat64_of_metadata() {
        // 64:ff9b::169.254.169.254 — NAT64 well-known prefix wrapping the
        // cloud-metadata endpoint.
        assert!(is_reserved_ip("64:ff9b::a9fe:a9fe".parse().unwrap()));
    }

    #[test]
    fn rejects_ipv6_6to4() {
        // 2002:a9fe:a9fe:: — 6to4 encoding of 169.254.169.254.
        assert!(is_reserved_ip("2002:a9fe:a9fe::".parse().unwrap()));
    }

    #[test]
    fn rejects_ipv6_nat64_rfc8215_local_use_prefix() {
        // RFC 8215 local-use NAT64 prefix 64:ff9b:1::/48 — a NAT64 gateway on
        // this prefix translates the embedded IPv4 (incl. metadata), so the
        // whole /48 must be blocked alongside the well-known /96 (issue #52).
        assert!(is_reserved_ip("64:ff9b:1::a9fe:a9fe".parse().unwrap()));
        assert!(is_reserved_ip("64:ff9b:1:ffff::1".parse().unwrap()));
        // A different second-label value is NOT the local-use prefix and is a
        // normal global-unicast address — must remain allowed.
        assert!(!is_reserved_ip("64:ff9b:2::1".parse().unwrap()));
    }

    #[test]
    fn rejects_ipv4_compatible_metadata() {
        // ::169.254.169.254 — deprecated IPv4-compatible form embedding the
        // metadata IP (to_ipv4_mapped() does NOT catch this).
        assert!(is_reserved_ip("::a9fe:a9fe".parse().unwrap()));
    }

    #[test]
    fn rejects_ipv6_documentation() {
        assert!(is_reserved_ip("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn allows_ipv4_compatible_public() {
        // ::8.8.8.8 embeds a public IPv4 — not reserved.
        assert!(!is_reserved_ip("::808:808".parse().unwrap()));
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

    #[tokio::test]
    async fn reserved_resolution_error_does_not_leak_resolved_ip() {
        // A hostname that resolves to a reserved address must be refused
        // WITHOUT echoing the resolved internal IP to the caller — that turned
        // the SSRF guard into an internal-DNS oracle (issue #49). `localhost`
        // resolves to a loopback address via the OS resolver/hosts file.
        let err = validate_public_host("localhost", 80).await.unwrap_err();
        assert!(matches!(err, SeerError::InvalidInput(_)));
        let msg = err.to_string();
        assert!(
            !msg.contains("127.0.0.1"),
            "must not leak resolved IPv4: {msg}"
        );
        assert!(!msg.contains("::1"), "must not leak resolved IPv6: {msg}");
        assert!(
            !msg.contains("resolves to reserved address"),
            "must not echo the resolved-address detail: {msg}"
        );
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
