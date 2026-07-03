//! Upstream nameserver specification parsing.
//!
//! Every surface that accepts a custom nameserver (CLI `--server`/positional
//! nameservers, REPL `@server`, config `nameserver`, Python/REST/MCP) passes
//! an opaque string into [`crate::dns::DnsResolver`]'s custom-nameserver
//! path. This module is the single parser for that string, so all surfaces
//! get every transport for free:
//!
//! - **UDP** (classic DNS, port 53): `8.8.8.8`, `dns.google`,
//!   `9.9.9.9:5353`, `[2001:4860:4860::8888]:53`
//! - **DoT** (DNS over TLS, port 853): `tls://1.1.1.1`,
//!   `tls://dns.quad9.net:853`
//! - **DoH** (DNS over HTTPS, port 443, path `/dns-query`):
//!   `https://cloudflare-dns.com/dns-query`, `https://dns.google:443`
//!
//! Bare IPs/hostnames keep their historical UDP behavior byte-for-byte; the
//! `host:port` and bracketed-IPv6 forms are additive. Unbracketed IPv6
//! literals are always parsed as a plain address — bracket them
//! (`[2001:db8::1]:5353`) to attach a port.

use std::net::{IpAddr, Ipv6Addr};

use crate::error::{Result, SeerError};

/// Default port for plain (UDP) DNS.
const UDP_PORT: u16 = 53;
/// Default port for DNS over TLS (RFC 7858).
const TLS_PORT: u16 = 853;
/// Default port for DNS over HTTPS (RFC 8484).
const HTTPS_PORT: u16 = 443;
/// Conventional DoH query path used by every major public resolver.
const DEFAULT_DOH_PATH: &str = "/dns-query";

/// Transport protocol for an upstream nameserver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameserverProtocol {
    /// Classic DNS over UDP (with no scheme prefix).
    Udp,
    /// DNS over TLS (`tls://`), RFC 7858.
    Tls,
    /// DNS over HTTPS (`https://`), RFC 8484.
    Https,
}

/// A parsed upstream nameserver specification.
///
/// Produced by [`NameserverSpec::parse`] from the opaque nameserver strings
/// accepted everywhere in seer (CLI flags, REPL `@server`, `config.toml`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameserverSpec {
    /// Transport to speak to the upstream server.
    pub protocol: NameserverProtocol,
    /// Hostname or IP literal (IPv6 stored unbracketed).
    pub host: String,
    /// Target port (defaulted per protocol: 53 / 853 / 443).
    pub port: u16,
    /// DoH query path. Always `Some` for [`NameserverProtocol::Https`]
    /// (defaulting to `/dns-query`), always `None` otherwise.
    pub path: Option<String>,
}

impl NameserverSpec {
    /// Parses a nameserver specification string.
    ///
    /// Accepted forms:
    /// - `IP`, `hostname`, `host:port`, `[v6]`, `[v6]:port` → UDP (port 53)
    /// - `tls://host[:port]` → DoT (port 853)
    /// - `https://host[:port][/path]` → DoH (port 443, path `/dns-query`)
    ///
    /// # Errors
    /// Returns [`SeerError::InvalidInput`] for empty input, embedded
    /// whitespace, unknown schemes, malformed brackets, bad ports, a path on
    /// a `tls://` spec, or credentials in an `https://` spec.
    pub fn parse(input: &str) -> Result<Self> {
        let spec = input.trim();
        if spec.is_empty() {
            return Err(SeerError::InvalidInput(
                "nameserver must not be empty".to_string(),
            ));
        }
        if spec.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(SeerError::InvalidInput(format!(
                "nameserver must not contain whitespace: {spec:?}"
            )));
        }

        if let Some((scheme, rest)) = spec.split_once("://") {
            match scheme.to_ascii_lowercase().as_str() {
                "tls" => Self::parse_tls(rest),
                "https" => Self::parse_https(rest),
                other => Err(SeerError::InvalidInput(format!(
                    "unsupported nameserver scheme '{other}://' — use a bare IP/hostname (UDP), \
                     tls://host[:port] (DNS over TLS), or https://host[/path] (DNS over HTTPS)"
                ))),
            }
        } else {
            let (host, port) = parse_host_port(spec, UDP_PORT)?;
            Ok(Self {
                protocol: NameserverProtocol::Udp,
                host,
                port,
                path: None,
            })
        }
    }

    /// Parses the remainder of a `tls://` spec (`host[:port]`, no path).
    fn parse_tls(rest: &str) -> Result<Self> {
        if rest.contains('/') {
            return Err(SeerError::InvalidInput(format!(
                "tls:// nameservers do not take a path: tls://{rest} \
                 (paths are a DNS-over-HTTPS concept — use https:// for DoH)"
            )));
        }
        let (host, port) = parse_host_port(rest, TLS_PORT)?;
        Ok(Self {
            protocol: NameserverProtocol::Tls,
            host,
            port,
            path: None,
        })
    }

    /// Parses the remainder of an `https://` spec (`host[:port][/path]`).
    fn parse_https(rest: &str) -> Result<Self> {
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, DEFAULT_DOH_PATH.to_string()),
        };
        if authority.contains('@') {
            return Err(SeerError::InvalidInput(format!(
                "credentials are not supported in DoH nameserver URLs: https://{rest}"
            )));
        }
        let (host, port) = parse_host_port(authority, HTTPS_PORT)?;
        Ok(Self {
            protocol: NameserverProtocol::Https,
            host,
            port,
            path: Some(path),
        })
    }

    /// The TLS server name presented for certificate verification (DoT/DoH).
    ///
    /// For hostname specs this is the hostname. For IP-literal specs it is
    /// the IP itself: rustls accepts IP-address server names and verifies
    /// them against the certificate's IP SANs, which the major public
    /// resolvers (1.1.1.1, 8.8.8.8, 9.9.9.9, …) all carry.
    pub fn tls_name(&self) -> &str {
        &self.host
    }
}

impl std::fmt::Display for NameserverSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        match self.protocol {
            NameserverProtocol::Udp => write!(f, "{}:{}", host, self.port),
            NameserverProtocol::Tls => write!(f, "tls://{}:{}", host, self.port),
            NameserverProtocol::Https => write!(
                f,
                "https://{}:{}{}",
                host,
                self.port,
                self.path.as_deref().unwrap_or(DEFAULT_DOH_PATH)
            ),
        }
    }
}

/// Splits `host[:port]` (with bracketed-IPv6 support) into its parts,
/// applying `default_port` when no port is given.
///
/// Unbracketed strings that parse as an [`IpAddr`] are returned whole — an
/// IPv6 literal's trailing hextet is never misread as a port. Hostnames
/// cannot legally contain `:`, so for everything else a single trailing
/// `:port` is split off and validated.
fn parse_host_port(s: &str, default_port: u16) -> Result<(String, u16)> {
    if s.is_empty() {
        return Err(SeerError::InvalidInput(
            "nameserver host must not be empty".to_string(),
        ));
    }

    // Bracketed IPv6: [addr] or [addr]:port
    if let Some(rest) = s.strip_prefix('[') {
        let Some((addr, after)) = rest.split_once(']') else {
            return Err(SeerError::InvalidInput(format!(
                "unterminated '[' in nameserver address: {s}"
            )));
        };
        if addr.parse::<Ipv6Addr>().is_err() {
            return Err(SeerError::InvalidInput(format!(
                "invalid IPv6 literal in nameserver address: [{addr}]"
            )));
        }
        let port = match after {
            "" => default_port,
            _ => match after.strip_prefix(':') {
                Some(p) => parse_port(p)?,
                None => {
                    return Err(SeerError::InvalidInput(format!(
                        "expected ':port' after ']' in nameserver address: {s}"
                    )));
                }
            },
        };
        return Ok((addr.to_string(), port));
    }

    // A full IP literal (IPv4, or unbracketed IPv6 — which may contain many
    // colons) never has a port suffix.
    if s.parse::<IpAddr>().is_ok() {
        return Ok((s.to_string(), default_port));
    }

    // host:port — hostnames cannot contain ':'.
    if let Some((host, port)) = s.rsplit_once(':') {
        if host.contains(':') {
            return Err(SeerError::InvalidInput(format!(
                "invalid nameserver address {s}: bracket IPv6 literals to add \
                 a port (e.g. [2001:db8::1]:53)"
            )));
        }
        if host.is_empty() {
            return Err(SeerError::InvalidInput(format!(
                "nameserver host must not be empty: {s}"
            )));
        }
        return Ok((host.to_string(), parse_port(port)?));
    }

    Ok((s.to_string(), default_port))
}

/// Parses a decimal port number, rejecting 0, signs, and non-digits.
fn parse_port(s: &str) -> Result<u16> {
    // Reject sign characters explicitly: u16::from_str accepts a leading '+'.
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(SeerError::InvalidInput(format!(
            "invalid nameserver port: {s:?} (expected 1-65535)"
        )));
    }
    match s.parse::<u16>() {
        Ok(p) if p != 0 => Ok(p),
        _ => Err(SeerError::InvalidInput(format!(
            "invalid nameserver port: {s} (expected 1-65535)"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> NameserverSpec {
        NameserverSpec::parse(s).unwrap_or_else(|e| panic!("{s:?} must parse: {e}"))
    }

    fn parse_err(s: &str) -> String {
        match NameserverSpec::parse(s) {
            Err(SeerError::InvalidInput(msg)) => msg,
            Err(other) => panic!("{s:?} must fail with InvalidInput, got: {other:?}"),
            Ok(spec) => panic!("{s:?} must fail to parse, got: {spec:?}"),
        }
    }

    // --- UDP forms (historical behavior + additive host:port) ---------

    #[test]
    fn udp_bare_ipv4() {
        let spec = parse("8.8.8.8");
        assert_eq!(spec.protocol, NameserverProtocol::Udp);
        assert_eq!(spec.host, "8.8.8.8");
        assert_eq!(spec.port, 53);
        assert_eq!(spec.path, None);
    }

    #[test]
    fn udp_ipv4_with_port() {
        let spec = parse("9.9.9.9:5353");
        assert_eq!(spec.protocol, NameserverProtocol::Udp);
        assert_eq!(spec.host, "9.9.9.9");
        assert_eq!(spec.port, 5353);
    }

    #[test]
    fn udp_hostname() {
        let spec = parse("dns.google");
        assert_eq!(spec.protocol, NameserverProtocol::Udp);
        assert_eq!(spec.host, "dns.google");
        assert_eq!(spec.port, 53);
    }

    #[test]
    fn udp_hostname_with_port() {
        let spec = parse("dns.google:5353");
        assert_eq!(spec.host, "dns.google");
        assert_eq!(spec.port, 5353);
    }

    #[test]
    fn udp_unbracketed_ipv6_is_whole_address() {
        // The trailing hextet must NOT be misread as a port.
        let spec = parse("2606:4700:4700::1111");
        assert_eq!(spec.protocol, NameserverProtocol::Udp);
        assert_eq!(spec.host, "2606:4700:4700::1111");
        assert_eq!(spec.port, 53);
    }

    #[test]
    fn udp_bracketed_ipv6_without_port() {
        let spec = parse("[2606:4700:4700::1111]");
        assert_eq!(spec.host, "2606:4700:4700::1111");
        assert_eq!(spec.port, 53);
    }

    #[test]
    fn udp_bracketed_ipv6_with_port() {
        let spec = parse("[2001:4860:4860::8888]:5353");
        assert_eq!(spec.protocol, NameserverProtocol::Udp);
        assert_eq!(spec.host, "2001:4860:4860::8888");
        assert_eq!(spec.port, 5353);
    }

    #[test]
    fn udp_input_is_trimmed() {
        let spec = parse("  8.8.8.8  ");
        assert_eq!(spec.host, "8.8.8.8");
    }

    // --- DoT forms -----------------------------------------------------

    #[test]
    fn tls_ip_default_port() {
        let spec = parse("tls://1.1.1.1");
        assert_eq!(spec.protocol, NameserverProtocol::Tls);
        assert_eq!(spec.host, "1.1.1.1");
        assert_eq!(spec.port, 853);
        assert_eq!(spec.path, None);
        assert_eq!(spec.tls_name(), "1.1.1.1");
    }

    #[test]
    fn tls_hostname_with_port() {
        let spec = parse("tls://dns.quad9.net:8853");
        assert_eq!(spec.protocol, NameserverProtocol::Tls);
        assert_eq!(spec.host, "dns.quad9.net");
        assert_eq!(spec.port, 8853);
        assert_eq!(spec.tls_name(), "dns.quad9.net");
    }

    #[test]
    fn tls_bracketed_ipv6_with_port() {
        let spec = parse("tls://[2606:4700:4700::1111]:853");
        assert_eq!(spec.host, "2606:4700:4700::1111");
        assert_eq!(spec.port, 853);
    }

    #[test]
    fn tls_scheme_is_case_insensitive() {
        let spec = parse("TLS://1.1.1.1");
        assert_eq!(spec.protocol, NameserverProtocol::Tls);
    }

    #[test]
    fn tls_rejects_path() {
        let msg = parse_err("tls://dns.quad9.net/dns-query");
        assert!(msg.contains("do not take a path"), "got: {msg}");
    }

    #[test]
    fn tls_rejects_empty_host() {
        parse_err("tls://");
    }

    // --- DoH forms -----------------------------------------------------

    #[test]
    fn https_hostname_defaults_port_and_path() {
        let spec = parse("https://cloudflare-dns.com");
        assert_eq!(spec.protocol, NameserverProtocol::Https);
        assert_eq!(spec.host, "cloudflare-dns.com");
        assert_eq!(spec.port, 443);
        assert_eq!(spec.path.as_deref(), Some("/dns-query"));
    }

    #[test]
    fn https_explicit_path() {
        let spec = parse("https://dns.google/resolve");
        assert_eq!(spec.host, "dns.google");
        assert_eq!(spec.path.as_deref(), Some("/resolve"));
    }

    #[test]
    fn https_port_and_path() {
        let spec = parse("https://doh.example.net:8443/custom/query");
        assert_eq!(spec.host, "doh.example.net");
        assert_eq!(spec.port, 8443);
        assert_eq!(spec.path.as_deref(), Some("/custom/query"));
    }

    #[test]
    fn https_ip_literal_host() {
        let spec = parse("https://8.8.8.8/dns-query");
        assert_eq!(spec.host, "8.8.8.8");
        assert_eq!(spec.tls_name(), "8.8.8.8");
    }

    #[test]
    fn https_bracketed_ipv6_with_port_and_path() {
        let spec = parse("https://[2606:4700:4700::1111]:443/dns-query");
        assert_eq!(spec.host, "2606:4700:4700::1111");
        assert_eq!(spec.port, 443);
        assert_eq!(spec.path.as_deref(), Some("/dns-query"));
    }

    #[test]
    fn https_rejects_credentials() {
        let msg = parse_err("https://user:pass@dns.example.net/dns-query");
        assert!(msg.contains("credentials"), "got: {msg}");
    }

    // --- Garbage and scheme typos ---------------------------------------

    #[test]
    fn rejects_empty_and_blank() {
        parse_err("");
        parse_err("   ");
    }

    #[test]
    fn rejects_embedded_whitespace() {
        parse_err("8.8.8.8 example.com");
        parse_err("tls://dns\t.quad9.net");
    }

    #[test]
    fn rejects_unknown_schemes() {
        for bad in [
            "http://dns.google",
            "udp://8.8.8.8",
            "tcp://8.8.8.8",
            "quic://1.1.1.1",
        ] {
            let msg = parse_err(bad);
            assert!(
                msg.contains("unsupported nameserver scheme"),
                "{bad}: {msg}"
            );
        }
    }

    #[test]
    fn rejects_scheme_typos_as_bad_ports() {
        // "tls:/1.1.1.1" has no "://" so it falls into the UDP host:port
        // path, where the "/1.1.1.1" suffix is an invalid port.
        parse_err("tls:/1.1.1.1");
    }

    #[test]
    fn rejects_bad_ports() {
        parse_err("8.8.8.8:0");
        parse_err("8.8.8.8:65536");
        parse_err("8.8.8.8:abc");
        parse_err("8.8.8.8:+53"); // u16::from_str accepts '+'; the parser must not
        parse_err("dns.google:");
        parse_err("tls://dns.quad9.net:");
    }

    #[test]
    fn rejects_malformed_brackets() {
        parse_err("[2001:db8::1"); // unterminated
        parse_err("[not-an-ip]");
        parse_err("[2001:db8::1]junk"); // garbage after bracket
        parse_err("[]:53"); // empty literal
    }

    #[test]
    fn rejects_unbracketed_ipv6_plus_port_shape() {
        // Not a valid IPv6 literal and the "host" still contains colons —
        // must point the user at the bracketed form.
        let msg = parse_err("2001:db8::zz:53");
        assert!(msg.contains("bracket IPv6"), "got: {msg}");
    }

    #[test]
    fn rejects_empty_host_with_port() {
        parse_err(":53");
    }

    // --- Display ---------------------------------------------------------

    #[test]
    fn display_round_trips_reasonably() {
        assert_eq!(parse("8.8.8.8").to_string(), "8.8.8.8:53");
        assert_eq!(parse("tls://1.1.1.1").to_string(), "tls://1.1.1.1:853");
        assert_eq!(
            parse("https://dns.google").to_string(),
            "https://dns.google:443/dns-query"
        );
        assert_eq!(
            parse("[2001:db8::1]:5353").to_string(),
            "[2001:db8::1]:5353"
        );
    }
}
