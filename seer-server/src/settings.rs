//! Validated server settings and the startup checks.
//!
//! [`Settings::new`] turns the `[server]` config section and the API key
//! into settings the server can run on, or a [`StartupError`] that `main`
//! prints before exiting. The server is secure by default: without
//! `public = true` it will not start unless a key is set.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use axum::http::HeaderValue;
use ipnet::IpNet;
use seer_core::config::ServerConfig;

/// Which origins a browser page may read responses from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorsOrigins {
    /// No cross-origin access (the default).
    None,
    /// Any origin (`"*"` in the config).
    Any,
    /// Exactly these origins.
    List(Vec<HeaderValue>),
}

/// Settings the server runs on, already validated.
#[derive(Debug, Clone)]
pub struct Settings {
    /// Address to listen on.
    pub bind: SocketAddr,
    /// Whether anonymous callers may use the public routes.
    pub public: bool,
    /// Browser origin policy.
    pub cors: CorsOrigins,
    /// The API key, if one is set. Never logged.
    pub api_key: Option<String>,
    /// Proxies whose `X-Forwarded-For` header is believed.
    pub trusted_proxies: Vec<IpNet>,
    /// How many times the anonymous rate limit a keyed caller gets.
    pub keyed_rate_multiplier: u32,
    /// Deadline for one request: the wait for a slot plus the lookup.
    pub request_timeout: Duration,
    /// Lookups allowed to run at once.
    pub max_in_flight: usize,
    /// Lookups one anonymous client may have running at once.
    pub max_in_flight_per_client: u32,
    /// How long a successful response is reused; zero disables the cache.
    pub cache_ttl: Duration,
}

/// Shortest API key the server starts with. The key is the only thing
/// guarding the keyed routes, so a guessable one is refused outright.
pub const MIN_KEY_LENGTH: usize = 16;

/// Narrowest prefix a `trusted_proxies` range may have. Anything broader
/// trusts a large share of all addresses (two `/1`s trust everyone); real
/// proxy and CDN ranges are far narrower than this.
const MIN_PROXY_PREFIX_V4: u8 = 8;
const MIN_PROXY_PREFIX_V6: u8 = 16;

/// Why the server will not start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupError {
    /// `[server] bind` is not an `address:port`.
    InvalidBind(String),
    /// A `[server] cors_origins` entry is not `scheme://host[:port]`.
    InvalidOrigin(String),
    /// A `[server] trusted_proxies` entry is not an IP address or a range.
    InvalidProxy(String),
    /// A `[server] trusted_proxies` range is broader than any real proxy
    /// range.
    ProxyRangeTooBroad(String),
    /// `SEER_API_KEY` is shorter than [`MIN_KEY_LENGTH`].
    KeyTooShort,
    /// `public = false` and no API key: nobody could call anything.
    KeyRequired,
}

impl fmt::Display for StartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StartupError::InvalidBind(bind) => write!(
                f,
                "[server] bind = {bind:?} is not an address and port (e.g. \"127.0.0.1:8001\")"
            ),
            StartupError::InvalidOrigin(origin) => write!(
                f,
                "[server] cors_origins entry {origin:?} is not an origin \
                 (e.g. \"https://example.com\", no path or trailing slash)"
            ),
            StartupError::InvalidProxy(entry) => write!(
                f,
                "[server] trusted_proxies entry {entry:?} is not an IP address or \
                 a range (e.g. \"127.0.0.1\", \"10.0.0.0/8\")"
            ),
            StartupError::ProxyRangeTooBroad(entry) => write!(
                f,
                "[server] trusted_proxies entry {entry:?} is too broad (at most a /{MIN_PROXY_PREFIX_V4} \
                 for IPv4, a /{MIN_PROXY_PREFIX_V6} for IPv6): any caller inside it could claim \
                 any identity. List only your reverse proxies"
            ),
            StartupError::KeyTooShort => write!(
                f,
                "refusing to start: SEER_API_KEY is shorter than {MIN_KEY_LENGTH} characters. \
                 Use a long random value, e.g. from `openssl rand -hex 32`"
            ),
            StartupError::KeyRequired => write!(
                f,
                "refusing to start: [server] public is false and SEER_API_KEY is not set. \
                 Set SEER_API_KEY, or set public = true to serve the public routes without a key"
            ),
        }
    }
}

impl std::error::Error for StartupError {}

impl Settings {
    /// Validates the `[server]` section and the API key (the value of
    /// `SEER_API_KEY`, if set). A blank key counts as none.
    pub fn new(server: &ServerConfig, api_key: Option<String>) -> Result<Self, StartupError> {
        let bind = server
            .bind
            .parse::<SocketAddr>()
            .map_err(|_| StartupError::InvalidBind(server.bind.clone()))?;
        let api_key = api_key
            .map(|key| key.trim().to_string())
            .filter(|key| !key.is_empty());
        if !server.public && api_key.is_none() {
            return Err(StartupError::KeyRequired);
        }
        if api_key
            .as_ref()
            .is_some_and(|key| key.chars().count() < MIN_KEY_LENGTH)
        {
            return Err(StartupError::KeyTooShort);
        }
        Ok(Self {
            bind,
            public: server.public,
            cors: parse_origins(&server.cors_origins)?,
            api_key,
            trusted_proxies: parse_proxies(&server.trusted_proxies)?,
            keyed_rate_multiplier: server.keyed_rate_multiplier,
            request_timeout: Duration::from_secs(server.request_timeout_secs),
            max_in_flight: server.max_in_flight,
            max_in_flight_per_client: server.max_in_flight_per_client,
            cache_ttl: Duration::from_secs(server.cache_ttl_secs),
        })
    }

    /// Things worth telling the operator at startup that do not stop the
    /// server.
    pub fn warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if self.public && self.trusted_proxies.is_empty() {
            warnings.push(
                "[server] public is true and trusted_proxies is empty: behind a reverse \
                 proxy every visitor shares the proxy's rate-limit bucket. List the \
                 proxy's address in trusted_proxies"
                    .to_string(),
            );
        }
        for net in &self.trusted_proxies {
            if is_broad_private_range(net) {
                warnings.push(format!(
                    "[server] trusted_proxies entry {net} is a whole private network: any \
                     client inside it can choose the address it is rate-limited as. List \
                     only your reverse proxies"
                ));
            }
        }
        warnings
    }
}

/// `"*"` anywhere allows any origin; otherwise every entry must be a bare
/// origin, which is what a browser sends in its `Origin` header.
fn parse_origins(origins: &[String]) -> Result<CorsOrigins, StartupError> {
    if origins.iter().any(|origin| origin.trim() == "*") {
        return Ok(CorsOrigins::Any);
    }
    let mut list = Vec::with_capacity(origins.len());
    for origin in origins {
        let trimmed = origin.trim();
        let host = trimmed
            .strip_prefix("https://")
            .or_else(|| trimmed.strip_prefix("http://"));
        let valid = host.is_some_and(|host| !host.is_empty() && !host.contains('/'));
        match (valid, HeaderValue::from_str(trimmed)) {
            (true, Ok(value)) => list.push(value),
            _ => return Err(StartupError::InvalidOrigin(origin.clone())),
        }
    }
    Ok(if list.is_empty() {
        CorsOrigins::None
    } else {
        CorsOrigins::List(list)
    })
}

/// Each entry is an IP address (one host) or a CIDR range.
fn parse_proxies(entries: &[String]) -> Result<Vec<IpNet>, StartupError> {
    entries
        .iter()
        .map(|entry| {
            let trimmed = entry.trim();
            trimmed
                .parse::<IpNet>()
                .or_else(|_| trimmed.parse::<IpAddr>().map(IpNet::from))
                .map_err(|_| StartupError::InvalidProxy(entry.clone()))
                .and_then(|net| {
                    let narrowest = match net {
                        IpNet::V4(_) => MIN_PROXY_PREFIX_V4,
                        IpNet::V6(_) => MIN_PROXY_PREFIX_V6,
                    };
                    if net.prefix_len() < narrowest {
                        Err(StartupError::ProxyRangeTooBroad(entry.clone()))
                    } else {
                        Ok(net)
                    }
                })
        })
        .collect()
}

/// A private (RFC 1918 or unique-local) range wider than one subnet. A
/// broad *public* range is not flagged: a CDN's published proxy blocks are
/// broad on purpose, and no client sits inside them.
fn is_broad_private_range(net: &IpNet) -> bool {
    match net {
        IpNet::V4(v4) => v4.prefix_len() < 24 && v4.network().is_private(),
        IpNet::V6(v6) => v6.prefix_len() < 64 && v6.network().is_unique_local(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::KEY;

    fn server(bind: &str, public: bool, origins: &[&str]) -> ServerConfig {
        ServerConfig {
            bind: bind.to_string(),
            public,
            cors_origins: origins.iter().map(|s| s.to_string()).collect(),
            ..ServerConfig::default()
        }
    }

    #[test]
    fn defaults_with_a_key_are_accepted() {
        let settings = Settings::new(
            &ServerConfig::default(),
            Some("s3cret-s3cret-s3cret".into()),
        )
        .unwrap();
        assert_eq!(settings.bind.to_string(), "127.0.0.1:8001");
        assert!(!settings.public);
        assert_eq!(settings.cors, CorsOrigins::None);
        assert_eq!(settings.api_key.as_deref(), Some("s3cret-s3cret-s3cret"));
    }

    #[test]
    fn private_without_a_key_refuses_to_start() {
        let error = Settings::new(&ServerConfig::default(), None).unwrap_err();
        assert_eq!(error, StartupError::KeyRequired);
        assert!(error.to_string().contains("SEER_API_KEY"));
    }

    #[test]
    fn a_blank_key_is_no_key() {
        let error = Settings::new(&ServerConfig::default(), Some("  \n".into())).unwrap_err();
        assert_eq!(error, StartupError::KeyRequired);
    }

    #[test]
    fn a_key_is_trimmed() {
        let settings = Settings::new(
            &ServerConfig::default(),
            Some(" sixteen-chars-xy \n".into()),
        )
        .unwrap();
        assert_eq!(settings.api_key.as_deref(), Some("sixteen-chars-xy"));
    }

    #[test]
    fn a_short_key_refuses_to_start() {
        // A key is the only thing guarding the keyed routes.
        for key in ["k", "short", "fifteen-chars-x"] {
            let error = Settings::new(&ServerConfig::default(), Some(key.into())).unwrap_err();
            assert_eq!(error, StartupError::KeyTooShort, "{key}");
        }
        assert!(Settings::new(&ServerConfig::default(), Some("sixteen-chars-xy".into())).is_ok());
        assert!(StartupError::KeyTooShort.to_string().contains("16"));
    }

    #[test]
    fn an_over_broad_proxy_range_is_refused() {
        // Halves of the address space trust everyone as surely as /0 does.
        for entry in [
            "0.0.0.0/1",
            "128.0.0.0/1",
            "0.0.0.0/7",
            "::/1",
            "2000::/3",
            "::/15",
        ] {
            let server = ServerConfig {
                public: true,
                trusted_proxies: vec![entry.to_string()],
                ..ServerConfig::default()
            };
            assert_eq!(
                Settings::new(&server, None).unwrap_err(),
                StartupError::ProxyRangeTooBroad(entry.to_string()),
                "{entry}"
            );
        }
        // Real proxy and CDN ranges are far narrower.
        for entry in ["10.0.0.0/8", "104.16.0.0/13", "2400:cb00::/32", "fd00::/16"] {
            let server = ServerConfig {
                public: true,
                trusted_proxies: vec![entry.to_string()],
                ..ServerConfig::default()
            };
            assert!(Settings::new(&server, None).is_ok(), "{entry}");
        }
    }

    #[test]
    fn public_without_a_key_is_accepted() {
        let settings = Settings::new(&server("127.0.0.1:8001", true, &[]), None).unwrap();
        assert!(settings.public);
        assert_eq!(settings.api_key, None);
    }

    #[test]
    fn invalid_bind_is_a_startup_error() {
        for bind in [
            "",
            "localhost",
            "127.0.0.1",
            "127.0.0.1:99999",
            "not an address",
        ] {
            let error = Settings::new(&server(bind, true, &[]), None).unwrap_err();
            assert_eq!(error, StartupError::InvalidBind(bind.to_string()));
        }
    }

    #[test]
    fn origins_are_parsed_and_a_star_means_any() {
        let listed = Settings::new(
            &server(
                "127.0.0.1:1",
                true,
                &["https://example.com", "http://localhost:3000"],
            ),
            None,
        )
        .unwrap();
        assert_eq!(
            listed.cors,
            CorsOrigins::List(vec![
                HeaderValue::from_static("https://example.com"),
                HeaderValue::from_static("http://localhost:3000"),
            ])
        );
        let any =
            Settings::new(&server("127.0.0.1:1", true, &["https://a.test", "*"]), None).unwrap();
        assert_eq!(any.cors, CorsOrigins::Any);
    }

    #[test]
    fn a_malformed_origin_is_a_startup_error() {
        for origin in [
            "example.com",
            "https://example.com/",
            "https://example.com/app",
            "ftp://x",
        ] {
            let error = Settings::new(&server("127.0.0.1:1", true, &[origin]), None).unwrap_err();
            assert_eq!(error, StartupError::InvalidOrigin(origin.to_string()));
        }
    }

    #[test]
    fn protection_settings_carry_over_with_units() {
        let settings = Settings::new(&ServerConfig::default(), Some(KEY.into())).unwrap();
        assert!(settings.trusted_proxies.is_empty());
        assert_eq!(settings.keyed_rate_multiplier, 10);
        assert_eq!(settings.request_timeout, Duration::from_secs(30));
        assert_eq!(settings.max_in_flight, 64);
        assert_eq!(settings.cache_ttl, Duration::from_secs(60));
    }

    #[test]
    fn trusted_proxies_accept_addresses_and_ranges() {
        let server = ServerConfig {
            trusted_proxies: vec![
                "127.0.0.1".into(),
                " 10.0.0.0/8 ".into(),
                "2001:db8::/32".into(),
                "::1".into(),
            ],
            ..ServerConfig::default()
        };
        let settings = Settings::new(&server, Some(KEY.into())).unwrap();
        let contains = |ip: &str| {
            let ip: IpAddr = ip.parse().unwrap();
            settings.trusted_proxies.iter().any(|net| net.contains(&ip))
        };
        assert!(contains("127.0.0.1"));
        assert!(
            !contains("127.0.0.2"),
            "a bare address is one host, not a range"
        );
        assert!(contains("10.200.3.4"));
        assert!(contains("2001:db8:ffff::1"));
        assert!(contains("::1"));
        assert!(!contains("192.0.2.1"));
    }

    #[test]
    fn a_malformed_proxy_is_a_startup_error() {
        for entry in ["proxy.internal", "10.0.0.0/33", "", "10.0.0.1:80"] {
            let server = ServerConfig {
                trusted_proxies: vec![entry.to_string()],
                ..ServerConfig::default()
            };
            let error = Settings::new(&server, Some(KEY.into())).unwrap_err();
            assert_eq!(error, StartupError::InvalidProxy(entry.to_string()));
        }
    }

    #[test]
    fn a_public_server_with_no_trusted_proxy_is_warned_about() {
        let public = ServerConfig {
            public: true,
            ..ServerConfig::default()
        };
        let warnings = Settings::new(&public, None).unwrap().warnings();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("trusted_proxies"), "{warnings:?}");

        let proxied = ServerConfig {
            public: true,
            trusted_proxies: vec!["127.0.0.1".into()],
            ..ServerConfig::default()
        };
        assert!(Settings::new(&proxied, None).unwrap().warnings().is_empty());
        // A private server limits by key, so the client IP does not matter.
        let private = Settings::new(&ServerConfig::default(), Some(KEY.into())).unwrap();
        assert!(private.warnings().is_empty());
    }
    #[test]
    fn trusting_every_address_is_a_startup_error() {
        // Under /0 every forwarded entry is "a proxy": callers could claim
        // any identity, or none could be told apart.
        for entry in ["0.0.0.0/0", "::/0"] {
            let server = ServerConfig {
                trusted_proxies: vec![entry.to_string()],
                ..ServerConfig::default()
            };
            let error = Settings::new(&server, Some(KEY.into())).unwrap_err();
            assert_eq!(error, StartupError::ProxyRangeTooBroad(entry.to_string()));
            assert!(error.to_string().contains("too broad"), "{error}");
        }
    }

    #[test]
    fn a_broad_private_proxy_range_is_warned_about() {
        let warnings = |proxies: &[&str]| {
            let server = ServerConfig {
                public: true,
                trusted_proxies: proxies.iter().map(|s| s.to_string()).collect(),
                ..ServerConfig::default()
            };
            Settings::new(&server, None).unwrap().warnings()
        };
        // "Trust my whole network": a client inside it can choose its own
        // identity.
        for broad in ["10.0.0.0/8", "192.168.0.0/16", "fd00::/16"] {
            let found = warnings(&[broad]);
            assert_eq!(found.len(), 1, "{broad}: {found:?}");
            assert!(found[0].contains(broad), "{found:?}");
        }
        // Single hosts, small private ranges and public ranges (a CDN's
        // published blocks are broad on purpose) are not.
        for fine in ["10.0.0.5", "10.0.0.0/24", "fd00::/64", "104.16.0.0/13"] {
            assert!(warnings(&[fine]).is_empty(), "{fine}");
        }
    }
}
