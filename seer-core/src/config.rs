//! Configuration file support for Seer.
//!
//! Loads settings from `~/.seer/config.toml` with environment variable overrides.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::debug;

/// Seer configuration loaded from `~/.seer/config.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SeerConfig {
    /// Default output format ("human", "json", "yaml")
    pub output_format: String,
    /// Default DNS nameserver spec. Accepts a bare IP/hostname with an
    /// optional port (UDP, e.g. `"8.8.8.8"`, `"dns.google"`,
    /// `"[2001:4860:4860::8888]:53"`), `tls://host[:port]` for DNS over TLS
    /// (default port 853, e.g. `"tls://1.1.1.1"`), or
    /// `https://host[:port][/path]` for DNS over HTTPS (default port 443,
    /// default path `/dns-query`, e.g. `"https://cloudflare-dns.com/dns-query"`).
    /// Parsed by [`crate::dns::NameserverSpec`]; invalid specs surface as an
    /// error on first use rather than at load time.
    pub nameserver: Option<String>,
    /// Timeout settings
    pub timeouts: TimeoutConfig,
    /// Bulk operation settings
    pub bulk: BulkConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TimeoutConfig {
    /// WHOIS query timeout in seconds
    pub whois_secs: u64,
    /// RDAP query timeout in seconds
    pub rdap_secs: u64,
    /// DNS query timeout in seconds
    pub dns_secs: u64,
    /// HTTP/SSL check timeout in seconds
    pub http_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BulkConfig {
    /// Default concurrency for bulk operations
    pub concurrency: usize,
    /// Rate limit delay in milliseconds between operations
    pub rate_limit_ms: u64,
}

impl Default for SeerConfig {
    fn default() -> Self {
        Self {
            output_format: "human".to_string(),
            nameserver: None,
            timeouts: TimeoutConfig::default(),
            bulk: BulkConfig::default(),
        }
    }
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            whois_secs: 15,
            // Matches the RDAP client's own DEFAULT_TIMEOUT (15s) and the
            // documented value; the client uses 15s, so the default must too.
            rdap_secs: 15,
            dns_secs: 5,
            http_secs: 10,
        }
    }
}

impl Default for BulkConfig {
    fn default() -> Self {
        Self {
            concurrency: 10,
            rate_limit_ms: 100,
        }
    }
}

impl SeerConfig {
    /// Returns the path to the config file (`~/.seer/config.toml`).
    pub fn config_path() -> Option<PathBuf> {
        dirs::home_dir().map(|home| home.join(".seer").join("config.toml"))
    }

    /// Loads config from `~/.seer/config.toml`, falling back to defaults if not found.
    pub fn load() -> Self {
        let Some(path) = Self::config_path() else {
            return Self::default();
        };

        if !path.exists() {
            return Self::default();
        }

        match std::fs::read_to_string(&path) {
            Ok(content) => Self::parse_or_default(&content, &path),
            Err(e) => {
                debug!(?path, error = %e, "Could not read config, using defaults");
                Self::default()
            }
        }
    }

    /// Parses config file content, falling back to defaults on malformed
    /// TOML. The failure is reported on stderr in addition to `tracing` —
    /// at the default log level a `warn!` is invisible, and `seer config`
    /// would then display defaults as though they came from the file.
    fn parse_or_default(content: &str, path: &std::path::Path) -> Self {
        match toml::from_str::<SeerConfig>(content) {
            Ok(config) => {
                debug!(?path, "Loaded config");
                config.clamped()
            }
            Err(e) => {
                tracing::warn!(?path, error = %e, "Failed to parse config, using defaults");
                // Config loads several times per process (startup + per-command
                // and per-client construction); warn on stderr only once — the
                // CLI always loads first at startup, so the warning also lands
                // before the TUI enters its alternate screen.
                static WARN_ONCE: std::sync::Once = std::sync::Once::new();
                WARN_ONCE.call_once(|| {
                    eprintln!(
                        "Warning: ignoring malformed config file {} (using defaults):\n{}",
                        path.display(),
                        e
                    );
                });
                Self::default()
            }
        }
    }

    /// Clamp loaded values into sane ranges. Without this, a user
    /// (accidentally or maliciously) setting `bulk.concurrency = 0` would
    /// hand `Semaphore::new(0)` to every bulk operation and block forever;
    /// `bulk.concurrency = 10000` would spawn thousands of concurrent
    /// connections. Timeouts of `0` would error every network call
    /// immediately. The bounds are per-protocol (a config file can't bypass
    /// them): concurrency 1–50; whois/rdap timeouts 1–300s; dns 1–60s;
    /// http 1–120s.
    fn clamped(mut self) -> Self {
        self.bulk.concurrency = self.bulk.concurrency.clamp(1, 50);
        // A multi-day per-operation delay would stall bulk runs indefinitely;
        // cap at 60s (0 is valid — no inter-operation delay).
        self.bulk.rate_limit_ms = self.bulk.rate_limit_ms.min(60_000);
        self.timeouts.whois_secs = self.timeouts.whois_secs.clamp(1, 300);
        self.timeouts.rdap_secs = self.timeouts.rdap_secs.clamp(1, 300);
        self.timeouts.dns_secs = self.timeouts.dns_secs.clamp(1, 60);
        self.timeouts.http_secs = self.timeouts.http_secs.clamp(1, 120);
        self
    }

    /// Returns the WHOIS timeout as a Duration.
    pub fn whois_timeout(&self) -> Duration {
        Duration::from_secs(self.timeouts.whois_secs)
    }

    /// Returns the RDAP timeout as a Duration.
    pub fn rdap_timeout(&self) -> Duration {
        Duration::from_secs(self.timeouts.rdap_secs)
    }

    /// Returns the DNS timeout as a Duration.
    pub fn dns_timeout(&self) -> Duration {
        Duration::from_secs(self.timeouts.dns_secs)
    }

    /// Returns the HTTP timeout as a Duration.
    pub fn http_timeout(&self) -> Duration {
        Duration::from_secs(self.timeouts.http_secs)
    }

    /// Returns the inter-operation bulk rate-limit delay as a Duration.
    pub fn bulk_rate_limit(&self) -> Duration {
        Duration::from_millis(self.bulk.rate_limit_ms)
    }

    /// Generates a default config file content as TOML.
    pub fn default_toml() -> String {
        toml::to_string_pretty(&Self::default()).unwrap_or_else(|_| String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SeerConfig::default();
        assert_eq!(config.output_format, "human");
        assert_eq!(config.timeouts.whois_secs, 15);
        assert_eq!(config.timeouts.rdap_secs, 15);
        assert_eq!(config.timeouts.dns_secs, 5);
        assert_eq!(config.bulk.concurrency, 10);
    }

    #[test]
    fn test_parse_config_toml() {
        let toml_str = r#"
output_format = "json"
nameserver = "1.1.1.1"

[timeouts]
whois_secs = 20
rdap_secs = 45

[bulk]
concurrency = 20
"#;
        let config: SeerConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.output_format, "json");
        assert_eq!(config.nameserver, Some("1.1.1.1".to_string()));
        assert_eq!(config.timeouts.whois_secs, 20);
        assert_eq!(config.timeouts.rdap_secs, 45);
        assert_eq!(config.timeouts.dns_secs, 5); // default
        assert_eq!(config.bulk.concurrency, 20);
    }

    #[test]
    fn nameserver_accepts_dot_doh_specs_opaquely() {
        // The nameserver key is an opaque spec string: DoT/DoH forms load
        // unchanged and are validated by NameserverSpec::parse on first use,
        // not at config-load time.
        let config: SeerConfig = toml::from_str(r#"nameserver = "tls://1.1.1.1""#).unwrap();
        assert_eq!(config.nameserver.as_deref(), Some("tls://1.1.1.1"));
    }

    #[test]
    fn test_default_toml_roundtrip() {
        let toml_str = SeerConfig::default_toml();
        let config: SeerConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(config.output_format, "human");
    }

    #[test]
    fn test_timeout_durations() {
        let config = SeerConfig::default();
        assert_eq!(config.whois_timeout(), Duration::from_secs(15));
        assert_eq!(config.rdap_timeout(), Duration::from_secs(15));
        assert_eq!(config.dns_timeout(), Duration::from_secs(5));
        assert_eq!(config.http_timeout(), Duration::from_secs(10));
    }

    #[test]
    fn malformed_toml_falls_back_to_defaults() {
        let path = std::path::Path::new("~/.seer/config.toml");
        // Both a syntax error and a type error must yield defaults, not a panic.
        for content in ["output_format = [not toml", "output_format = 42"] {
            let config = SeerConfig::parse_or_default(content, path);
            assert_eq!(config.output_format, "human");
            assert_eq!(config.bulk.concurrency, 10);
        }
    }

    #[test]
    fn unknown_keys_are_tolerated() {
        // Forward-compat: a config written by a newer seer (or with a typo'd
        // extra key) must not hard-fail — no deny_unknown_fields.
        let path = std::path::Path::new("~/.seer/config.toml");
        let config =
            SeerConfig::parse_or_default("output_format = \"json\"\nfuture_option = true\n", path);
        assert_eq!(config.output_format, "json");
    }

    #[test]
    fn valid_content_is_clamped_through_parse_seam() {
        // parse_or_default must apply the same clamping load() always did.
        let path = std::path::Path::new("~/.seer/config.toml");
        let config = SeerConfig::parse_or_default("[bulk]\nconcurrency = 10000\n", path);
        assert_eq!(config.bulk.concurrency, 50);
    }

    #[test]
    fn clamp_bounds_rate_limit_ms() {
        // An unbounded rate-limit delay (once wired into the bulk executor)
        // would stall every operation for the configured duration; clamp it.
        let mut config = SeerConfig::default();
        config.bulk.rate_limit_ms = 10_000_000;
        let config = config.clamped();
        assert!(config.bulk.rate_limit_ms <= 60_000);
    }
}
