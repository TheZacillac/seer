//! Configuration file support for Seer.
//!
//! Loads settings from `~/.seer/config.toml` (a missing or malformed file
//! falls back to built-in defaults; values are clamped to safe ranges).

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::debug;

/// Upper clamp for `timeouts.ct_secs`; the CT-log client is built with it so
/// any configured per-request timeout fits under it.
pub(crate) const MAX_CT_SECS: u64 = 120;

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
    /// Watchlist settings (`seer watch`)
    pub watch: WatchConfig,
    /// TUI settings (`seer tui`)
    pub tui: TuiConfig,
    /// HTTP server settings (`seer-server`)
    pub server: ServerConfig,
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
    /// Certificate Transparency log request timeout in seconds (subdomain
    /// enumeration). Separate from `http_secs`: CT aggregators routinely take
    /// tens of seconds to answer for a busy domain, far past a site probe.
    pub ct_secs: u64,
    /// Overall deadline for one `seer audit` run, in seconds: every check
    /// still running when it passes is reported incomplete.
    pub audit_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BulkConfig {
    /// Default concurrency for bulk operations
    pub concurrency: usize,
    /// Rate limit delay in milliseconds between operations
    pub rate_limit_ms: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WatchConfig {
    /// Webhook URL the `seer watch` check-all report is POSTed to as JSON.
    /// `None` (the default) disables delivery; the CLI `--webhook` flag
    /// overrides this value.
    pub webhook_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TuiConfig {
    /// TUI color theme name. Known names: "frappe" (default) and "latte";
    /// read through [`SeerConfig::tui_theme`], which falls back to "frappe"
    /// on anything unrecognized so config parsing stays tolerant.
    pub theme: String,
}

/// Settings for the `seer-server` HTTP server. The CLI ignores them. The
/// API key is not here: secrets stay out of the config file and come from
/// the `SEER_API_KEY` environment variable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Address and port to listen on. Loopback by default: the server is
    /// meant to sit behind a reverse proxy that terminates TLS.
    pub bind: String,
    /// Whether callers without an API key may use the public routes. Off by
    /// default; with it off the server needs `SEER_API_KEY` to start.
    pub public: bool,
    /// Origins whose pages may read responses from a browser (CORS), e.g.
    /// `"https://example.com"`. Empty by default; `"*"` allows any origin.
    pub cors_origins: Vec<String>,
    /// Reverse proxies whose `X-Forwarded-For` header is believed, as IP
    /// addresses or CIDR ranges (`"127.0.0.1"`, `"10.0.0.0/8"`). Empty by
    /// default: the socket peer is then the client, so behind a proxy every
    /// visitor would share one rate-limit bucket.
    pub trusted_proxies: Vec<String>,
    /// How many times the anonymous rate limit a keyed caller gets.
    pub keyed_rate_multiplier: u32,
    /// Overall deadline for one request, in seconds: the wait for a free
    /// slot plus the lookup itself.
    pub request_timeout_secs: u64,
    /// Lookups allowed to run at once. Anonymous callers share half of it.
    pub max_in_flight: usize,
    /// How long a successful response is reused, in seconds; `0` disables
    /// the response cache.
    pub cache_ttl_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8001".to_string(),
            public: false,
            cors_origins: Vec::new(),
            trusted_proxies: Vec::new(),
            keyed_rate_multiplier: 10,
            request_timeout_secs: 30,
            max_in_flight: 64,
            cache_ttl_secs: 60,
        }
    }
}

impl Default for TuiConfig {
    fn default() -> Self {
        Self {
            theme: "frappe".to_string(),
        }
    }
}

impl Default for SeerConfig {
    fn default() -> Self {
        Self {
            output_format: "human".to_string(),
            nameserver: None,
            timeouts: TimeoutConfig::default(),
            bulk: BulkConfig::default(),
            watch: WatchConfig::default(),
            tui: TuiConfig::default(),
            server: ServerConfig::default(),
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
            ct_secs: 30,
            audit_secs: 60,
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
        std::env::home_dir().map(|home| home.join(".seer").join("config.toml"))
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

    /// Loads `~/.seer/config.toml` for a long-running service, refusing a
    /// file [`load`](Self::load) would paper over. A missing file is the
    /// defaults. A file that cannot be read, does not parse, or names a
    /// setting seer does not know is an error: a server must not start on
    /// defaults its operator did not choose because of a typo.
    pub fn load_strict() -> crate::error::Result<Self> {
        match Self::config_path() {
            Some(path) => Self::load_strict_from(&path),
            None => Ok(Self::default()),
        }
    }

    /// [`load_strict`](Self::load_strict) for a given path.
    fn load_strict_from(path: &std::path::Path) -> crate::error::Result<Self> {
        use crate::error::SeerError;

        let content = match std::fs::read_to_string(path) {
            Ok(content) => content,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => {
                return Err(SeerError::ConfigError(format!(
                    "cannot read {}: {e}",
                    path.display()
                )))
            }
        };
        let config: Self = toml::from_str(&content)
            .map_err(|e| SeerError::ConfigError(format!("{} is not valid: {e}", path.display())))?;
        let unknown = Self::unknown_keys(&content);
        if !unknown.is_empty() {
            return Err(SeerError::ConfigError(format!(
                "{} has unknown settings: {}",
                path.display(),
                unknown.join(", ")
            )));
        }
        Ok(config.clamped())
    }

    /// Parses config file content, falling back to defaults on malformed
    /// TOML. The failure is reported on stderr in addition to `tracing` —
    /// at the default log level a `warn!` is invisible, and `seer config`
    /// would then display defaults as though they came from the file.
    fn parse_or_default(content: &str, path: &std::path::Path) -> Self {
        match toml::from_str::<SeerConfig>(content) {
            Ok(config) => {
                debug!(?path, "Loaded config");
                // An unknown key is tolerated (a newer or older seer may know
                // it) but said out loud: a misspelled one would otherwise
                // leave its default in force with nothing to show for it.
                let unknown = Self::unknown_keys(content);
                if !unknown.is_empty() {
                    static WARN_ONCE: std::sync::Once = std::sync::Once::new();
                    WARN_ONCE.call_once(|| {
                        eprintln!(
                            "Warning: unknown setting{} in {} ignored: {}",
                            if unknown.len() == 1 { "" } else { "s" },
                            path.display(),
                            unknown.join(", ")
                        );
                    });
                }
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

    /// The dotted paths of keys and tables in `content` that no setting
    /// reads (`timeouts.whois_sec`, `timeout`), in file order. Empty when
    /// the content is not valid TOML — that is reported as malformed.
    pub(crate) fn unknown_keys(content: &str) -> Vec<String> {
        // Every setting present, so the optional ones count as known.
        let full = Self {
            nameserver: Some(String::new()),
            watch: WatchConfig {
                webhook_url: Some(String::new()),
            },
            ..Self::default()
        };
        let (Ok(file), Ok(known)) = (content.parse::<toml::Table>(), toml::Table::try_from(full))
        else {
            return Vec::new();
        };
        fn walk(file: &toml::Table, known: &toml::Table, prefix: &str, out: &mut Vec<String>) {
            for (key, value) in file {
                let path = format!("{prefix}{key}");
                match (value, known.get(key)) {
                    (toml::Value::Table(file), Some(toml::Value::Table(known))) => {
                        walk(file, known, &format!("{path}."), out);
                    }
                    (_, Some(_)) => {}
                    (_, None) => out.push(path),
                }
            }
        }
        let mut out = Vec::new();
        walk(&file, &known, "", &mut out);
        out
    }

    /// Clamp loaded values into sane ranges. Without this, a user
    /// (accidentally or maliciously) setting `bulk.concurrency = 0` would
    /// hand `buffer_unordered(0)` to every bulk fan-out, which never starts a
    /// task and hangs; `bulk.concurrency = 10000` would spawn thousands of
    /// concurrent connections. Timeouts of `0` would error every network call
    /// immediately. The bounds are per-protocol (a config file can't bypass
    /// them): concurrency 1–50; whois/rdap timeouts 1–300s; dns 1–60s;
    /// http and CT 1–120s; audit 10–300s; server: key multiplier 1–100,
    /// request timeout 1–120s, in-flight 2–1024, cache TTL 0–3600s.
    fn clamped(mut self) -> Self {
        self.bulk.concurrency = self.bulk.concurrency.clamp(1, 50);
        // A multi-day per-operation delay would stall bulk runs indefinitely;
        // cap at 60s (0 is valid — no inter-operation delay).
        self.bulk.rate_limit_ms = self.bulk.rate_limit_ms.min(60_000);
        self.timeouts.whois_secs = self.timeouts.whois_secs.clamp(1, 300);
        self.timeouts.rdap_secs = self.timeouts.rdap_secs.clamp(1, 300);
        self.timeouts.dns_secs = self.timeouts.dns_secs.clamp(1, 60);
        self.timeouts.http_secs = self.timeouts.http_secs.clamp(1, 120);
        self.timeouts.ct_secs = self.timeouts.ct_secs.clamp(1, MAX_CT_SECS);
        self.timeouts.audit_secs = self.timeouts.audit_secs.clamp(10, 300);
        // seer-server: a multiplier of 0 would refuse every keyed request,
        // a timeout of 0 every request, and fewer than 2 slots would leave
        // anonymous callers none. `cache_ttl_secs = 0` is valid (cache off).
        self.server.keyed_rate_multiplier = self.server.keyed_rate_multiplier.clamp(1, 100);
        self.server.request_timeout_secs = self.server.request_timeout_secs.clamp(1, 120);
        self.server.max_in_flight = self.server.max_in_flight.clamp(2, 1024);
        self.server.cache_ttl_secs = self.server.cache_ttl_secs.min(3600);
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

    /// Returns the Certificate Transparency log request timeout as a Duration.
    pub fn ct_timeout(&self) -> Duration {
        Duration::from_secs(self.timeouts.ct_secs)
    }

    /// Returns the overall `seer audit` deadline as a Duration.
    pub fn audit_timeout(&self) -> Duration {
        Duration::from_secs(self.timeouts.audit_secs)
    }

    /// Returns the inter-operation bulk rate-limit delay as a Duration.
    pub fn bulk_rate_limit(&self) -> Duration {
        Duration::from_millis(self.bulk.rate_limit_ms)
    }

    /// Returns the configured TUI theme, clamped to a known canonical name.
    ///
    /// Accepts "frappe" / "frappé" / "latte" (case-insensitive, trimmed);
    /// anything else falls back to "frappe" so a typo'd config degrades to
    /// the default look instead of erroring. Keep the accepted set in sync
    /// with the TUI's `Theme::from_name` (seer-cli/src/tui/theme.rs).
    pub fn tui_theme(&self) -> &'static str {
        match self.tui.theme.trim().to_lowercase().as_str() {
            "latte" => "latte",
            _ => "frappe",
        }
    }

    /// Generates a default config file content as TOML.
    pub fn default_toml() -> String {
        toml::to_string_pretty(&Self::default()).unwrap_or_else(|_| String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::SeerError;

    #[test]
    fn server_section_defaults_are_private_and_loopback() {
        let config = SeerConfig::default();
        assert_eq!(config.server.bind, "127.0.0.1:8001");
        assert!(!config.server.public);
        assert!(config.server.cors_origins.is_empty());
    }

    #[test]
    fn server_section_parses() {
        let config: SeerConfig = toml::from_str(
            r#"
[server]
bind = "127.0.0.1:9000"
public = true
cors_origins = ["https://example.com"]
"#,
        )
        .unwrap();
        assert_eq!(config.server.bind, "127.0.0.1:9000");
        assert!(config.server.public);
        assert_eq!(config.server.cors_origins, ["https://example.com"]);
    }

    #[test]
    fn server_section_keys_are_known_and_typos_are_reported() {
        let unknown = SeerConfig::unknown_keys(
            "[server]\nbind = \"127.0.0.1:1\"\npublic = true\ncors_origins = []\npublc = true\n",
        );
        assert_eq!(unknown, ["server.publc"]);
    }

    #[test]
    fn server_section_survives_default_toml_roundtrip() {
        let parsed: SeerConfig = toml::from_str(&SeerConfig::default_toml()).unwrap();
        assert_eq!(parsed.server.bind, "127.0.0.1:8001");
        assert!(SeerConfig::default_toml().contains("[server]"));
    }

    #[test]
    fn server_protection_settings_have_safe_defaults() {
        let server = SeerConfig::default().server;
        assert!(server.trusted_proxies.is_empty());
        assert_eq!(server.keyed_rate_multiplier, 10);
        assert_eq!(server.request_timeout_secs, 30);
        assert_eq!(server.max_in_flight, 64);
        assert_eq!(server.cache_ttl_secs, 60);
    }

    #[test]
    fn server_protection_settings_parse_and_are_clamped() {
        let parse = |body: &str| {
            SeerConfig::parse_or_default(
                &format!("[server]\n{body}\n"),
                std::path::Path::new("test.toml"),
            )
            .server
        };
        let low = parse(
            "keyed_rate_multiplier = 0\nrequest_timeout_secs = 0\nmax_in_flight = 0\ncache_ttl_secs = 0",
        );
        assert_eq!(low.keyed_rate_multiplier, 1);
        assert_eq!(low.request_timeout_secs, 1);
        assert_eq!(low.max_in_flight, 2);
        assert_eq!(low.cache_ttl_secs, 0, "0 is valid: it disables the cache");

        let high = parse(
            "keyed_rate_multiplier = 5000\nrequest_timeout_secs = 5000\nmax_in_flight = 500000\ncache_ttl_secs = 500000",
        );
        assert_eq!(high.keyed_rate_multiplier, 100);
        assert_eq!(high.request_timeout_secs, 120);
        assert_eq!(high.max_in_flight, 1024);
        assert_eq!(high.cache_ttl_secs, 3600);

        let proxies = parse("trusted_proxies = [\"10.0.0.0/8\", \"192.0.2.1\"]");
        assert_eq!(proxies.trusted_proxies, ["10.0.0.0/8", "192.0.2.1"]);
    }

    #[test]
    fn server_protection_settings_are_known_keys() {
        let unknown = SeerConfig::unknown_keys(
            "[server]\ntrusted_proxies = []\nkeyed_rate_multiplier = 2\nrequest_timeout_secs = 5\nmax_in_flight = 8\ncache_ttl_secs = 0\n",
        );
        assert!(unknown.is_empty(), "{unknown:?}");
    }

    /// Writes `content` to a fresh temp file and strict-loads it.
    fn strict(name: &str, content: &str) -> crate::error::Result<SeerConfig> {
        let path =
            std::env::temp_dir().join(format!("seer-strict-{}-{name}.toml", std::process::id()));
        std::fs::write(&path, content).unwrap();
        let result = SeerConfig::load_strict_from(&path);
        let _ = std::fs::remove_file(&path);
        result
    }

    #[test]
    fn strict_load_of_a_missing_file_is_the_defaults() {
        let path = std::env::temp_dir().join(format!("seer-absent-{}.toml", std::process::id()));
        let config = SeerConfig::load_strict_from(&path).unwrap();
        assert_eq!(config.server.bind, "127.0.0.1:8001");
    }

    #[test]
    fn strict_load_accepts_and_clamps_a_valid_file() {
        let config = strict("valid", "[server]\npublic = true\nmax_in_flight = 1\n").unwrap();
        assert!(config.server.public);
        assert_eq!(config.server.max_in_flight, 2);
    }

    #[test]
    fn strict_load_rejects_malformed_toml() {
        // The tolerant loader would start on defaults; a server must not.
        let error = strict("malformed", "[server]\nbind = 8001\n").unwrap_err();
        assert!(matches!(error, SeerError::ConfigError(_)), "{error:?}");
        assert!(
            error.to_string().contains("seer-strict-"),
            "names the file: {error}"
        );
    }

    #[test]
    fn strict_load_rejects_unknown_settings() {
        let error = strict("typo", "[server]\npublc = true\n").unwrap_err();
        assert!(matches!(error, SeerError::ConfigError(_)), "{error:?}");
        assert!(error.to_string().contains("server.publc"), "{error}");
    }

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
        assert_eq!(config.ct_timeout(), Duration::from_secs(30));
    }

    #[test]
    fn audit_timeout_defaults_and_is_clamped() {
        let path = std::path::Path::new("~/.seer/config.toml");
        assert_eq!(
            SeerConfig::default().audit_timeout(),
            Duration::from_secs(60)
        );
        let config = SeerConfig::parse_or_default("[timeouts]\naudit_secs = 90\n", path);
        assert_eq!(config.audit_timeout(), Duration::from_secs(90));
        let config = SeerConfig::parse_or_default("[timeouts]\naudit_secs = 1\n", path);
        assert_eq!(config.audit_timeout(), Duration::from_secs(10));
        let config = SeerConfig::parse_or_default("[timeouts]\naudit_secs = 9999\n", path);
        assert_eq!(config.audit_timeout(), Duration::from_secs(300));
    }

    #[test]
    fn ct_timeout_parses_and_is_clamped() {
        let path = std::path::Path::new("~/.seer/config.toml");
        let config = SeerConfig::parse_or_default("[timeouts]\nct_secs = 45\n", path);
        assert_eq!(config.ct_timeout(), Duration::from_secs(45));
        let config = SeerConfig::parse_or_default("[timeouts]\nct_secs = 0\n", path);
        assert_eq!(config.ct_timeout(), Duration::from_secs(1));
        let config = SeerConfig::parse_or_default("[timeouts]\nct_secs = 9999\n", path);
        assert_eq!(config.ct_timeout(), Duration::from_secs(MAX_CT_SECS));
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
    fn watch_webhook_url_parses_and_defaults_to_none() {
        let config: SeerConfig =
            toml::from_str("[watch]\nwebhook_url = \"https://hooks.example.com/seer\"\n").unwrap();
        assert_eq!(
            config.watch.webhook_url.as_deref(),
            Some("https://hooks.example.com/seer")
        );

        let config = SeerConfig::default();
        assert_eq!(config.watch.webhook_url, None);
    }

    #[test]
    fn tui_theme_parses_and_defaults_to_frappe() {
        let config: SeerConfig = toml::from_str("[tui]\ntheme = \"latte\"\n").unwrap();
        assert_eq!(config.tui.theme, "latte");
        assert_eq!(config.tui_theme(), "latte");

        let config = SeerConfig::default();
        assert_eq!(config.tui.theme, "frappe");
        assert_eq!(config.tui_theme(), "frappe");
    }

    #[test]
    fn tui_theme_accessor_is_case_insensitive_and_trims() {
        for raw in ["Latte", "LATTE", "  latte  "] {
            let mut config = SeerConfig::default();
            config.tui.theme = raw.to_string();
            assert_eq!(config.tui_theme(), "latte", "input: {raw:?}");
        }
        for raw in ["Frappe", "frappé", "FRAPPÉ"] {
            let mut config = SeerConfig::default();
            config.tui.theme = raw.to_string();
            assert_eq!(config.tui_theme(), "frappe", "input: {raw:?}");
        }
    }

    #[test]
    fn tui_theme_unknown_name_falls_back_to_frappe() {
        // Config parsing stays tolerant: an unknown theme loads unchanged but
        // the accessor clamps it to the default instead of erroring.
        let config: SeerConfig = toml::from_str("[tui]\ntheme = \"nord\"\n").unwrap();
        assert_eq!(config.tui.theme, "nord");
        assert_eq!(config.tui_theme(), "frappe");
    }

    #[test]
    fn new_sections_survive_default_toml_roundtrip() {
        // default_toml must serialize the new [watch]/[tui] tables without
        // erroring (webhook_url = None is omitted by the toml serializer).
        let toml_str = SeerConfig::default_toml();
        let config: SeerConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(config.tui.theme, "frappe");
        assert_eq!(config.watch.webhook_url, None);
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

    /// Regression: a misspelled key or section was ignored without a word,
    /// so `seer config` showed defaults as though the file had set them.
    #[test]
    fn unknown_keys_are_reported_by_path() {
        let content = "nameserver = \"1.1.1.1\"\n[timeouts]\nwhois_sec = 3\ndns_secs = 2\n\n\
                       [bulk]\nconcurency = 2\n\n[timeout]\ndns_secs = 1\n\n\
                       [watch]\nwebhook_url = \"https://example.com/hook\"\n";
        let mut unknown = SeerConfig::unknown_keys(content);
        unknown.sort();
        assert_eq!(
            unknown,
            ["bulk.concurency", "timeout", "timeouts.whois_sec"]
        );
        assert!(SeerConfig::unknown_keys(&SeerConfig::default_toml()).is_empty());
        assert!(SeerConfig::unknown_keys("not = [valid").is_empty());
    }
}
