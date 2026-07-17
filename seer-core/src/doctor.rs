//! Environment self-diagnosis for `seer doctor`: config file health, DNS
//! resolution, WHOIS port-43 reachability, and RDAP bootstrap (outbound
//! HTTPS) reachability.
//!
//! [`Doctor::run`] executes all four checks concurrently (`tokio::join!`);
//! each probe is individually timeout-bounded, and one failing probe never
//! aborts the others. Results fold into a [`DoctorReport`] whose `overall`
//! status is the worst individual result. A malformed config file is a
//! [`CheckStatus::Warn`] — seer still works on built-in defaults — while an
//! unreachable network dependency is a [`CheckStatus::Fail`].
//!
//! Probe endpoints are injectable through `#[cfg(test)]`-only seams
//! (mirroring the `allowing_private_hosts`/`with_port` pattern on the
//! protocol clients) so the hermetic tests run entirely against loopback
//! fixtures. The seams do not exist in release builds: production probes
//! always target the real, hardcoded endpoints below.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::config::SeerConfig;
use crate::dns::{DnsResolver, RecordType};

/// IANA RDAP bootstrap registry for DNS. Mirrors the private
/// `IANA_BOOTSTRAP_DNS` const in `rdap/client.rs` — keep the two in sync.
const IANA_BOOTSTRAP_DNS: &str = "https://data.iana.org/rdap/dns.json";

/// Default WHOIS probe target: IANA's root WHOIS server (reachable for every
/// TLD lookup seer performs, so it is the canonical port-43 reachability
/// signal).
const DEFAULT_WHOIS_ADDR: &str = "whois.iana.org:43";

/// Well-known name resolved by the DNS probe and sent as the WHOIS query
/// line. `example.com` is IANA-reserved and permanently registered.
const DEFAULT_PROBE_DOMAIN: &str = "example.com";

/// Per-probe deadline. Deliberately independent of the user-tunable protocol
/// timeouts: a diagnosis should answer quickly even when the user has
/// configured generous lookup timeouts.
const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Check names as they appear in [`DoctorCheck::name`].
const CHECK_CONFIG: &str = "config";
const CHECK_DNS: &str = "dns";
const CHECK_WHOIS: &str = "whois";
const CHECK_RDAP_BOOTSTRAP: &str = "rdap-bootstrap";

/// Outcome of a single diagnostic check.
///
/// Variant order is the severity order [`DoctorReport::from_checks`]
/// aggregates by (`Ord`: `Pass < Warn < Fail`) — keep it that way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    /// The check succeeded.
    Pass,
    /// Degraded but non-blocking (e.g. malformed config: seer runs on defaults).
    Warn,
    /// The checked dependency is unusable (timeout, refusal, bad response).
    Fail,
}

impl std::fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CheckStatus::Pass => "PASS",
            CheckStatus::Warn => "WARN",
            CheckStatus::Fail => "FAIL",
        })
    }
}

/// A single named diagnostic result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorCheck {
    /// Stable check identifier: `"config"`, `"dns"`, `"whois"`, or
    /// `"rdap-bootstrap"`.
    pub name: String,
    /// Outcome severity.
    pub status: CheckStatus,
    /// Human-readable explanation of the outcome.
    pub detail: String,
    /// Wall-clock duration of the probe. `None` for the local config check.
    pub latency_ms: Option<u64>,
}

impl DoctorCheck {
    fn new(
        name: &str,
        status: CheckStatus,
        detail: impl Into<String>,
        latency_ms: Option<u64>,
    ) -> Self {
        Self {
            name: name.to_string(),
            status,
            detail: detail.into(),
            latency_ms,
        }
    }
}

/// Aggregated result of a [`Doctor::run`] diagnosis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorReport {
    /// Individual check results, in the fixed order config, dns, whois,
    /// rdap-bootstrap.
    pub checks: Vec<DoctorCheck>,
    /// Worst status across `checks` ([`CheckStatus::Pass`] when empty).
    pub overall: CheckStatus,
}

impl DoctorReport {
    /// Builds a report from individual checks, computing `overall` as the
    /// worst (maximum-severity) status present.
    pub fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let overall = checks
            .iter()
            .map(|check| check.status)
            .max()
            .unwrap_or(CheckStatus::Pass);
        Self { checks, overall }
    }
}

/// Environment/connectivity self-diagnosis runner.
///
/// Built from a [`SeerConfig`] so the DNS probe honors the configured
/// nameserver and `timeouts.dns_secs`. All probe endpoints default to the
/// real production targets; they are only injectable in `#[cfg(test)]`
/// builds.
#[derive(Debug, Clone)]
pub struct Doctor {
    config: SeerConfig,
    /// Path checked by the config diagnostic (`None` when no home directory
    /// could be determined).
    config_path: Option<PathBuf>,
    /// Resolver used by the DNS probe (built via [`DnsResolver::from_config`]).
    resolver: DnsResolver,
    /// Name resolved by the DNS probe and queried over WHOIS.
    probe_domain: String,
    /// `host:port` target of the WHOIS TCP probe.
    whois_addr: String,
    /// URL fetched by the RDAP bootstrap probe.
    bootstrap_url: String,
    /// Per-probe deadline.
    probe_timeout: Duration,
}

impl Doctor {
    /// Creates a doctor honoring `config` (nameserver + DNS timeout), with
    /// all probes pointed at the real production endpoints.
    pub fn from_config(config: &SeerConfig) -> Self {
        Self {
            config: config.clone(),
            config_path: SeerConfig::config_path(),
            resolver: DnsResolver::from_config(config),
            probe_domain: DEFAULT_PROBE_DOMAIN.to_string(),
            whois_addr: DEFAULT_WHOIS_ADDR.to_string(),
            bootstrap_url: IANA_BOOTSTRAP_DNS.to_string(),
            probe_timeout: DEFAULT_PROBE_TIMEOUT,
        }
    }

    // --- #[cfg(test)]-only endpoint seams --------------------------------
    // Mirror the repo's mock-server pattern (`allowing_private_hosts` /
    // `with_port`): thread test fixtures in, never weaken production paths.

    /// Test-only: point the config check at an arbitrary file path.
    #[cfg(test)]
    pub(crate) fn with_config_path(mut self, path: PathBuf) -> Self {
        self.config_path = Some(path);
        self
    }

    /// Test-only: substitute the DNS probe's resolver (e.g. one wired to the
    /// loopback fixture via `dns::test_support::mock_dns_resolver`).
    #[cfg(test)]
    pub(crate) fn with_resolver(mut self, resolver: DnsResolver) -> Self {
        self.resolver = resolver;
        self
    }

    /// Test-only: change the probe domain (the mock DNS zone serves `seer.test`).
    #[cfg(test)]
    pub(crate) fn with_probe_domain(mut self, domain: &str) -> Self {
        self.probe_domain = domain.to_string();
        self
    }

    /// Test-only: point the WHOIS probe at a loopback listener.
    #[cfg(test)]
    pub(crate) fn with_whois_addr(mut self, addr: String) -> Self {
        self.whois_addr = addr;
        self
    }

    /// Test-only: point the RDAP bootstrap probe at a wiremock server.
    #[cfg(test)]
    pub(crate) fn with_bootstrap_url(mut self, url: String) -> Self {
        self.bootstrap_url = url;
        self
    }

    /// Test-only: shorten the per-probe deadline to keep failing tests fast.
    #[cfg(test)]
    pub(crate) fn with_probe_timeout(mut self, timeout: Duration) -> Self {
        self.probe_timeout = timeout;
        self
    }

    /// Runs all checks concurrently and aggregates them.
    ///
    /// Never fails: probe errors surface as [`CheckStatus::Fail`] checks in
    /// the report, not as an `Err`.
    ///
    /// # Example
    /// ```no_run
    /// # async fn demo() {
    /// use seer_core::config::SeerConfig;
    /// use seer_core::doctor::Doctor;
    ///
    /// let report = Doctor::from_config(&SeerConfig::load()).run().await;
    /// for check in &report.checks {
    ///     println!("{}: {} — {}", check.name, check.status, check.detail);
    /// }
    /// # }
    /// ```
    pub async fn run(&self) -> DoctorReport {
        let (config, dns, whois, rdap) = tokio::join!(
            self.check_config(),
            self.check_dns(),
            self.check_whois(),
            self.check_rdap_bootstrap(),
        );
        DoctorReport::from_checks(vec![config, dns, whois, rdap])
    }

    /// Reports whether `~/.seer/config.toml` is absent (defaults apply),
    /// parses cleanly, or is malformed (seer falls back to defaults — Warn).
    ///
    /// Re-parses the file directly rather than trusting `self.config`: the
    /// in-memory config is already defaults-on-failure, so it cannot tell us
    /// *why* it holds defaults.
    async fn check_config(&self) -> DoctorCheck {
        let Some(path) = self.config_path.as_ref() else {
            return DoctorCheck::new(
                CHECK_CONFIG,
                CheckStatus::Pass,
                "no home directory found; using built-in defaults",
                None,
            );
        };
        if !path.exists() {
            return DoctorCheck::new(
                CHECK_CONFIG,
                CheckStatus::Pass,
                format!("{} not present; using built-in defaults", path.display()),
                None,
            );
        }
        // Sync read of a tiny local file; matches config.rs, and tokio's `fs`
        // feature isn't enabled in this workspace.
        match std::fs::read_to_string(path) {
            Ok(content) => match toml::from_str::<SeerConfig>(&content) {
                Ok(_) => DoctorCheck::new(
                    CHECK_CONFIG,
                    CheckStatus::Pass,
                    format!("{} parsed OK", path.display()),
                    None,
                ),
                Err(e) => DoctorCheck::new(
                    CHECK_CONFIG,
                    CheckStatus::Warn,
                    format!(
                        "{} is malformed TOML (seer runs on defaults): {}",
                        path.display(),
                        one_line(&e.to_string())
                    ),
                    None,
                ),
            },
            Err(e) => DoctorCheck::new(
                CHECK_CONFIG,
                CheckStatus::Warn,
                format!(
                    "could not read {} (seer runs on defaults): {}",
                    path.display(),
                    e
                ),
                None,
            ),
        }
    }

    /// Resolves the well-known probe domain's A records through the
    /// configured nameserver (or the default Google DNS resolver).
    async fn check_dns(&self) -> DoctorCheck {
        let nameserver = self.config.nameserver.as_deref();
        let ns_label = nameserver.unwrap_or("8.8.8.8 (default)");
        let start = Instant::now();
        let outcome = timeout(
            self.probe_timeout,
            self.resolver
                .resolve(&self.probe_domain, RecordType::A, nameserver),
        )
        .await;
        let latency = Some(latency_since(start));
        match outcome {
            Ok(Ok(records)) if !records.is_empty() => DoctorCheck::new(
                CHECK_DNS,
                CheckStatus::Pass,
                format!(
                    "resolved {} A via {} ({} record{})",
                    self.probe_domain,
                    ns_label,
                    records.len(),
                    plural(records.len())
                ),
                latency,
            ),
            // NXDOMAIN/NODATA fold to Ok(vec![]) in the resolver. The
            // transport works (a server answered), but a permanently
            // registered name coming back empty means the resolver is
            // filtering or intercepted — degraded, not dead.
            Ok(Ok(_)) => DoctorCheck::new(
                CHECK_DNS,
                CheckStatus::Warn,
                format!(
                    "{} returned no A records via {} — resolver reachable, but a well-known name came back empty (possible filtering or captive portal)",
                    self.probe_domain, ns_label
                ),
                latency,
            ),
            Ok(Err(e)) => DoctorCheck::new(
                CHECK_DNS,
                CheckStatus::Fail,
                format!("resolving {} via {} failed: {}", self.probe_domain, ns_label, e),
                latency,
            ),
            Err(_) => DoctorCheck::new(
                CHECK_DNS,
                CheckStatus::Fail,
                format!(
                    "resolving {} via {} timed out after {:?}",
                    self.probe_domain, ns_label, self.probe_timeout
                ),
                latency,
            ),
        }
    }

    /// TCP-connects to the WHOIS server, sends one query line, and requires
    /// at least one response byte.
    async fn check_whois(&self) -> DoctorCheck {
        let start = Instant::now();
        let outcome = timeout(self.probe_timeout, self.whois_probe()).await;
        let latency = Some(latency_since(start));
        match outcome {
            Ok(Ok(detail)) => DoctorCheck::new(CHECK_WHOIS, CheckStatus::Pass, detail, latency),
            Ok(Err(detail)) => DoctorCheck::new(CHECK_WHOIS, CheckStatus::Fail, detail, latency),
            Err(_) => DoctorCheck::new(
                CHECK_WHOIS,
                CheckStatus::Fail,
                format!(
                    "WHOIS probe to {} timed out after {:?} (port 43 may be blocked)",
                    self.whois_addr, self.probe_timeout
                ),
                latency,
            ),
        }
    }

    /// The raw WHOIS exchange; `Err` carries the failure detail. The probe
    /// target is the hardcoded IANA server in production (the address is
    /// only injectable under `#[cfg(test)]`), so no SSRF validation applies.
    async fn whois_probe(&self) -> Result<String, String> {
        let mut stream = TcpStream::connect(&self.whois_addr)
            .await
            .map_err(|e| format!("connect to {} failed: {}", self.whois_addr, e))?;
        stream
            .write_all(format!("{}\r\n", self.probe_domain).as_bytes())
            .await
            .map_err(|e| format!("write to {} failed: {}", self.whois_addr, e))?;
        let mut buf = [0u8; 256];
        let n = stream
            .read(&mut buf)
            .await
            .map_err(|e| format!("read from {} failed: {}", self.whois_addr, e))?;
        if n == 0 {
            return Err(format!(
                "{} closed the connection without sending data",
                self.whois_addr
            ));
        }
        Ok(format!(
            "queried {} via {} ({} byte{} received)",
            self.probe_domain,
            self.whois_addr,
            n,
            plural(n)
        ))
    }

    /// HTTPS-fetches the IANA RDAP DNS bootstrap registry, requiring an
    /// HTTP 200 with a non-empty body.
    async fn check_rdap_bootstrap(&self) -> DoctorCheck {
        let start = Instant::now();
        let outcome = timeout(self.probe_timeout, self.rdap_bootstrap_probe()).await;
        let latency = Some(latency_since(start));
        match outcome {
            Ok(Ok(detail)) => {
                DoctorCheck::new(CHECK_RDAP_BOOTSTRAP, CheckStatus::Pass, detail, latency)
            }
            Ok(Err(detail)) => {
                DoctorCheck::new(CHECK_RDAP_BOOTSTRAP, CheckStatus::Fail, detail, latency)
            }
            Err(_) => DoctorCheck::new(
                CHECK_RDAP_BOOTSTRAP,
                CheckStatus::Fail,
                format!(
                    "GET {} timed out after {:?}",
                    self.bootstrap_url, self.probe_timeout
                ),
                latency,
            ),
        }
    }

    /// The raw bootstrap fetch; `Ok` carries the success detail, `Err` the
    /// failure detail. The URL is the hardcoded IANA HTTPS endpoint in
    /// production (only injectable under `#[cfg(test)]`).
    async fn rdap_bootstrap_probe(&self) -> Result<String, String> {
        // reqwest's client-level timeout spans connect through body read; the
        // caller's outer `timeout()` is defense in depth.
        let client = reqwest::Client::builder()
            .timeout(self.probe_timeout)
            .build()
            .map_err(|e| format!("could not build HTTP client: {}", e))?;
        let response = client
            .get(&self.bootstrap_url)
            .send()
            .await
            .map_err(|e| format!("GET {} failed: {}", self.bootstrap_url, e))?;
        let status = response.status();
        if status != reqwest::StatusCode::OK {
            return Err(format!(
                "GET {} returned HTTP {}",
                self.bootstrap_url, status
            ));
        }
        let body = response
            .bytes()
            .await
            .map_err(|e| format!("reading {} body failed: {}", self.bootstrap_url, e))?;
        if body.is_empty() {
            return Err(format!("GET {} returned an empty body", self.bootstrap_url));
        }
        Ok(format!(
            "fetched {} ({} bytes)",
            self.bootstrap_url,
            body.len()
        ))
    }
}

/// Milliseconds elapsed since `start`, saturating at `u64::MAX`.
fn latency_since(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// `"s"` when `n != 1`, for probe detail strings.
fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

/// Collapses a multi-line error (toml parse errors span lines) into a single
/// whitespace-normalized line for the check detail.
fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU32, Ordering};

    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::dns::test_support::{mock_dns_resolver, spawn_mock_dns, MockMode};

    // --- fixtures ------------------------------------------------------

    /// A unique temp-file path; the file (if created) is removed on drop.
    struct TmpFile(PathBuf);

    impl TmpFile {
        fn unique(tag: &str) -> Self {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "seer-doctor-{}-{}-{}.toml",
                tag,
                std::process::id(),
                n
            )))
        }

        fn with_content(tag: &str, content: &str) -> Self {
            let file = Self::unique(tag);
            std::fs::write(&file.0, content).expect("write temp config");
            file
        }
    }

    impl Drop for TmpFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// Loopback WHOIS listener that answers every connection with `response`.
    async fn spawn_whois_responder(response: &'static [u8]) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock whois");
        let port = listener.local_addr().expect("local addr").port();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = [0u8; 128];
                let _ = sock.read(&mut buf).await; // consume "domain\r\n"
                let _ = sock.write_all(response).await;
            }
        });
        port
    }

    /// A loopback port with nothing listening (bind then drop → refused).
    async fn refused_port() -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind for refused port");
        let port = listener.local_addr().expect("local addr").port();
        drop(listener);
        port
    }

    fn base_doctor(config: &SeerConfig) -> Doctor {
        // Point the config check away from the developer's real
        // ~/.seer/config.toml — every test overrides what it exercises.
        Doctor::from_config(config)
            .with_config_path(TmpFile::unique("unused").0.clone())
            .with_probe_timeout(Duration::from_secs(2))
    }

    /// Doctor whose DNS probe is wired to the loopback mock fixture.
    async fn dns_doctor(mode: MockMode) -> Doctor {
        let port = spawn_mock_dns(mode).await;
        let config = SeerConfig {
            nameserver: Some("127.0.0.1".to_string()),
            ..SeerConfig::default()
        };
        base_doctor(&config)
            .with_resolver(mock_dns_resolver(port))
            .with_probe_domain("seer.test")
    }

    // --- aggregation -----------------------------------------------------

    fn check(status: CheckStatus) -> DoctorCheck {
        DoctorCheck::new("x", status, "detail", None)
    }

    #[test]
    fn overall_is_worst_of_checks() {
        use CheckStatus::{Fail, Pass, Warn};
        let cases = [
            (vec![], Pass),
            (vec![check(Pass), check(Pass)], Pass),
            (vec![check(Pass), check(Warn)], Warn),
            (vec![check(Warn), check(Pass), check(Fail)], Fail),
            (vec![check(Fail), check(Warn)], Fail),
        ];
        for (checks, expected) in cases {
            assert_eq!(DoctorReport::from_checks(checks).overall, expected);
        }
    }

    #[test]
    fn report_serde_roundtrips_with_lowercase_statuses() {
        let report = DoctorReport::from_checks(vec![DoctorCheck::new(
            "dns",
            CheckStatus::Fail,
            "boom",
            Some(12),
        )]);
        let json = serde_json::to_string(&report).expect("serialize report");
        assert!(json.contains("\"fail\""), "got: {json}");
        let back: DoctorReport = serde_json::from_str(&json).expect("deserialize report");
        assert_eq!(back, report);
    }

    #[test]
    fn doctor_defaults_target_real_endpoints() {
        // The wiring agent's CLI contract depends on these production
        // defaults; the test seams must be the only way to change them.
        let doctor = Doctor::from_config(&SeerConfig::default());
        assert_eq!(doctor.whois_addr, "whois.iana.org:43");
        assert_eq!(doctor.bootstrap_url, "https://data.iana.org/rdap/dns.json");
        assert_eq!(doctor.probe_domain, "example.com");
        assert_eq!(doctor.probe_timeout, Duration::from_secs(5));
    }

    // --- config check ----------------------------------------------------

    #[tokio::test]
    async fn config_check_absent_file_passes() {
        let missing = TmpFile::unique("absent");
        let doctor =
            Doctor::from_config(&SeerConfig::default()).with_config_path(missing.0.clone());
        let check = doctor.check_config().await;
        assert_eq!(check.status, CheckStatus::Pass);
        assert!(check.detail.contains("defaults"), "got: {}", check.detail);
        assert_eq!(check.latency_ms, None);
    }

    #[tokio::test]
    async fn config_check_valid_file_passes() {
        let file = TmpFile::with_content("valid", "output_format = \"json\"\n");
        let doctor = Doctor::from_config(&SeerConfig::default()).with_config_path(file.0.clone());
        let check = doctor.check_config().await;
        assert_eq!(check.status, CheckStatus::Pass);
        assert!(check.detail.contains("parsed OK"), "got: {}", check.detail);
    }

    #[tokio::test]
    async fn config_check_malformed_file_warns() {
        // Both a syntax error and a type error must Warn, mirroring the two
        // fallback paths in SeerConfig::parse_or_default.
        for content in ["output_format = [not toml", "output_format = 42"] {
            let file = TmpFile::with_content("malformed", content);
            let doctor =
                Doctor::from_config(&SeerConfig::default()).with_config_path(file.0.clone());
            let check = doctor.check_config().await;
            assert_eq!(check.status, CheckStatus::Warn, "content: {content}");
            assert!(check.detail.contains("defaults"), "got: {}", check.detail);
            // Detail must stay a single line for terminal/JSON output.
            assert!(!check.detail.contains('\n'), "got: {}", check.detail);
        }
    }

    // --- whois check -------------------------------------------------------

    #[tokio::test]
    async fn whois_check_passes_against_responding_listener() {
        let port = spawn_whois_responder(b"% IANA WHOIS server\r\n").await;
        let doctor =
            base_doctor(&SeerConfig::default()).with_whois_addr(format!("127.0.0.1:{port}"));
        let check = doctor.check_whois().await;
        assert_eq!(check.status, CheckStatus::Pass, "got: {}", check.detail);
        assert!(check.latency_ms.is_some());
    }

    #[tokio::test]
    async fn whois_check_fails_on_connection_refused() {
        let port = refused_port().await;
        let doctor =
            base_doctor(&SeerConfig::default()).with_whois_addr(format!("127.0.0.1:{port}"));
        let check = doctor.check_whois().await;
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.detail.contains("connect"), "got: {}", check.detail);
    }

    #[tokio::test]
    async fn whois_check_fails_on_eof_without_data() {
        // Listener accepts, reads the query, then closes without writing —
        // "read at least 1 byte" must not count a bare FIN as success.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock whois");
        let port = listener.local_addr().expect("local addr").port();
        tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut buf = [0u8; 128];
            let _ = sock.read(&mut buf).await;
            // drop(sock) → FIN with zero response bytes
        });
        let doctor =
            base_doctor(&SeerConfig::default()).with_whois_addr(format!("127.0.0.1:{port}"));
        let check = doctor.check_whois().await;
        assert_eq!(check.status, CheckStatus::Fail, "got: {}", check.detail);
    }

    #[tokio::test]
    async fn whois_check_fails_on_timeout() {
        // Listener accepts but never responds: the probe deadline must fire.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock whois");
        let port = listener.local_addr().expect("local addr").port();
        tokio::spawn(async move {
            let Ok((_sock, _)) = listener.accept().await else {
                return;
            };
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let doctor = base_doctor(&SeerConfig::default())
            .with_whois_addr(format!("127.0.0.1:{port}"))
            .with_probe_timeout(Duration::from_millis(200));
        let check = doctor.check_whois().await;
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.detail.contains("timed out"), "got: {}", check.detail);
    }

    // --- rdap bootstrap check ---------------------------------------------

    #[tokio::test]
    async fn rdap_check_passes_on_200_with_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"services":[]}"#))
            .mount(&server)
            .await;
        let doctor = base_doctor(&SeerConfig::default())
            .with_bootstrap_url(format!("{}/rdap/dns.json", server.uri()));
        let check = doctor.check_rdap_bootstrap().await;
        assert_eq!(check.status, CheckStatus::Pass, "got: {}", check.detail);
        assert!(check.latency_ms.is_some());
    }

    #[tokio::test]
    async fn rdap_check_fails_on_500() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let doctor = base_doctor(&SeerConfig::default())
            .with_bootstrap_url(format!("{}/rdap/dns.json", server.uri()));
        let check = doctor.check_rdap_bootstrap().await;
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.detail.contains("500"), "got: {}", check.detail);
    }

    #[tokio::test]
    async fn rdap_check_fails_on_empty_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let doctor = base_doctor(&SeerConfig::default())
            .with_bootstrap_url(format!("{}/rdap/dns.json", server.uri()));
        let check = doctor.check_rdap_bootstrap().await;
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.detail.contains("empty body"), "got: {}", check.detail);
    }

    #[tokio::test]
    async fn rdap_check_fails_on_timeout() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
            .mount(&server)
            .await;
        let doctor = base_doctor(&SeerConfig::default())
            .with_bootstrap_url(format!("{}/rdap/dns.json", server.uri()))
            .with_probe_timeout(Duration::from_millis(200));
        let check = doctor.check_rdap_bootstrap().await;
        assert_eq!(check.status, CheckStatus::Fail, "got: {}", check.detail);
    }

    // --- dns check ---------------------------------------------------------

    #[tokio::test]
    async fn dns_check_passes_with_mock_zone() {
        let doctor = dns_doctor(MockMode::Zone).await;
        let check = doctor.check_dns().await;
        assert_eq!(check.status, CheckStatus::Pass, "got: {}", check.detail);
        // Detail must show the config nameserver was honored.
        assert!(check.detail.contains("127.0.0.1"), "got: {}", check.detail);
        assert!(check.latency_ms.is_some());
    }

    #[tokio::test]
    async fn dns_check_warns_on_nxdomain_for_probe_name() {
        let doctor = dns_doctor(MockMode::Nxdomain).await;
        let check = doctor.check_dns().await;
        assert_eq!(check.status, CheckStatus::Warn, "got: {}", check.detail);
    }

    #[tokio::test]
    async fn dns_check_fails_when_server_unresponsive() {
        // MockMode::Ignore never answers: either the resolver's own timeout
        // or the probe deadline fires — both must map to Fail.
        let doctor = dns_doctor(MockMode::Ignore)
            .await
            .with_probe_timeout(Duration::from_secs(1));
        let check = doctor.check_dns().await;
        assert_eq!(check.status, CheckStatus::Fail, "got: {}", check.detail);
    }

    // --- full run ------------------------------------------------------------

    #[tokio::test]
    async fn run_reports_all_four_checks_in_order_and_passes() {
        let config_file = TmpFile::with_content("run-valid", "output_format = \"yaml\"\n");
        let whois_port = spawn_whois_responder(b"% ok\r\n").await;
        let rdap = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"services":[]}"#))
            .mount(&rdap)
            .await;

        let doctor = dns_doctor(MockMode::Zone)
            .await
            .with_config_path(config_file.0.clone())
            .with_whois_addr(format!("127.0.0.1:{whois_port}"))
            .with_bootstrap_url(format!("{}/rdap/dns.json", rdap.uri()));

        let report = doctor.run().await;
        let names: Vec<&str> = report.checks.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["config", "dns", "whois", "rdap-bootstrap"]);
        for check in &report.checks {
            assert_eq!(
                check.status,
                CheckStatus::Pass,
                "{}: {}",
                check.name,
                check.detail
            );
        }
        assert_eq!(report.overall, CheckStatus::Pass);
    }

    #[tokio::test]
    async fn run_isolates_probe_failures() {
        // WHOIS refused + RDAP 500 while config and DNS are healthy: the
        // failures must not abort the healthy probes, and overall is Fail.
        let missing_config = TmpFile::unique("run-absent");
        let whois_port = refused_port().await;
        let rdap = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&rdap)
            .await;

        let doctor = dns_doctor(MockMode::Zone)
            .await
            .with_config_path(missing_config.0.clone())
            .with_whois_addr(format!("127.0.0.1:{whois_port}"))
            .with_bootstrap_url(format!("{}/rdap/dns.json", rdap.uri()));

        let report = doctor.run().await;
        let by_name = |name: &str| {
            report
                .checks
                .iter()
                .find(|c| c.name == name)
                .unwrap_or_else(|| panic!("missing check {name}"))
        };
        assert_eq!(by_name("config").status, CheckStatus::Pass);
        assert_eq!(by_name("dns").status, CheckStatus::Pass);
        assert_eq!(by_name("whois").status, CheckStatus::Fail);
        assert_eq!(by_name("rdap-bootstrap").status, CheckStatus::Fail);
        assert_eq!(report.overall, CheckStatus::Fail);
    }

    #[tokio::test]
    async fn run_with_malformed_config_only_warns_overall() {
        // Warn-vs-Fail end to end: a broken config file must degrade the
        // report to Warn, never Fail, when every network probe passes.
        let config_file = TmpFile::with_content("run-malformed", "output_format = [broken");
        let whois_port = spawn_whois_responder(b"% ok\r\n").await;
        let rdap = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"services":[]}"#))
            .mount(&rdap)
            .await;

        let doctor = dns_doctor(MockMode::Zone)
            .await
            .with_config_path(config_file.0.clone())
            .with_whois_addr(format!("127.0.0.1:{whois_port}"))
            .with_bootstrap_url(format!("{}/rdap/dns.json", rdap.uri()));

        let report = doctor.run().await;
        assert_eq!(report.overall, CheckStatus::Warn);
    }
}
