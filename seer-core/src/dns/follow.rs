use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tracing::{debug, instrument};

use super::records::{DnsRecord, RecordType};
use super::resolver::DnsResolver;
use crate::error::{Result, SeerError};

/// Upper bound on follow iterations. A non-interactive caller (API / Python
/// bindings) passing a huge count would otherwise schedule an effectively
/// unbounded long-running loop; the interval is already capped at 60 minutes.
pub const MAX_FOLLOW_ITERATIONS: usize = 10_000;

/// Upper bound on the follow interval, in seconds (60 minutes). Exposed so
/// front-ends (e.g. the TUI) can clamp user input to the same range
/// `FollowConfig::new` enforces, instead of letting an over-range value fail
/// validation and silently no-op.
pub const MAX_FOLLOW_INTERVAL_SECS: u64 = 3600;

/// Configuration for DNS follow operation
#[derive(Debug, Clone)]
pub struct FollowConfig {
    /// Number of checks to perform
    pub iterations: usize,
    /// Interval between checks in seconds
    pub interval_secs: u64,
    /// Only output when records change
    pub changes_only: bool,
}

impl Default for FollowConfig {
    fn default() -> Self {
        Self {
            iterations: 10,
            interval_secs: 60,
            changes_only: false,
        }
    }
}

impl FollowConfig {
    /// Construct a new `FollowConfig`.
    ///
    /// Validates:
    /// - `iterations` must be >= 1
    /// - `interval_minutes` must be finite (not NaN / infinity)
    /// - `interval_minutes` must be non-negative
    /// - `interval_minutes` must be at most 60
    pub fn new(iterations: usize, interval_minutes: f64) -> Result<Self> {
        if iterations == 0 {
            return Err(SeerError::InvalidInput(
                "iterations must be at least 1".into(),
            ));
        }
        if iterations > MAX_FOLLOW_ITERATIONS {
            return Err(SeerError::InvalidInput(format!(
                "iterations must be at most {MAX_FOLLOW_ITERATIONS}"
            )));
        }
        if !interval_minutes.is_finite() {
            return Err(SeerError::InvalidInput(
                "interval_minutes must be a finite number".into(),
            ));
        }
        if interval_minutes < 0.0 {
            return Err(SeerError::InvalidInput(
                "interval_minutes must be non-negative".into(),
            ));
        }
        if interval_minutes > MAX_FOLLOW_INTERVAL_SECS as f64 / 60.0 {
            return Err(SeerError::InvalidInput(
                "interval_minutes must be at most 60".into(),
            ));
        }
        // Round to the nearest second rather than truncating: float minutes
        // rarely land exactly on a second (2.05 min * 60 = 122.999…), and
        // truncation silently shortened the interval.
        //
        // A sub-second interval rounds to 0 seconds. For a multi-iteration
        // follow that means back-to-back live DNS queries with no spacing — a
        // self-inflicted query flood. Floor to 1s whenever more than one
        // iteration will run; a single-shot follow (iterations == 1) does no
        // looping and may keep a 0s interval.
        let mut interval_secs = (interval_minutes * 60.0).round() as u64;
        if iterations > 1 {
            interval_secs = interval_secs.max(1);
        }
        Ok(Self {
            iterations,
            interval_secs,
            changes_only: false,
        })
    }

    pub fn with_changes_only(mut self, changes_only: bool) -> Self {
        self.changes_only = changes_only;
        self
    }

    /// Re-checks the bounds [`FollowConfig::new`] enforces. The fields are
    /// public, so a caller can build a config literally; [`DnsFollower::follow`]
    /// calls this first so an out-of-range literal (e.g. `iterations:
    /// usize::MAX`, which overflowed `Vec::with_capacity` and panicked) is
    /// rejected as input instead.
    fn validate(&self) -> Result<()> {
        if self.iterations == 0 || self.iterations > MAX_FOLLOW_ITERATIONS {
            return Err(SeerError::InvalidInput(format!(
                "iterations must be between 1 and {MAX_FOLLOW_ITERATIONS}"
            )));
        }
        if self.interval_secs > MAX_FOLLOW_INTERVAL_SECS {
            return Err(SeerError::InvalidInput(format!(
                "interval must be at most {MAX_FOLLOW_INTERVAL_SECS} seconds"
            )));
        }
        Ok(())
    }
}

/// Result of a single follow iteration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FollowIteration {
    /// Iteration number (1-based)
    pub iteration: usize,
    /// Total number of iterations
    pub total_iterations: usize,
    /// Timestamp of the check
    pub timestamp: DateTime<Utc>,
    /// Records found (or empty if error/NXDOMAIN)
    pub records: Vec<DnsRecord>,
    /// Whether records changed from previous iteration
    pub changed: bool,
    /// Values added since previous iteration
    pub added: Vec<String>,
    /// Values removed since previous iteration
    pub removed: Vec<String>,
    /// Error message if the check failed
    pub error: Option<String>,
}

impl FollowIteration {
    pub fn success(&self) -> bool {
        self.error.is_none()
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }
}

/// Complete result of a follow operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FollowResult {
    /// Domain that was monitored
    pub domain: String,
    /// Record type that was monitored
    pub record_type: RecordType,
    /// Nameserver used (if custom)
    pub nameserver: Option<String>,
    /// Configuration used
    pub iterations_requested: usize,
    pub interval_secs: u64,
    /// All iteration results
    pub iterations: Vec<FollowIteration>,
    /// Whether the operation was interrupted
    pub interrupted: bool,
    /// Total number of changes detected
    pub total_changes: usize,
    /// Start time
    pub started_at: DateTime<Utc>,
    /// End time
    pub ended_at: DateTime<Utc>,
}

impl FollowResult {
    pub fn completed_iterations(&self) -> usize {
        self.iterations.len()
    }
}

/// Callback type for real-time progress updates
pub type FollowProgressCallback = Arc<dyn Fn(&FollowIteration) + Send + Sync>;

/// DNS Follower - monitors DNS records over time
#[derive(Clone)]
pub struct DnsFollower {
    resolver: DnsResolver,
}

impl Default for DnsFollower {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsFollower {
    pub fn new() -> Self {
        Self {
            resolver: DnsResolver::new(),
        }
    }

    pub fn with_resolver(resolver: DnsResolver) -> Self {
        Self { resolver }
    }

    /// Builds a follower whose resolver honors `~/.seer/config.toml`
    /// (`timeouts.dns_secs`), like [`DnsResolver::from_config`]. As there, the
    /// configured nameserver is passed per call to [`DnsFollower::follow`].
    pub fn from_config(config: &crate::config::SeerConfig) -> Self {
        Self::with_resolver(DnsResolver::from_config(config))
    }

    /// Follow DNS records over time
    #[instrument(skip(self, config, callback, cancel_rx))]
    pub async fn follow(
        &self,
        domain: &str,
        record_type: RecordType,
        nameserver: Option<&str>,
        config: FollowConfig,
        callback: Option<FollowProgressCallback>,
        cancel_rx: Option<watch::Receiver<bool>>,
    ) -> Result<FollowResult> {
        config.validate()?;
        // The resolver's own per-name rule: keeps `www.` and passes an IPv6
        // PTR literal through (normalize_domain did neither).
        let domain = crate::dns::resolver::prepare_query(domain, record_type)?;
        let started_at = Utc::now();
        // Bounded by `validate` above.
        let mut iterations: Vec<FollowIteration> = Vec::with_capacity(config.iterations);
        // The last successful observation, if any. `None` until an iteration
        // succeeds, so a first iteration that errors can't become an empty
        // baseline that the first success then "changes" (added = every
        // record).
        let mut baseline: Option<Observation> = None;
        let mut total_changes = 0;
        let mut interrupted = false;

        debug!(
            domain = %domain,
            record_type = %record_type,
            iterations = config.iterations,
            interval_secs = config.interval_secs,
            "Starting DNS follow"
        );

        for i in 0..config.iterations {
            // Check for cancellation
            if let Some(ref rx) = cancel_rx {
                if *rx.borrow() {
                    debug!("Follow operation cancelled");
                    interrupted = true;
                    break;
                }
            }

            let timestamp = Utc::now();
            let iteration_num = i + 1;

            // Perform DNS lookup
            let (records, error) = match self
                .resolver
                .resolve(&domain, record_type, nameserver)
                .await
            {
                Ok(records) => (records, None),
                Err(e) => {
                    debug!(domain = %domain, error = %e, "DNS follow query failed");
                    // Sanitized for external return; full detail logged above.
                    (Vec::new(), Some(e.sanitized_message()))
                }
            };

            let current = observe(&records);

            // Compare with the last successful iteration. Keys fold case only
            // for domain-name fields (see `RecordData::comparison_key`), so a
            // resolver applying 0x20 randomization is not a spurious change
            // while a real case change in TXT data still is; `added` /
            // `removed` carry the values as the server returned them.
            let (changed, added, removed) = match (&baseline, &error) {
                (Some(previous), None) => diff_observations(&current, previous),
                // No successful observation yet (nothing to compare), or this
                // iteration errored: a transient resolver failure yields an
                // empty record set that would otherwise look like every record
                // was removed (and re-added on recovery), inflating
                // total_changes with phantom events.
                _ => (false, Vec::new(), Vec::new()),
            };

            if changed {
                total_changes += 1;
            }

            // Capture before `error` is moved into the iteration struct.
            let error_is_none = error.is_none();

            let iteration = FollowIteration {
                iteration: iteration_num,
                total_iterations: config.iterations,
                timestamp,
                records,
                changed,
                added,
                removed,
                error,
            };

            // Call progress callback
            if let Some(ref cb) = callback {
                // Only call if not changes_only mode, or if this is first iteration or changed
                if !config.changes_only || iteration_num == 1 || changed {
                    cb(&iteration);
                }
            }

            iterations.push(iteration);
            // Only a successful iteration becomes the baseline, so the last
            // known-good observation survives an errored iteration: the next
            // success is compared against real prior values rather than an
            // empty set (which would fabricate a full re-addition).
            if error_is_none {
                baseline = Some(current);
            }

            // Sleep before next iteration (unless this is the last one)
            if i < config.iterations - 1 {
                let sleep_duration = Duration::from_secs(config.interval_secs);

                // Use interruptible sleep
                if let Some(ref rx) = cancel_rx {
                    let mut rx_clone = rx.clone();
                    tokio::select! {
                        _ = tokio::time::sleep(sleep_duration) => {}
                        _ = rx_clone.changed() => {
                            if *rx_clone.borrow() {
                                debug!("Follow operation cancelled during sleep");
                                interrupted = true;
                                break;
                            }
                        }
                    }
                } else {
                    tokio::time::sleep(sleep_duration).await;
                }
            }
        }

        let ended_at = Utc::now();

        Ok(FollowResult {
            domain: domain.to_string(),
            record_type,
            nameserver: nameserver.map(|s| s.to_string()),
            iterations_requested: config.iterations,
            interval_secs: config.interval_secs,
            iterations,
            interrupted,
            total_changes,
            started_at,
            ended_at,
        })
    }
}

/// One iteration's record values: comparison key
/// ([`RecordData::comparison_key`](super::RecordData::comparison_key)) → the
/// value as the server returned it.
type Observation = BTreeMap<String, String>;

fn observe(records: &[DnsRecord]) -> Observation {
    records
        .iter()
        .map(|r| (r.data.comparison_key(), r.data.to_string()))
        .collect()
}

/// Diffs the current observation against the baseline. Returns `(changed,
/// added, removed)`: membership is decided on the comparison key — so a record
/// that reappears with only a case difference in a domain-name field (0x20
/// query-name randomization) is not a change — while `added` / `removed`
/// carry the values as the respective servers returned them.
fn diff_observations(
    current: &Observation,
    previous: &Observation,
) -> (bool, Vec<String>, Vec<String>) {
    let mut added: Vec<String> = current
        .iter()
        .filter(|(key, _)| !previous.contains_key(*key))
        .map(|(_, value)| value.clone())
        .collect();
    let mut removed: Vec<String> = previous
        .iter()
        .filter(|(key, _)| !current.contains_key(*key))
        .map(|(_, value)| value.clone())
        .collect();
    added.sort();
    added.dedup();
    removed.sort();
    removed.dedup();

    let changed = !added.is_empty() || !removed.is_empty();
    (changed, added, removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::super::records::RecordData;

    /// Regression: the TUI's live follow used `DnsFollower::new()` and so
    /// ignored the configured DNS timeout that `dig`, the CLI and the REPL
    /// honor. Every surface now builds its follower through `from_config`.
    #[test]
    fn from_config_applies_dns_timeout() {
        let mut config = crate::config::SeerConfig::default();
        config.timeouts.dns_secs = 9;
        let follower = DnsFollower::from_config(&config);
        assert_eq!(follower.resolver.timeout(), Duration::from_secs(9));
    }

    fn record(data: RecordData) -> DnsRecord {
        DnsRecord {
            name: "example.com".to_string(),
            record_type: RecordType::NS,
            ttl: 300,
            data,
        }
    }

    /// An observation of NS records, built the way `follow()` builds one.
    fn ns_observation<const N: usize>(names: [&str; N]) -> Observation {
        let records: Vec<DnsRecord> = names
            .iter()
            .map(|n| {
                record(RecordData::NS {
                    nameserver: n.to_string(),
                })
            })
            .collect();
        observe(&records)
    }

    #[tokio::test]
    async fn test_follow_config_default() {
        let config = FollowConfig::default();
        assert_eq!(config.iterations, 10);
        assert_eq!(config.interval_secs, 60);
        assert!(!config.changes_only);
    }

    /// Records that differ only in case between iterations (e.g. a resolver that
    /// applies 0x20 query-name randomization to NS answers) must NOT be reported
    /// as a change. The comparison key is case-folded.
    #[test]
    fn diff_values_ignores_case_only_differences() {
        let previous = ns_observation(["NS1.EXAMPLE.COM.", "ns2.example.com."]);
        let current = ns_observation(["ns1.example.com.", "NS2.EXAMPLE.COM."]);
        let (changed, added, removed) = diff_observations(&current, &previous);
        assert!(!changed, "case-only differences must not count as a change");
        assert!(added.is_empty(), "no added values: {added:?}");
        assert!(removed.is_empty(), "no removed values: {removed:?}");
    }

    /// A genuine value change is still detected, and `added`/`removed` carry the
    /// original casing for display (the removed value now keeps the casing the
    /// earlier server returned, rather than a lowercased key).
    #[test]
    fn diff_values_detects_real_change_preserving_case() {
        let previous = ns_observation(["NS1.Example.com."]);
        let current = ns_observation(["NS2.Example.Com."]);
        let (changed, added, removed) = diff_observations(&current, &previous);
        assert!(changed, "a different nameserver is a real change");
        assert_eq!(added, vec!["NS2.Example.Com.".to_string()]);
        assert_eq!(removed, vec!["NS1.Example.com.".to_string()]);
    }

    /// TXT data is case-sensitive: a token rotated from `AbC` to `abc` is a
    /// real change (case used to be folded for every record type).
    #[test]
    fn diff_values_reports_case_change_in_txt() {
        let txt = |t: &str| {
            observe(&[record(RecordData::TXT {
                text: t.to_string(),
            })])
        };
        let (changed, added, removed) = diff_observations(&txt("token=abc"), &txt("token=AbC"));
        assert!(changed);
        assert_eq!(added, vec!["\"token=abc\"".to_string()]);
        assert_eq!(removed, vec!["\"token=AbC\"".to_string()]);
    }

    #[test]
    fn follow_config_rounds_interval_to_nearest_second() {
        // 2.05 min * 60 = 122.999…; truncation gave 122s.
        assert_eq!(FollowConfig::new(2, 2.05).unwrap().interval_secs, 123);
        assert_eq!(FollowConfig::new(2, 0.5).unwrap().interval_secs, 30);
    }

    /// `FollowConfig`'s fields are public, so `follow` must re-validate:
    /// `iterations: usize::MAX` used to reach `Vec::with_capacity` and panic
    /// with a capacity overflow.
    #[tokio::test]
    async fn follow_rejects_out_of_range_literal_config() {
        let follower = DnsFollower::new();
        for config in [
            FollowConfig {
                iterations: usize::MAX,
                interval_secs: 1,
                changes_only: false,
            },
            FollowConfig {
                iterations: 0,
                interval_secs: 1,
                changes_only: false,
            },
            FollowConfig {
                iterations: 2,
                interval_secs: MAX_FOLLOW_INTERVAL_SECS + 1,
                changes_only: false,
            },
        ] {
            let err = follower
                .follow("example.com", RecordType::A, None, config, None, None)
                .await
                .expect_err("out-of-range config must be rejected before any query");
            assert!(matches!(err, SeerError::InvalidInput(_)), "{err:?}");
        }
    }

    /// Regression: when iteration 1 errored, the (empty) error result became
    /// the diff baseline, so the first successful iteration reported every
    /// record as added and `changed = true`. The baseline must be the first
    /// SUCCESSFUL observation.
    #[tokio::test]
    async fn follow_first_iteration_error_is_not_a_baseline() {
        use std::sync::atomic::{AtomicBool, Ordering};

        use hickory_resolver::proto::rr::rdata as wire;
        use hickory_resolver::proto::rr::{RData as HickoryRData, RecordType as WireType};

        use crate::dns::test_support::{mock_dns_resolver, spawn_mock_dns_fn, MockReply};

        // SERVFAIL until the first iteration's callback flips the switch, so
        // every retry hickory makes inside iteration 1 fails too.
        let healthy = Arc::new(AtomicBool::new(false));
        let port = spawn_mock_dns_fn({
            let healthy = Arc::clone(&healthy);
            move |_, qtype| {
                if healthy.load(Ordering::SeqCst) && qtype == WireType::A {
                    MockReply::Answer(vec![HickoryRData::A(wire::A(std::net::Ipv4Addr::new(
                        192, 0, 2, 7,
                    )))])
                } else {
                    MockReply::ServFail
                }
            }
        })
        .await;
        let callback: FollowProgressCallback = {
            let healthy = Arc::clone(&healthy);
            Arc::new(move |_: &FollowIteration| healthy.store(true, Ordering::SeqCst))
        };

        let config = FollowConfig {
            iterations: 3,
            interval_secs: 0,
            changes_only: false,
        };
        let result = DnsFollower::with_resolver(mock_dns_resolver(port))
            .follow(
                "seer.test",
                RecordType::A,
                Some("127.0.0.1"),
                config,
                Some(callback),
                None,
            )
            .await
            .expect("follow against the mock fixture");

        assert!(!result.iterations[0].success(), "iteration 1 must error");
        let second = &result.iterations[1];
        assert!(second.success(), "{second:?}");
        assert!(
            !second.changed && second.added.is_empty() && second.removed.is_empty(),
            "the first success establishes the baseline, it is not a change: {second:?}"
        );
        assert!(!result.iterations[2].changed);
        assert_eq!(result.total_changes, 0);
    }

    /// `follow` keeps `www.` and accepts IPv6 PTR literals, like `resolve`.
    #[tokio::test]
    async fn follow_uses_per_name_normalization() {
        use crate::dns::test_support::{mock_dns_resolver, spawn_mock_dns, MockMode};

        let port = spawn_mock_dns(MockMode::Zone).await;
        let follower = DnsFollower::with_resolver(mock_dns_resolver(port));
        let one_shot = || FollowConfig::new(1, 0.0).expect("valid config");

        let result = follower
            .follow(
                "www.seer.test",
                RecordType::CNAME,
                Some("127.0.0.1"),
                one_shot(),
                None,
                None,
            )
            .await
            .expect("follow www");
        assert_eq!(result.domain, "www.seer.test");
        assert_eq!(result.iterations[0].record_count(), 1);

        let result = follower
            .follow(
                "2606:4700:4700::1111",
                RecordType::PTR,
                Some("127.0.0.1"),
                one_shot(),
                None,
                None,
            )
            .await
            .expect("IPv6 PTR literal must be accepted");
        assert_eq!(result.domain, "2606:4700:4700::1111");
        assert_eq!(result.iterations[0].record_count(), 1);
    }

    #[test]
    fn follow_config_rejects_unbounded_iterations() {
        assert!(FollowConfig::new(MAX_FOLLOW_ITERATIONS, 1.0).is_ok());
        let err = FollowConfig::new(MAX_FOLLOW_ITERATIONS + 1, 1.0).unwrap_err();
        assert!(matches!(err, SeerError::InvalidInput(_)));
        assert!(FollowConfig::new(usize::MAX, 1.0).is_err());
    }

    #[tokio::test]
    async fn test_follow_config_new() {
        let config = FollowConfig::new(5, 0.5).unwrap();
        assert_eq!(config.iterations, 5);
        assert_eq!(config.interval_secs, 30);
    }

    /// Hermetic follow-loop test against the sequenced mock DNS fixture in
    /// [`crate::dns::test_support`]. Covers the loop end-to-end: the initial
    /// snapshot (never a "change"), one record-change detection event with
    /// the correct added/removed diff, a steady-state iteration, callback
    /// delivery for every iteration, and a clean (uninterrupted) exit.
    #[tokio::test]
    async fn follow_loop_detects_change_against_mock_dns() {
        use std::sync::Mutex;

        use hickory_resolver::proto::rr::rdata as wire;
        use hickory_resolver::proto::rr::RData as HickoryRData;

        use crate::dns::test_support::{mock_dns_resolver, spawn_mock_dns_sequence};

        let a = |last_octet: u8| {
            HickoryRData::A(wire::A(std::net::Ipv4Addr::new(192, 0, 2, last_octet)))
        };
        // Iteration 1 sees .1; iteration 2 sees .2 (the change); iteration 3
        // sees .2 again (steady state).
        let port = spawn_mock_dns_sequence(vec![vec![a(1)], vec![a(2)], vec![a(2)]]).await;

        // Built literally rather than via FollowConfig::new: the constructor
        // floors multi-iteration intervals to 1s (anti-flood), but against a
        // loopback fixture a 0s interval is harmless and keeps the test fast.
        let config = FollowConfig {
            iterations: 3,
            interval_secs: 0,
            changes_only: false,
        };

        let seen: Arc<Mutex<Vec<(usize, bool)>>> = Arc::new(Mutex::new(Vec::new()));
        let callback: FollowProgressCallback = {
            let seen = Arc::clone(&seen);
            Arc::new(move |it: &FollowIteration| {
                seen.lock()
                    .expect("callback mutex")
                    .push((it.iteration, it.changed));
            })
        };

        let follower = DnsFollower::with_resolver(mock_dns_resolver(port));
        let result = follower
            .follow(
                "seer.test",
                RecordType::A,
                Some("127.0.0.1"),
                config,
                Some(callback),
                None,
            )
            .await
            .expect("follow against the mock fixture must succeed");

        // Clean loop exit: every iteration ran, none errored, no interrupt.
        assert_eq!(result.completed_iterations(), 3);
        assert!(result.iterations.iter().all(|i| i.success()));
        assert!(!result.interrupted);
        assert_eq!(result.domain, "seer.test");
        assert_eq!(result.record_type, RecordType::A);

        // Iteration 1 — initial snapshot: records present, no diff baseline.
        let first = &result.iterations[0];
        assert_eq!(first.record_count(), 1);
        assert_eq!(first.records[0].data.to_string(), "192.0.2.1");
        assert!(!first.changed, "first iteration is never a change");
        assert!(first.added.is_empty() && first.removed.is_empty());

        // Iteration 2 — the record set changed and the diff names both sides.
        let second = &result.iterations[1];
        assert!(second.changed, "record change must be detected");
        assert_eq!(second.added, vec!["192.0.2.2".to_string()]);
        assert_eq!(second.removed, vec!["192.0.2.1".to_string()]);

        // Iteration 3 — steady state: same records, no phantom change.
        let third = &result.iterations[2];
        assert!(!third.changed, "unchanged records must not be a change");
        assert!(third.added.is_empty() && third.removed.is_empty());

        assert_eq!(result.total_changes, 1);

        // changes_only=false → the callback fired for every iteration.
        let seen = seen.lock().expect("callback mutex");
        assert_eq!(*seen, vec![(1, false), (2, true), (3, false)]);
    }

    #[tokio::test]
    #[ignore = "live network; run with --ignored or SEER_LIVE_TESTS=1"]
    async fn test_follow_single_iteration() {
        let follower = DnsFollower::new();
        let config = FollowConfig::new(1, 0.0).unwrap();

        let result = follower
            .follow("example.com", RecordType::A, None, config, None, None)
            .await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.completed_iterations(), 1);
        assert!(!result.interrupted);
    }

    #[test]
    fn follow_config_rejects_zero_iterations() {
        assert!(FollowConfig::new(0, 1.0).is_err());
    }

    #[test]
    fn follow_config_rejects_infinite_interval() {
        assert!(FollowConfig::new(10, f64::INFINITY).is_err());
        assert!(FollowConfig::new(10, f64::NEG_INFINITY).is_err());
    }

    #[test]
    fn follow_config_rejects_nan_interval() {
        assert!(FollowConfig::new(10, f64::NAN).is_err());
    }

    #[test]
    fn follow_config_rejects_negative_interval() {
        assert!(FollowConfig::new(10, -1.0).is_err());
    }

    #[test]
    fn follow_config_rejects_interval_above_cap() {
        assert!(FollowConfig::new(10, 60.1).is_err());
    }

    #[test]
    fn follow_config_accepts_valid() {
        assert!(FollowConfig::new(10, 1.5).is_ok());
        assert!(FollowConfig::new(1, 0.0).is_ok());
        assert!(FollowConfig::new(1, 60.0).is_ok());
    }

    #[test]
    fn follow_config_floors_subsecond_interval_for_multi_iteration() {
        // A sub-second interval truncates to 0s; with many iterations that is
        // a back-to-back live-DNS query flood. Multi-iteration follows must
        // be floored to at least 1s between queries.
        let config = FollowConfig::new(10_000, 0.001).unwrap();
        assert!(
            config.interval_secs >= 1,
            "multi-iteration interval must be floored to >= 1s, got {}",
            config.interval_secs
        );
    }

    #[test]
    fn follow_config_allows_zero_interval_for_single_iteration() {
        // A single-shot follow does no looping, so a 0s interval is harmless
        // and must not be forced to 1s.
        let config = FollowConfig::new(1, 0.0).unwrap();
        assert_eq!(config.interval_secs, 0);
    }

    #[tokio::test]
    #[ignore = "live network; run with --ignored or SEER_LIVE_TESTS=1"]
    async fn follow_honors_cancel() {
        use tokio::sync::watch;

        let (tx, rx) = watch::channel(false);
        // 100 iterations with 30s intervals would take ~50 minutes.
        let config = FollowConfig::new(100, 0.5).unwrap();
        let follower = DnsFollower::new();

        let handle = tokio::spawn(async move {
            follower
                .follow("example.com", RecordType::A, None, config, None, Some(rx))
                .await
        });

        // Give the follow a tick to start and get into its first sleep.
        tokio::time::sleep(Duration::from_millis(200)).await;
        tx.send(true).unwrap();

        let joined = tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("follow should return promptly after cancel");
        let result = joined.expect("join").expect("follow result");
        assert!(result.interrupted, "follow should be interrupted");
        assert!(
            result.completed_iterations() < 100,
            "should not complete all iterations"
        );
    }
}
