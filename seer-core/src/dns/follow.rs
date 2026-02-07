use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tracing::{debug, instrument};

use super::records::{DnsRecord, RecordType};
use super::resolver::DnsResolver;
use crate::error::Result;

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
    pub fn new(iterations: usize, interval_minutes: f64) -> Self {
        Self {
            iterations,
            interval_secs: (interval_minutes * 60.0) as u64,
            changes_only: false,
        }
    }

    pub fn with_changes_only(mut self, changes_only: bool) -> Self {
        self.changes_only = changes_only;
        self
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

    pub fn successful_iterations(&self) -> usize {
        self.iterations.iter().filter(|i| i.success()).count()
    }

    pub fn failed_iterations(&self) -> usize {
        self.iterations.iter().filter(|i| !i.success()).count()
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
        let started_at = Utc::now();
        let mut iterations: Vec<FollowIteration> = Vec::with_capacity(config.iterations);
        let mut previous_values: HashSet<String> = HashSet::new();
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
            let (records, error) =
                match self.resolver.resolve(domain, record_type, nameserver).await {
                    Ok(records) => (records, None),
                    Err(e) => (Vec::new(), Some(e.to_string())),
                };

            // Extract record values for comparison
            let current_values: HashSet<String> =
                records.iter().map(|r| r.data.to_string()).collect();

            // Compare with previous iteration
            let (changed, added, removed) = if i == 0 {
                // First iteration - no previous to compare
                (false, Vec::new(), Vec::new())
            } else {
                let added: Vec<String> = current_values
                    .difference(&previous_values)
                    .cloned()
                    .collect();
                let removed: Vec<String> = previous_values
                    .difference(&current_values)
                    .cloned()
                    .collect();
                let changed = !added.is_empty() || !removed.is_empty();
                (changed, added, removed)
            };

            if changed {
                total_changes += 1;
            }

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
            previous_values = current_values;

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

    /// Simple follow without callback or cancellation
    pub async fn follow_simple(
        &self,
        domain: &str,
        record_type: RecordType,
        nameserver: Option<&str>,
        config: FollowConfig,
    ) -> Result<FollowResult> {
        self.follow(domain, record_type, nameserver, config, None, None)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_follow_config_default() {
        let config = FollowConfig::default();
        assert_eq!(config.iterations, 10);
        assert_eq!(config.interval_secs, 60);
        assert!(!config.changes_only);
    }

    #[tokio::test]
    async fn test_follow_config_new() {
        let config = FollowConfig::new(5, 0.5);
        assert_eq!(config.iterations, 5);
        assert_eq!(config.interval_secs, 30);
    }

    #[tokio::test]
    async fn test_follow_single_iteration() {
        let follower = DnsFollower::new();
        let config = FollowConfig::new(1, 0.0);

        let result = follower
            .follow_simple("example.com", RecordType::A, None, config)
            .await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.completed_iterations(), 1);
        assert!(!result.interrupted);
    }
}
