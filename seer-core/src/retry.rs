//! Retry logic with exponential backoff for transient failures.
//!
//! This module provides configurable retry policies and executors for handling
//! transient network failures in WHOIS and RDAP lookups.

use std::future::Future;
use std::time::Duration;

use rand::Rng;
use tracing::{debug, warn};

use crate::error::{Result, SeerError};

/// Configuration for retry behavior with exponential backoff.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of attempts (including the initial attempt).
    pub max_attempts: usize,
    /// Initial delay before the first retry.
    pub initial_delay: Duration,
    /// Maximum delay between retries (caps exponential growth).
    pub max_delay: Duration,
    /// Multiplier for exponential backoff (delay *= multiplier after each retry).
    pub multiplier: f64,
    /// Whether to add random jitter to delays to avoid thundering herd.
    pub jitter: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
            multiplier: 2.0,
            jitter: true,
        }
    }
}

impl RetryPolicy {
    /// Creates a new retry policy with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the maximum number of attempts.
    pub fn with_max_attempts(mut self, attempts: usize) -> Self {
        self.max_attempts = attempts.max(1);
        self
    }

    /// Sets the initial delay before the first retry.
    pub fn with_initial_delay(mut self, delay: Duration) -> Self {
        self.initial_delay = delay;
        self
    }

    /// Sets the maximum delay between retries.
    pub fn with_max_delay(mut self, delay: Duration) -> Self {
        self.max_delay = delay;
        self
    }

    /// Sets the multiplier for exponential backoff.
    pub fn with_multiplier(mut self, multiplier: f64) -> Self {
        self.multiplier = multiplier.max(1.0);
        self
    }

    /// Enables or disables jitter.
    pub fn with_jitter(mut self, jitter: bool) -> Self {
        self.jitter = jitter;
        self
    }

    /// Creates a policy that disables retries (single attempt only).
    pub fn no_retry() -> Self {
        Self {
            max_attempts: 1,
            ..Self::default()
        }
    }

    /// Calculates the delay for a given attempt number (0-indexed).
    ///
    /// The attempt number is internally capped to prevent integer overflow
    /// in the exponential calculation.
    pub fn delay_for_attempt(&self, attempt: usize) -> Duration {
        if attempt == 0 {
            return self.initial_delay;
        }

        // Cap attempt to prevent overflow in powi() - 20 attempts with multiplier 2.0
        // gives 2^20 = ~1 million, which is safe for f64 and reasonable for delays
        let safe_attempt = attempt.min(20) as i32;

        let base_delay = self.initial_delay.as_millis() as f64 * self.multiplier.powi(safe_attempt);
        let capped_delay = base_delay.min(self.max_delay.as_millis() as f64);

        let final_delay = if self.jitter {
            // Add jitter: random value between 50% and 100% of the delay
            let mut rng = rand::thread_rng();
            let jitter_factor = rng.gen_range(0.5..1.0);
            capped_delay * jitter_factor
        } else {
            capped_delay
        };

        Duration::from_millis(final_delay as u64)
    }
}

/// Trait for classifying whether an error is retryable.
pub trait RetryClassifier: Send + Sync {
    /// Returns true if the error is transient and the operation should be retried.
    fn is_retryable(&self, error: &SeerError) -> bool;
}

/// Default classifier for network operations (WHOIS/RDAP).
///
/// Classifies the following as retryable:
/// - Timeouts
/// - Connection failures (IO errors)
/// - Rate limiting (429)
/// - Server errors (5xx)
///
/// Non-retryable errors:
/// - Invalid input (domain, IP, record type)
/// - Server not found
/// - Parse errors (JSON, WHOIS format)
#[derive(Debug, Clone, Default)]
pub struct NetworkRetryClassifier;

impl NetworkRetryClassifier {
    pub fn new() -> Self {
        Self
    }
}

impl RetryClassifier for NetworkRetryClassifier {
    fn is_retryable(&self, error: &SeerError) -> bool {
        match error {
            // Transient errors - worth retrying
            SeerError::Timeout(_) => true,
            SeerError::WhoisConnectionFailed(_) => true,
            SeerError::RateLimited(_) => true,

            // Reqwest errors need deeper inspection
            SeerError::ReqwestError(e) => is_transient_reqwest_error(e),

            // WHOIS errors might be transient if they're connection-related
            SeerError::WhoisError(msg) => {
                let lower = msg.to_lowercase();
                lower.contains("connection")
                    || lower.contains("timeout")
                    || lower.contains("refused")
                    || lower.contains("reset")
            }

            // RDAP errors might be transient server errors
            SeerError::RdapError(msg) => {
                let lower = msg.to_lowercase();
                lower.contains("status 5")
                    || lower.contains("status 429")
                    || lower.contains("timeout")
            }

            // Bootstrap errors could be transient if IANA is temporarily unavailable
            SeerError::RdapBootstrapError(msg) => {
                let lower = msg.to_lowercase();
                lower.contains("timeout") || lower.contains("connection")
            }

            // DNS errors can be transient
            SeerError::DnsError(msg) => {
                let lower = msg.to_lowercase();
                lower.contains("timeout") || lower.contains("temporary")
            }

            // HTTP errors might be transient
            SeerError::HttpError(msg) => {
                let lower = msg.to_lowercase();
                lower.contains("timeout") || lower.contains("connection") || lower.contains("5")
            }

            // Not retryable - permanent failures
            SeerError::InvalidDomain(_) => false,
            SeerError::DomainNotAllowed { .. } => false,
            SeerError::InvalidIpAddress(_) => false,
            SeerError::InvalidRecordType(_) => false,
            SeerError::WhoisServerNotFound(_) => false,
            SeerError::JsonError(_) => false,
            SeerError::CertificateError(_) => false,
            SeerError::DnsResolverError(_) => false,
            SeerError::BulkOperationError { .. } => false,
            SeerError::LookupFailed { .. } => false,
            SeerError::RetryExhausted { .. } => false,
            SeerError::Other(_) => false,
        }
    }
}

/// Checks if a reqwest error is transient and worth retrying.
fn is_transient_reqwest_error(error: &reqwest::Error) -> bool {
    // Connection errors are transient
    if error.is_connect() {
        return true;
    }

    // Timeout errors are transient
    if error.is_timeout() {
        return true;
    }

    // Check HTTP status codes
    if let Some(status) = error.status() {
        // 429 Too Many Requests - rate limited, retry with backoff
        if status.as_u16() == 429 {
            return true;
        }
        // 5xx Server errors are transient
        if status.is_server_error() {
            return true;
        }
        // 4xx Client errors (except 429) are not retryable
        return false;
    }

    // Request/body errors are generally not retryable
    if error.is_request() || error.is_body() {
        return false;
    }

    // Default: assume transient for unknown errors
    true
}

/// Executes operations with retry logic using exponential backoff.
#[derive(Debug, Clone)]
pub struct RetryExecutor<C: RetryClassifier> {
    policy: RetryPolicy,
    classifier: C,
}

impl RetryExecutor<NetworkRetryClassifier> {
    /// Creates a new executor with the default network retry classifier.
    pub fn new(policy: RetryPolicy) -> Self {
        Self {
            policy,
            classifier: NetworkRetryClassifier::new(),
        }
    }
}

impl<C: RetryClassifier> RetryExecutor<C> {
    /// Creates a new executor with a custom classifier.
    pub fn with_classifier(policy: RetryPolicy, classifier: C) -> Self {
        Self { policy, classifier }
    }

    /// Executes an async operation with retry logic.
    ///
    /// The operation will be retried up to `max_attempts` times if it fails
    /// with a retryable error. Delays between retries follow exponential
    /// backoff with optional jitter.
    pub async fn execute<F, Fut, T>(&self, mut operation: F) -> Result<T>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let mut last_error: Option<SeerError> = None;
        let mut attempt = 0;

        while attempt < self.policy.max_attempts {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    let is_retryable = self.classifier.is_retryable(&e);
                    let attempts_remaining = self.policy.max_attempts - attempt - 1;

                    if !is_retryable || attempts_remaining == 0 {
                        if attempt > 0 {
                            warn!(
                                attempt = attempt + 1,
                                max_attempts = self.policy.max_attempts,
                                error = %e,
                                "Operation failed after retries"
                            );
                        }
                        return Err(if attempt > 0 {
                            SeerError::RetryExhausted {
                                attempts: attempt + 1,
                                last_error: e.to_string(),
                            }
                        } else {
                            e
                        });
                    }

                    let delay = self.policy.delay_for_attempt(attempt);
                    debug!(
                        attempt = attempt + 1,
                        max_attempts = self.policy.max_attempts,
                        delay_ms = delay.as_millis(),
                        error = %e,
                        "Retrying after transient error"
                    );

                    last_error = Some(e);
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                }
            }
        }

        // Should not reach here, but handle it gracefully
        Err(last_error.unwrap_or_else(|| SeerError::Other("retry loop exited unexpectedly".into())))
    }

    /// Executes an async operation once without retries.
    /// Useful for operations that should not be retried.
    pub async fn execute_once<F, Fut, T>(&self, operation: F) -> Result<T>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        operation().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn test_retry_policy_defaults() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_attempts, 3);
        assert_eq!(policy.initial_delay, Duration::from_millis(100));
        assert_eq!(policy.max_delay, Duration::from_secs(5));
        assert_eq!(policy.multiplier, 2.0);
        assert!(policy.jitter);
    }

    #[test]
    fn test_retry_policy_builder() {
        let policy = RetryPolicy::new()
            .with_max_attempts(5)
            .with_initial_delay(Duration::from_millis(200))
            .with_max_delay(Duration::from_secs(10))
            .with_multiplier(3.0)
            .with_jitter(false);

        assert_eq!(policy.max_attempts, 5);
        assert_eq!(policy.initial_delay, Duration::from_millis(200));
        assert_eq!(policy.max_delay, Duration::from_secs(10));
        assert_eq!(policy.multiplier, 3.0);
        assert!(!policy.jitter);
    }

    #[test]
    fn test_delay_calculation_no_jitter() {
        let policy = RetryPolicy::new()
            .with_initial_delay(Duration::from_millis(100))
            .with_multiplier(2.0)
            .with_max_delay(Duration::from_secs(10))
            .with_jitter(false);

        assert_eq!(policy.delay_for_attempt(0), Duration::from_millis(100));
        assert_eq!(policy.delay_for_attempt(1), Duration::from_millis(200));
        assert_eq!(policy.delay_for_attempt(2), Duration::from_millis(400));
        assert_eq!(policy.delay_for_attempt(3), Duration::from_millis(800));
    }

    #[test]
    fn test_delay_capped_at_max() {
        let policy = RetryPolicy::new()
            .with_initial_delay(Duration::from_secs(1))
            .with_multiplier(10.0)
            .with_max_delay(Duration::from_secs(5))
            .with_jitter(false);

        // 1s * 10^2 = 100s, but capped at 5s
        assert_eq!(policy.delay_for_attempt(2), Duration::from_secs(5));
    }

    #[test]
    fn test_classifier_timeout_is_retryable() {
        let classifier = NetworkRetryClassifier::new();
        assert!(classifier.is_retryable(&SeerError::Timeout("test".to_string())));
    }

    #[test]
    fn test_classifier_invalid_domain_not_retryable() {
        let classifier = NetworkRetryClassifier::new();
        assert!(!classifier.is_retryable(&SeerError::InvalidDomain("test".to_string())));
    }

    #[test]
    fn test_classifier_server_not_found_not_retryable() {
        let classifier = NetworkRetryClassifier::new();
        assert!(!classifier.is_retryable(&SeerError::WhoisServerNotFound("test".to_string())));
    }

    #[test]
    fn test_classifier_rate_limited_is_retryable() {
        let classifier = NetworkRetryClassifier::new();
        assert!(classifier.is_retryable(&SeerError::RateLimited("test".to_string())));
    }

    #[tokio::test]
    async fn test_executor_success_on_first_try() {
        let policy = RetryPolicy::new().with_max_attempts(3);
        let executor = RetryExecutor::new(policy);
        let attempts = Arc::new(AtomicUsize::new(0));

        let attempts_clone = attempts.clone();
        let result: Result<&str> = executor
            .execute(|| {
                let a = attempts_clone.clone();
                async move {
                    a.fetch_add(1, Ordering::SeqCst);
                    Ok("success")
                }
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "success");
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_executor_retries_on_transient_error() {
        let policy = RetryPolicy::new()
            .with_max_attempts(3)
            .with_initial_delay(Duration::from_millis(1))
            .with_jitter(false);
        let executor = RetryExecutor::new(policy);
        let attempts = Arc::new(AtomicUsize::new(0));

        let attempts_clone = attempts.clone();
        let result: Result<&str> = executor
            .execute(|| {
                let a = attempts_clone.clone();
                async move {
                    let count = a.fetch_add(1, Ordering::SeqCst);
                    if count < 2 {
                        Err(SeerError::Timeout("test timeout".to_string()))
                    } else {
                        Ok("success after retries")
                    }
                }
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "success after retries");
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_executor_no_retry_on_non_retryable_error() {
        let policy = RetryPolicy::new()
            .with_max_attempts(3)
            .with_initial_delay(Duration::from_millis(1));
        let executor = RetryExecutor::new(policy);
        let attempts = Arc::new(AtomicUsize::new(0));

        let attempts_clone = attempts.clone();
        let result: Result<&str> = executor
            .execute(|| {
                let a = attempts_clone.clone();
                async move {
                    a.fetch_add(1, Ordering::SeqCst);
                    Err(SeerError::InvalidDomain("bad.".to_string()))
                }
            })
            .await;

        assert!(result.is_err());
        // Should only attempt once since InvalidDomain is not retryable
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_executor_exhausts_retries() {
        let policy = RetryPolicy::new()
            .with_max_attempts(3)
            .with_initial_delay(Duration::from_millis(1))
            .with_jitter(false);
        let executor = RetryExecutor::new(policy);
        let attempts = Arc::new(AtomicUsize::new(0));

        let attempts_clone = attempts.clone();
        let result: Result<&str> = executor
            .execute(|| {
                let a = attempts_clone.clone();
                async move {
                    a.fetch_add(1, Ordering::SeqCst);
                    Err(SeerError::Timeout("always fails".to_string()))
                }
            })
            .await;

        assert!(result.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 3);

        // Check that we get RetryExhausted error
        match result.unwrap_err() {
            SeerError::RetryExhausted { attempts, .. } => {
                assert_eq!(attempts, 3);
            }
            other => panic!("Expected RetryExhausted, got {:?}", other),
        }
    }

    #[test]
    fn test_no_retry_policy() {
        let policy = RetryPolicy::no_retry();
        assert_eq!(policy.max_attempts, 1);
    }

    #[test]
    fn test_delay_overflow_protection() {
        let policy = RetryPolicy::new()
            .with_initial_delay(Duration::from_millis(100))
            .with_multiplier(2.0)
            .with_max_delay(Duration::from_secs(5))
            .with_jitter(false);

        // Test with very large attempt numbers - should not panic or produce invalid durations
        let delay_50 = policy.delay_for_attempt(50);
        let delay_100 = policy.delay_for_attempt(100);
        let delay_1000 = policy.delay_for_attempt(1000);

        // All should be capped at max_delay due to our overflow protection
        assert!(delay_50 <= Duration::from_secs(5));
        assert!(delay_100 <= Duration::from_secs(5));
        assert!(delay_1000 <= Duration::from_secs(5));
    }
}
