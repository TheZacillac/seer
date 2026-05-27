use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::time::{sleep_until, Instant as TokioInstant};
use tracing::{debug, info, instrument};

use crate::availability::{AvailabilityChecker, AvailabilityResult};
use crate::dns::{DnsRecord, DnsResolver, PropagationChecker, PropagationResult, RecordType};
use crate::error::Result;
use crate::lookup::{LookupResult, SmartLookup};
use crate::rdap::{RdapClient, RdapResponse};
use crate::ssl::{SslChecker, SslReport};
use crate::status::{StatusClient, StatusResponse};
use crate::whois::{WhoisClient, WhoisResponse};

pub type ProgressCallback = Box<dyn Fn(usize, usize, &str) + Send + Sync>;

/// A single operation to perform in a bulk execution batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BulkOperation {
    Whois {
        domain: String,
    },
    Rdap {
        domain: String,
    },
    Dns {
        domain: String,
        record_type: RecordType,
    },
    Propagation {
        domain: String,
        record_type: RecordType,
    },
    Lookup {
        domain: String,
    },
    Status {
        domain: String,
    },
    Avail {
        domain: String,
    },
    Info {
        domain: String,
    },
    Ssl {
        domain: String,
    },
}

/// The data returned from a bulk operation (varies by operation type).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result_type", content = "data", rename_all = "snake_case")]
pub enum BulkResultData {
    Whois(WhoisResponse),
    Rdap(Box<RdapResponse>),
    Dns(Vec<DnsRecord>),
    Propagation(PropagationResult),
    Lookup(LookupResult),
    Status(StatusResponse),
    Avail(AvailabilityResult),
    Info(crate::domain_info::DomainInfo),
    Ssl(SslReport),
}

/// Result of a single operation within a bulk execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkResult {
    pub operation: BulkOperation,
    pub success: bool,
    pub data: Option<BulkResultData>,
    pub error: Option<String>,
    pub duration_ms: u64,
}

/// Executes bulk operations concurrently with rate limiting.
#[derive(Debug, Clone)]
pub struct BulkExecutor {
    concurrency: usize,
    rate_limit_delay: Duration,
    whois_client: WhoisClient,
    rdap_client: RdapClient,
    dns_resolver: DnsResolver,
    propagation_checker: PropagationChecker,
    smart_lookup: SmartLookup,
    status_client: StatusClient,
    availability_checker: AvailabilityChecker,
    ssl_checker: SslChecker,
}

impl Default for BulkExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl BulkExecutor {
    pub fn new() -> Self {
        Self {
            concurrency: 10,
            rate_limit_delay: Duration::from_millis(100),
            whois_client: WhoisClient::new(),
            rdap_client: RdapClient::new(),
            dns_resolver: DnsResolver::new(),
            propagation_checker: PropagationChecker::new(),
            smart_lookup: SmartLookup::new(),
            status_client: StatusClient::new(),
            availability_checker: AvailabilityChecker::new(),
            ssl_checker: SslChecker::new(),
        }
    }

    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency.clamp(1, 50);
        self
    }

    pub fn with_rate_limit(mut self, delay: Duration) -> Self {
        self.rate_limit_delay = delay;
        self
    }

    #[instrument(skip(self, operations, progress), fields(count = operations.len(), concurrency = self.concurrency))]
    pub async fn execute(
        &self,
        operations: Vec<BulkOperation>,
        progress: Option<ProgressCallback>,
    ) -> Vec<BulkResult> {
        let total = operations.len();
        let completed = Arc::new(AtomicUsize::new(0));

        info!("bulk operation started");
        debug!(
            total = total,
            concurrency = self.concurrency,
            "Starting bulk execution"
        );

        // Per-batch rate limiter. The naive `interval(...).tick().await` inside
        // a `Mutex` would hold the lock across the await, serializing all
        // dispatch through the lock at 1 / rate_limit_delay — exactly the
        // regression v0.26.7 tried to fix from the other direction.
        //
        // Instead each task locks briefly to *claim* its dispatch slot (the
        // next monotonically-increasing deadline at `rate_limit_delay`
        // spacing), then releases the lock and `sleep_until`s its assigned
        // slot. With concurrency=N and rate=D, N tasks can be sleeping
        // simultaneously on N distinct deadlines, and execution begins at
        // each task's deadline — so global dispatch rate is 1/D while up
        // to N tasks run their operation concurrently.
        let limiter = if self.rate_limit_delay.is_zero() {
            None
        } else {
            Some(Arc::new(Mutex::new(None::<TokioInstant>)))
        };
        let rate_limit_delay = self.rate_limit_delay;

        let results: Vec<BulkResult> = stream::iter(operations)
            .map(|op| {
                let completed = completed.clone();
                let progress = progress.as_ref();
                let limiter = limiter.clone();
                let whois_client = &self.whois_client;
                let rdap_client = &self.rdap_client;
                let dns_resolver = &self.dns_resolver;
                let propagation_checker = &self.propagation_checker;
                let smart_lookup = &self.smart_lookup;
                let status_client = &self.status_client;
                let availability_checker = &self.availability_checker;
                let ssl_checker = &self.ssl_checker;

                async move {
                    // Rate-limited dispatch: claim our slot quickly under the
                    // lock, then `sleep_until` outside the lock so multiple
                    // tasks can be sleeping in parallel on their own slots.
                    if let Some(limiter) = &limiter {
                        let my_slot = {
                            let mut next = limiter.lock().await;
                            let now = TokioInstant::now();
                            let slot = match *next {
                                Some(prev) if prev > now => prev,
                                _ => now,
                            };
                            *next = Some(slot + rate_limit_delay);
                            slot
                        };
                        sleep_until(my_slot).await;
                    }

                    let start = std::time::Instant::now();
                    let result = execute_operation(
                        &op,
                        &Clients {
                            whois: whois_client,
                            rdap: rdap_client,
                            dns: dns_resolver,
                            propagation: propagation_checker,
                            lookup: smart_lookup,
                            status: status_client,
                            avail: availability_checker,
                            ssl: ssl_checker,
                        },
                    )
                    .await;
                    let duration_ms = start.elapsed().as_millis() as u64;

                    let count = completed.fetch_add(1, Ordering::Relaxed) + 1;

                    if let Some(progress) = progress {
                        let desc = match &op {
                            BulkOperation::Whois { domain }
                            | BulkOperation::Rdap { domain }
                            | BulkOperation::Dns { domain, .. }
                            | BulkOperation::Propagation { domain, .. }
                            | BulkOperation::Lookup { domain }
                            | BulkOperation::Status { domain }
                            | BulkOperation::Avail { domain }
                            | BulkOperation::Info { domain }
                            | BulkOperation::Ssl { domain } => domain.as_str(),
                        };
                        progress(count, total, desc);
                    }

                    match result {
                        Ok(data) => BulkResult {
                            operation: op,
                            success: true,
                            data: Some(data),
                            error: None,
                            duration_ms,
                        },
                        Err(e) => {
                            debug!(error = %e, "Bulk operation failed");
                            BulkResult {
                                operation: op,
                                success: false,
                                data: None,
                                error: Some(e.to_string()),
                                duration_ms,
                            }
                        }
                    }
                }
            })
            .buffer_unordered(self.concurrency)
            .collect()
            .await;

        let succeeded = results.iter().filter(|r| r.success).count();
        let failed = results.iter().filter(|r| !r.success).count();
        info!(
            total = total,
            succeeded = succeeded,
            failed = failed,
            "bulk operation completed"
        );

        results
    }

    pub async fn execute_whois(&self, domains: Vec<String>) -> Vec<BulkResult> {
        let operations = domains
            .into_iter()
            .map(|domain| BulkOperation::Whois { domain })
            .collect();
        self.execute(operations, None).await
    }

    pub async fn execute_rdap(&self, domains: Vec<String>) -> Vec<BulkResult> {
        let operations = domains
            .into_iter()
            .map(|domain| BulkOperation::Rdap { domain })
            .collect();
        self.execute(operations, None).await
    }

    pub async fn execute_dns(
        &self,
        domains: Vec<String>,
        record_type: RecordType,
    ) -> Vec<BulkResult> {
        let operations = domains
            .into_iter()
            .map(|domain| BulkOperation::Dns {
                domain,
                record_type,
            })
            .collect();
        self.execute(operations, None).await
    }

    pub async fn execute_propagation(
        &self,
        domains: Vec<String>,
        record_type: RecordType,
    ) -> Vec<BulkResult> {
        let operations = domains
            .into_iter()
            .map(|domain| BulkOperation::Propagation {
                domain,
                record_type,
            })
            .collect();
        self.execute(operations, None).await
    }

    pub async fn execute_lookup(&self, domains: Vec<String>) -> Vec<BulkResult> {
        let operations = domains
            .into_iter()
            .map(|domain| BulkOperation::Lookup { domain })
            .collect();
        self.execute(operations, None).await
    }

    pub async fn execute_status(&self, domains: Vec<String>) -> Vec<BulkResult> {
        let operations = domains
            .into_iter()
            .map(|domain| BulkOperation::Status { domain })
            .collect();
        self.execute(operations, None).await
    }

    pub async fn execute_avail(&self, domains: Vec<String>) -> Vec<BulkResult> {
        let operations = domains
            .into_iter()
            .map(|domain| BulkOperation::Avail { domain })
            .collect();
        self.execute(operations, None).await
    }

    pub async fn execute_info(&self, domains: Vec<String>) -> Vec<BulkResult> {
        let operations = domains
            .into_iter()
            .map(|domain| BulkOperation::Info { domain })
            .collect();
        self.execute(operations, None).await
    }

    pub async fn execute_ssl(&self, domains: Vec<String>) -> Vec<BulkResult> {
        let operations = domains
            .into_iter()
            .map(|domain| BulkOperation::Ssl { domain })
            .collect();
        self.execute(operations, None).await
    }
}

struct Clients<'a> {
    whois: &'a WhoisClient,
    rdap: &'a RdapClient,
    dns: &'a DnsResolver,
    propagation: &'a PropagationChecker,
    lookup: &'a SmartLookup,
    status: &'a StatusClient,
    avail: &'a AvailabilityChecker,
    ssl: &'a SslChecker,
}

async fn execute_operation(op: &BulkOperation, clients: &Clients<'_>) -> Result<BulkResultData> {
    match op {
        BulkOperation::Whois { domain } => {
            let result = clients.whois.lookup(domain).await?;
            Ok(BulkResultData::Whois(result))
        }
        BulkOperation::Rdap { domain } => {
            let result = clients.rdap.lookup_domain(domain).await?;
            Ok(BulkResultData::Rdap(Box::new(result)))
        }
        BulkOperation::Dns {
            domain,
            record_type,
        } => {
            let result = clients.dns.resolve(domain, *record_type, None).await?;
            Ok(BulkResultData::Dns(result))
        }
        BulkOperation::Propagation {
            domain,
            record_type,
        } => {
            let result = clients.propagation.check(domain, *record_type).await?;
            Ok(BulkResultData::Propagation(result))
        }
        BulkOperation::Lookup { domain } => {
            let result = clients.lookup.lookup(domain).await?;
            Ok(BulkResultData::Lookup(result))
        }
        BulkOperation::Status { domain } => {
            let result = clients.status.check(domain).await?;
            Ok(BulkResultData::Status(result))
        }
        BulkOperation::Avail { domain } => {
            let result = clients.avail.check(domain).await?;
            Ok(BulkResultData::Avail(result))
        }
        BulkOperation::Info { domain } => {
            let result = clients.lookup.lookup(domain).await?;
            Ok(BulkResultData::Info(
                crate::domain_info::DomainInfo::from_lookup_result(&result),
            ))
        }
        BulkOperation::Ssl { domain } => {
            let result = clients.ssl.check(domain).await?;
            Ok(BulkResultData::Ssl(result))
        }
    }
}

/// Keywords commonly used as CSV header labels for a domain column.
const HEADER_KEYWORDS: &[&str] = &["domain", "host", "hostname", "url", "name", "site", "fqdn"];

/// Returns true if `first` looks like a CSV header row rather than a real domain.
///
/// Heuristic: take the first comma-delimited column and trim it. Real domains
/// always contain a `.` (e.g., "example.com", "domain.com"); a bare keyword
/// like "domain" or "hostname" does not. Only treat the row as a header when
/// the first column has no dot AND matches a known header keyword.
fn is_csv_header_row(first: &str) -> bool {
    let first_col = first.split(',').next().unwrap_or(first).trim();
    // Real domains always contain a dot; a bare keyword does not.
    if first_col.contains('.') {
        return false;
    }
    let label = first_col.to_lowercase();
    HEADER_KEYWORDS.contains(&label.as_str())
}

pub fn parse_domains_from_file(content: &str) -> Vec<String> {
    let mut domains: Vec<String> = content
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            // Handle CSV format (take first column)
            line.split(',').next().unwrap_or(line).trim().to_string()
        })
        .filter(|domain| domain.contains('.'))
        .collect();

    // A bare-keyword CSV header like "domain" / "hostname" has no dot and is
    // already dropped by the filter above. `is_csv_header_row` additionally
    // covers the edge case where the first surviving entry is a dotted header
    // (rare, and the current heuristic treats such values as real domains —
    // see `domain_dot_com_is_not_dropped_as_header`). The guard below is a
    // belt-and-suspenders check that stays correct if the upstream filter
    // ever changes.
    if domains
        .first()
        .map(|d| is_csv_header_row(d))
        .unwrap_or(false)
    {
        domains.remove(0);
    }

    domains
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_domains_from_file() {
        let content = r#"
# This is a comment
example1.com
google2.com
  whitespace3.com
invalid
csv,format,example.org
"#;

        let domains = parse_domains_from_file(content);
        assert_eq!(domains.len(), 3);
        assert!(domains.contains(&"example1.com".to_string()));
        assert!(domains.contains(&"google2.com".to_string()));
        assert!(domains.contains(&"whitespace3.com".to_string()));
        // "invalid" and "csv" are filtered out because they don't contain a dot
    }

    #[test]
    fn test_parse_domains_skip_bare_header() {
        // Bare-keyword header ("domain") is dropped by the dot filter.
        let content = "domain\nexample.com\n";
        let domains = parse_domains_from_file(content);
        assert_eq!(domains, vec!["example.com"]);
    }

    #[test]
    fn test_parse_domains_multi_column_csv_header_dropped() {
        // First column is a bare keyword → whole header row has no dot in col 1
        // and is dropped by the dot filter.
        let content = "domain,status\ngoogle.com,live\n";
        let domains = parse_domains_from_file(content);
        assert_eq!(domains, vec!["google.com"]);
        assert!(!domains.contains(&"domain".to_string()));
    }

    #[test]
    fn first_domain_with_no_digits_is_kept() {
        // Regression: previous heuristic dropped the first entry when it
        // had no ASCII digits, losing "google.com" / "amazon.com" / ...
        let input = "google.com\namazon.com\n";
        let result = parse_domains_from_file(input);
        assert_eq!(result, vec!["google.com", "amazon.com"]);
    }

    #[test]
    fn header_row_named_hostname_is_dropped() {
        let input = "hostname\nexample.com\n";
        let result = parse_domains_from_file(input);
        assert_eq!(result, vec!["example.com"]);
    }

    #[test]
    fn domain_dot_com_is_not_dropped_as_header() {
        // "domain.com" is a real domain, not a header, because it has a dot.
        let input = "domain.com\nexample.com\n";
        let result = parse_domains_from_file(input);
        assert_eq!(result, vec!["domain.com", "example.com"]);
    }

    #[test]
    fn is_csv_header_row_detects_bare_keywords() {
        assert!(is_csv_header_row("domain"));
        assert!(is_csv_header_row("Hostname"));
        assert!(is_csv_header_row("URL"));
        assert!(is_csv_header_row("domain,status,notes"));
        assert!(is_csv_header_row("  host  "));
    }

    #[test]
    fn is_csv_header_row_rejects_dotted_values() {
        assert!(!is_csv_header_row("domain.com"));
        assert!(!is_csv_header_row("google.com"));
        assert!(!is_csv_header_row("host.name"));
    }

    #[test]
    fn is_csv_header_row_rejects_non_keyword() {
        assert!(!is_csv_header_row("example"));
        assert!(!is_csv_header_row("mydata"));
    }

    /// Regression test for the v0.26.7 rate-limiter regression. The
    /// previous implementation held a `tokio::sync::Mutex` guard across
    /// `Interval::tick().await`, fully serializing dispatch through the
    /// lock. We need a behavioural assertion (not just code review) that
    /// catches that pattern if it ever returns.
    ///
    /// With concurrency 5, rate_limit 50ms, and 4 hermetic-failure tasks:
    /// - Dispatch should be spaced ~50ms apart (slot-claim semantics).
    /// - All 4 tasks should *finish* in well under 4 * (per-op cost),
    ///   i.e. they overlap on the execution side.
    /// - Total wall time should be approximately the longest single op
    ///   plus the cumulative slot delays (~150ms).
    ///
    /// The previous (broken) implementation would have produced wall
    /// time = sum-of-per-op-cost because dispatch was serialized.
    #[tokio::test]
    async fn rate_limiter_dispatches_in_parallel_not_serialized() {
        use std::time::Instant;
        let executor = BulkExecutor::new()
            .with_concurrency(5)
            .with_rate_limit(Duration::from_millis(50));

        // Use unresolvable `.invalid` hosts — they fail fast at DNS, well
        // under the limiter's slot spacing. If dispatch IS rate-limited
        // in parallel, all 4 finish in close to 3 * 50ms = 150ms (plus
        // per-op DNS-fail cost, typically tens of ms). If dispatch was
        // serialized through a lock, each task waits for the previous
        // to FINISH before starting — total would be much higher.
        let start = Instant::now();
        let domains = vec![
            "seer-rl-1.invalid".to_string(),
            "seer-rl-2.invalid".to_string(),
            "seer-rl-3.invalid".to_string(),
            "seer-rl-4.invalid".to_string(),
        ];
        let results = executor.execute_ssl(domains).await;
        let elapsed = start.elapsed();

        assert_eq!(results.len(), 4);
        // Generous upper bound — 2s is far above the worst legitimate
        // wall time (4*50ms slots + 4*100ms DNS-fail = ~600ms) but well
        // below the serialised path (would be 4 * per-op-cost minimum).
        assert!(
            elapsed < Duration::from_secs(2),
            "rate-limited dispatch should run in parallel; took {:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn execute_ssl_failure_path_for_unresolvable_host() {
        // Verifies the SSL bulk arm wires correctly: an unresolvable hostname
        // must surface as success=false with a non-empty error string. Uses
        // the IETF-reserved `.invalid` TLD so this is hermetic.
        let executor = BulkExecutor::new().with_rate_limit(Duration::ZERO);
        let results = executor
            .execute_ssl(vec!["seer-bulk-ssl-test.invalid".to_string()])
            .await;
        assert_eq!(results.len(), 1);
        let r = &results[0];
        assert!(!r.success, "expected failure, got success");
        assert!(r.data.is_none(), "expected no data on failure");
        let err = r.error.as_deref().unwrap_or("");
        assert!(!err.is_empty(), "expected non-empty error, got: {:?}", err);
        assert!(
            matches!(r.operation, BulkOperation::Ssl { ref domain } if domain == "seer-bulk-ssl-test.invalid"),
            "expected Ssl variant, got {:?}",
            r.operation
        );
    }

    #[tokio::test]
    #[ignore = "live network: hits cloudflare.com:443; run with --ignored"]
    async fn execute_ssl_live_cloudflare_has_non_empty_chain() {
        let executor = BulkExecutor::new();
        let results = executor
            .execute_ssl(vec!["cloudflare.com".to_string()])
            .await;
        assert_eq!(results.len(), 1);
        let r = &results[0];
        assert!(r.success, "expected success, got error: {:?}", r.error);
        let Some(BulkResultData::Ssl(ref report)) = r.data else {
            panic!("expected Ssl data, got {:?}", r.data);
        };
        assert!(!report.chain.is_empty(), "chain must not be empty");
        assert!(report.is_valid, "cloudflare leaf cert should be valid");
        assert!(
            report.days_until_expiry > 0,
            "cert should still be valid in the future, got {} days",
            report.days_until_expiry
        );
        assert!(
            !report.san_names.is_empty(),
            "cloudflare cert should have SAN entries"
        );
    }
}
