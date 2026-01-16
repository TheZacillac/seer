use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tokio::time::sleep;
use tracing::{debug, warn};

use crate::dns::{DnsRecord, DnsResolver, PropagationChecker, PropagationResult, RecordType};
use crate::error::Result;
use crate::lookup::{LookupResult, SmartLookup};
use crate::rdap::{RdapClient, RdapResponse};
use crate::status::{StatusClient, StatusResponse};
use crate::whois::{WhoisClient, WhoisResponse};

pub type ProgressCallback = Box<dyn Fn(usize, usize, &str) + Send + Sync>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BulkOperation {
    Whois { domain: String },
    Rdap { domain: String },
    Dns { domain: String, record_type: RecordType },
    Propagation { domain: String, record_type: RecordType },
    Lookup { domain: String },
    Status { domain: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BulkResultData {
    Whois(WhoisResponse),
    Rdap(Box<RdapResponse>),
    Dns(Vec<DnsRecord>),
    Propagation(PropagationResult),
    Lookup(LookupResult),
    Status(StatusResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkResult {
    pub operation: BulkOperation,
    pub success: bool,
    pub data: Option<BulkResultData>,
    pub error: Option<String>,
    pub duration_ms: u64,
}

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
        }
    }

    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency.max(1);
        self
    }

    pub fn with_rate_limit(mut self, delay: Duration) -> Self {
        self.rate_limit_delay = delay;
        self
    }

    pub async fn execute(
        &self,
        operations: Vec<BulkOperation>,
        progress: Option<ProgressCallback>,
    ) -> Vec<BulkResult> {
        let total = operations.len();
        let completed = Arc::new(AtomicUsize::new(0));
        let semaphore = Arc::new(Semaphore::new(self.concurrency));

        debug!(
            total = total,
            concurrency = self.concurrency,
            "Starting bulk execution"
        );

        let results: Vec<BulkResult> = stream::iter(operations)
            .map(|op| {
                let semaphore = semaphore.clone();
                let completed = completed.clone();
                let progress = progress.as_ref();
                let rate_limit_delay = self.rate_limit_delay;
                let whois_client = &self.whois_client;
                let rdap_client = &self.rdap_client;
                let dns_resolver = &self.dns_resolver;
                let propagation_checker = &self.propagation_checker;
                let smart_lookup = &self.smart_lookup;
                let status_client = &self.status_client;

                async move {
                    let _permit = match semaphore.acquire().await {
                        Ok(permit) => permit,
                        Err(_) => {
                            return BulkResult {
                                operation: op,
                                success: false,
                                data: None,
                                error: Some("Operation cancelled".to_string()),
                                duration_ms: 0,
                            };
                        }
                    };

                    // Rate limiting delay
                    if !rate_limit_delay.is_zero() {
                        sleep(rate_limit_delay).await;
                    }

                    let start = std::time::Instant::now();
                    let result = execute_operation(
                        &op,
                        whois_client,
                        rdap_client,
                        dns_resolver,
                        propagation_checker,
                        smart_lookup,
                        status_client,
                    )
                    .await;
                    let duration_ms = start.elapsed().as_millis() as u64;

                    let count = completed.fetch_add(1, Ordering::Relaxed) + 1;

                    if let Some(progress) = progress {
                        let desc = match &op {
                            BulkOperation::Whois { domain } => domain.clone(),
                            BulkOperation::Rdap { domain } => domain.clone(),
                            BulkOperation::Dns { domain, .. } => domain.clone(),
                            BulkOperation::Propagation { domain, .. } => domain.clone(),
                            BulkOperation::Lookup { domain } => domain.clone(),
                            BulkOperation::Status { domain } => domain.clone(),
                        };
                        progress(count, total, &desc);
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
                            warn!(error = %e, "Bulk operation failed");
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
}

async fn execute_operation(
    op: &BulkOperation,
    whois_client: &WhoisClient,
    rdap_client: &RdapClient,
    dns_resolver: &DnsResolver,
    propagation_checker: &PropagationChecker,
    smart_lookup: &SmartLookup,
    status_client: &StatusClient,
) -> Result<BulkResultData> {
    match op {
        BulkOperation::Whois { domain } => {
            let result = whois_client.lookup(domain).await?;
            Ok(BulkResultData::Whois(result))
        }
        BulkOperation::Rdap { domain } => {
            let result = rdap_client.lookup_domain(domain).await?;
            Ok(BulkResultData::Rdap(Box::new(result)))
        }
        BulkOperation::Dns {
            domain,
            record_type,
        } => {
            let result = dns_resolver.resolve(domain, *record_type, None).await?;
            Ok(BulkResultData::Dns(result))
        }
        BulkOperation::Propagation {
            domain,
            record_type,
        } => {
            let result = propagation_checker.check(domain, *record_type).await?;
            Ok(BulkResultData::Propagation(result))
        }
        BulkOperation::Lookup { domain } => {
            let result = smart_lookup.lookup(domain).await?;
            Ok(BulkResultData::Lookup(result))
        }
        BulkOperation::Status { domain } => {
            let result = status_client.check(domain).await?;
            Ok(BulkResultData::Status(result))
        }
    }
}

pub fn parse_domains_from_file(content: &str) -> Vec<String> {
    content
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            // Handle CSV format (take first column)
            line.split(',').next().unwrap_or(line).trim().to_string()
        })
        .filter(|domain| domain.contains('.'))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_domains_from_file() {
        let content = r#"
# This is a comment
example.com
google.com
  whitespace.com
invalid
csv,format,example.org
"#;

        let domains = parse_domains_from_file(content);
        assert_eq!(domains.len(), 3);
        assert!(domains.contains(&"example.com".to_string()));
        assert!(domains.contains(&"google.com".to_string()));
        assert!(domains.contains(&"whitespace.com".to_string()));
        // "invalid" and "csv" are filtered out because they don't contain a dot
    }
}
