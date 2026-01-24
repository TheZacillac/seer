# Bulk Module

Concurrent bulk operation executor with rate limiting.

## Overview

This module provides efficient bulk operations for processing multiple domains:
- Semaphore-based concurrency control
- Configurable rate limiting
- Progress callbacks for UI updates
- Unified interface for all operation types

## Files

| File | Description |
|------|-------------|
| `mod.rs` | Module exports and public interface |
| `executor.rs` | Bulk executor with concurrency control |

## Public API

### Types

```rust
pub use executor::{
    parse_domains_from_file,
    BulkExecutor,
    BulkOperation,
    BulkResult,
    BulkResultData,
    ProgressCallback,
};
```

### BulkExecutor

Main executor for bulk operations.

```rust
impl BulkExecutor {
    /// Create a new executor with default settings
    pub fn new() -> Self;

    /// Set maximum concurrent operations (default: 10, max: 50)
    pub fn with_concurrency(self, concurrency: usize) -> Self;

    /// Set delay between operations for rate limiting (default: 100ms)
    pub fn with_rate_limit(self, delay: Duration) -> Self;

    /// Execute a list of operations with optional progress callback
    pub async fn execute(
        &self,
        operations: Vec<BulkOperation>,
        progress: Option<ProgressCallback>,
    ) -> Vec<BulkResult>;

    // Convenience methods for specific operation types
    pub async fn execute_lookup(&self, domains: Vec<String>) -> Vec<BulkResult>;
    pub async fn execute_whois(&self, domains: Vec<String>) -> Vec<BulkResult>;
    pub async fn execute_rdap(&self, domains: Vec<String>) -> Vec<BulkResult>;
    pub async fn execute_dns(&self, domains: Vec<String>, record_type: RecordType) -> Vec<BulkResult>;
    pub async fn execute_propagation(&self, domains: Vec<String>, record_type: RecordType) -> Vec<BulkResult>;
    pub async fn execute_status(&self, domains: Vec<String>) -> Vec<BulkResult>;
}
```

### BulkOperation

Operation type enum.

```rust
pub enum BulkOperation {
    Whois { domain: String },
    Rdap { domain: String },
    Dns { domain: String, record_type: RecordType },
    Propagation { domain: String, record_type: RecordType },
    Lookup { domain: String },
    Status { domain: String },
}
```

### BulkResult

Result of a single operation.

```rust
pub struct BulkResult {
    pub operation: BulkOperation,
    pub success: bool,
    pub data: Option<BulkResultData>,
    pub error: Option<String>,
    pub duration_ms: u64,
}
```

### BulkResultData

Data from successful operations.

```rust
pub enum BulkResultData {
    Whois(WhoisResponse),
    Rdap(Box<RdapResponse>),
    Dns(Vec<DnsRecord>),
    Propagation(PropagationResult),
    Lookup(LookupResult),
    Status(StatusResponse),
}
```

### ProgressCallback

Callback for progress updates.

```rust
pub type ProgressCallback = Box<dyn Fn(usize, usize, &str) + Send + Sync>;
// Called with: (completed_count, total_count, current_domain)
```

### Utility Functions

```rust
/// Parse domains from file content (text or CSV)
pub fn parse_domains_from_file(content: &str) -> Vec<String>;
```

## Usage Examples

### Basic Bulk Lookup

```rust
use seer_core::BulkExecutor;

let executor = BulkExecutor::new();
let domains = vec![
    "example.com".to_string(),
    "google.com".to_string(),
    "github.com".to_string(),
];

let results = executor.execute_lookup(domains).await;

for result in results {
    if result.success {
        println!("{}: OK ({} ms)", result.operation, result.duration_ms);
    } else {
        println!("{}: FAILED - {:?}", result.operation, result.error);
    }
}
```

### With Progress Callback

```rust
let executor = BulkExecutor::new();

let progress: ProgressCallback = Box::new(|completed, total, domain| {
    println!("[{}/{}] Processing: {}", completed, total, domain);
});

let operations: Vec<BulkOperation> = domains
    .iter()
    .map(|d| BulkOperation::Lookup { domain: d.clone() })
    .collect();

let results = executor.execute(operations, Some(progress)).await;
```

### Custom Concurrency

```rust
let executor = BulkExecutor::new()
    .with_concurrency(20)  // Up to 20 concurrent operations
    .with_rate_limit(Duration::from_millis(50));  // 50ms between starts
```

### Bulk DNS Resolution

```rust
use seer_core::{BulkExecutor, RecordType};

let executor = BulkExecutor::new();
let results = executor.execute_dns(domains, RecordType::MX).await;
```

### Parse Domains from File

```rust
use seer_core::bulk::parse_domains_from_file;

let content = std::fs::read_to_string("domains.txt")?;
let domains = parse_domains_from_file(&content);

// Supports:
// - Plain text (one domain per line)
// - Comments (lines starting with #)
// - CSV (uses first column)
// - Filters invalid entries (must contain '.')
```

## File Format Support

The `parse_domains_from_file` function supports:

```
# Plain text format
example.com
google.com
github.com

# Comments are ignored
# invalid-no-dot entries are filtered

# CSV format (uses first column)
domain,owner,notes
example.com,Alice,Main site
google.com,Bob,Search
```

## Concurrency Control

The executor uses a semaphore-based approach:

1. Semaphore with `concurrency` permits
2. Each operation acquires a permit before executing
3. Rate limit delay applied after acquiring permit
4. Permit released when operation completes

This ensures:
- Maximum `concurrency` operations run simultaneously
- Minimum `rate_limit` delay between operation starts
- Operations don't block each other on completion

## Constants

| Setting | Default | Description |
|---------|---------|-------------|
| Concurrency | 10 | Maximum concurrent operations |
| Rate limit | 100ms | Delay between operation starts |

## Error Handling

- Individual operation failures don't stop the batch
- Each result contains `success` flag and optional `error`
- Progress continues even when operations fail
- Summary can be calculated from results:

```rust
let success_count = results.iter().filter(|r| r.success).count();
let fail_count = results.len() - success_count;
```
