# CLAUDE.md - AI Assistant Guide for Seer

This document provides comprehensive guidance for AI assistants working on the Seer codebase. It covers architecture, conventions, workflows, and best practices.

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Codebase Structure](#codebase-structure)
4. [Development Workflows](#development-workflows)
5. [Code Conventions](#code-conventions)
6. [Testing Strategy](#testing-strategy)
7. [Common Tasks](#common-tasks)
8. [Key Patterns](#key-patterns)
9. [Things to Avoid](#things-to-avoid)
10. [Troubleshooting](#troubleshooting)

---

## Project Overview

**Seer** is a multi-interface domain name utility tool written in Rust with Python bindings. It provides WHOIS, RDAP, DNS, and domain status checking functionality through multiple interfaces:

- **CLI** (seer-cli): Command-line tool with interactive REPL
- **Python Library** (seer-py): PyO3-based Python bindings
- **REST API** (seer-api): FastAPI-based web service
- **MCP Server** (seer-api): Model Context Protocol server for AI assistants

### Technology Stack

**Rust Core:**
- Tokio (async runtime)
- Reqwest (HTTP client)
- Hickory-resolver (DNS resolution)
- Serde (serialization)
- Thiserror (error handling)

**CLI:**
- Clap (command parsing)
- Rustyline (REPL)
- Indicatif (progress indicators)
- Colored (terminal colors)

**Python:**
- PyO3 (Rust/Python bindings)
- FastAPI (REST API)
- Pydantic (validation)
- MCP (Model Context Protocol)

---

## Architecture

### Workspace Organization

Seer uses a Cargo workspace with 3 Rust crates and 1 Python package:

```
seer/
├── Cargo.toml              # Workspace root with shared dependencies
├── seer-core/              # Core Rust library (all business logic)
├── seer-cli/               # CLI application (commands + REPL)
├── seer-py/                # Python bindings (PyO3 wrapper)
└── seer-api/               # FastAPI REST + MCP server (Python)
```

### Dependency Flow

```
seer-cli ──┐
           ├──> seer-core (Rust core library)
seer-py ───┘

seer-api (Python) ──> seer-py (Python package) ──> seer-core (Rust)
```

**Key Principle:** All business logic lives in `seer-core`. Other crates/packages are thin presentation layers.

---

## Codebase Structure

### seer-core/ (Core Library)

All business logic and domain operations live here:

```
seer-core/src/
├── lib.rs              # Module exports and re-exports
├── error.rs            # Centralized error types (SeerError enum)
├── colors.rs           # Catppuccin color palette for terminal output
├── lookup.rs           # Smart lookup (RDAP-first with WHOIS fallback)
│
├── whois/              # WHOIS functionality
│   ├── mod.rs          # Public interface
│   ├── client.rs       # TCP WHOIS client with referral following
│   ├── parser.rs       # Regex-based response parser
│   └── servers.rs      # TLD-to-WHOIS-server mapping
│
├── rdap/               # RDAP functionality
│   ├── mod.rs          # Public interface
│   ├── client.rs       # HTTP RDAP client with IANA bootstrap
│   └── types.rs        # RDAP response structures
│
├── dns/                # DNS functionality
│   ├── mod.rs          # Public interface
│   ├── resolver.rs     # DNS resolver (hickory-resolver)
│   ├── records.rs      # Record type definitions
│   └── propagation.rs  # Global DNS propagation checker
│
├── status/             # Domain health checking
│   ├── mod.rs          # Public interface
│   ├── client.rs       # HTTP/SSL/expiration checker
│   └── types.rs        # Status response structures
│
├── bulk/               # Bulk operations
│   ├── mod.rs          # Public interface
│   └── executor.rs     # Concurrent operation executor with rate limiting
│
└── output/             # Output formatting
    ├── mod.rs          # OutputFormat enum
    ├── human.rs        # Human-readable formatter (colored)
    └── json.rs         # JSON formatter
```

#### Module Responsibilities

- **error.rs**: All error types in one place, uses thiserror
- **whois/**: WHOIS protocol, parsing, referral following (max depth: 3)
- **rdap/**: RDAP protocol, IANA bootstrap caching, domain/IP/ASN lookups
- **dns/**: DNS resolution (all record types), propagation checking (29 servers)
- **status/**: HTTP status, SSL certificates, domain expiration checking
- **lookup.rs**: Smart lookup orchestration (RDAP → WHOIS fallback)
- **bulk/**: Semaphore-based concurrent execution, file parsing
- **output/**: Human (colored) and JSON formatters
- **colors.rs**: Catppuccin Frappe color palette

### seer-cli/ (CLI Application)

```
seer-cli/src/
├── main.rs             # Entry point, clap commands, subcommand dispatch
├── repl/               # Interactive REPL
│   ├── mod.rs          # REPL main loop, session state
│   ├── commands.rs     # Command parsing and context
│   └── completer.rs    # Tab completion
└── display/            # UI utilities
    └── spinner.rs      # Loading spinner for async operations
```

**Key Points:**
- Uses Clap v4 with derive macros
- Defaults to REPL when no command provided
- Supports `--format` flag (human/json)
- REPL history saved to `~/.seer_history`

### seer-py/ (Python Bindings)

```
seer-py/
├── Cargo.toml          # Library config with crate-type = ["cdylib"]
├── pyproject.toml      # Maturin build config, ABI3 (Python 3.9+)
├── src/lib.rs          # PyO3 bindings, async→sync conversion
└── python/seer/        # Python wrapper package
    └── __init__.py     # Re-exports and convenience functions
```

**Key Points:**
- Single Tokio runtime via `OnceLock` (thread-safe singleton)
- All async Rust functions exposed synchronously to Python
- Custom `json_to_python()` converter for serde_json → PyObject
- Errors converted to PyRuntimeError/PyValueError

### seer-api/ (FastAPI + MCP)

```
seer-api/
├── pyproject.toml          # Entry points: seer-api, seer-mcp
└── seer_api/
    ├── main.py             # FastAPI app, CORS config
    ├── routers/            # API endpoints by feature
    │   ├── lookup.py       # Smart lookup (single + bulk)
    │   ├── whois.py        # WHOIS lookups
    │   ├── rdap.py         # RDAP lookups
    │   ├── dns.py          # DNS queries
    │   ├── propagation.py  # DNS propagation
    │   └── status.py       # Domain status
    └── mcp/
        └── server.py       # MCP server (13 tools, stdio transport)
```

**Key Points:**
- CORS configured via `SEER_CORS_ORIGINS` env var
- OpenAPI docs at `/docs` and `/redoc`
- Bulk endpoints have limits (max 100 domains, max 50 concurrency)
- MCP server exposes all operations as tools for AI assistants

---

## Development Workflows

### Setting Up Development Environment

```bash
# 1. Clone repository
git clone https://github.com/TheZacillac/seer.git
cd seer

# 2. Install CLI to PATH (installs to ~/.cargo/bin/)
cargo install --path seer-cli

# 3. Build Python bindings
cd seer-py
maturin develop --release
cd ..

# 4. Install API package
cd seer-api
pip install -e .
cd ..
```

### Building

```bash
# Build all Rust packages (CLI + core + Python bindings)
cargo build --release

# Build only CLI
cargo build --release -p seer-cli

# Build only core library
cargo build --release -p seer-core

# Build Python bindings (development mode)
cd seer-py && maturin develop --release

# Build Python wheel
cd seer-py && maturin build --release
```

### Running Tests

```bash
# Run all Rust tests
cargo test

# Run tests for specific package
cargo test -p seer-core
cargo test -p seer-cli

# Run Python tests
cd seer-api && pytest

# Run with logging
RUST_LOG=debug cargo test
```

### Running the Applications

```bash
# CLI in command mode
./target/release/seer lookup example.com
./target/release/seer whois example.com
./target/release/seer dig example.com MX

# CLI in REPL mode
./target/release/seer

# REST API server
seer-api  # Runs on http://localhost:8000

# MCP server
seer-mcp  # Runs on stdio
```

---

## Code Conventions

### Naming Conventions

**Rust:**
- **Structs/Enums:** PascalCase (`WhoisClient`, `RecordType`, `SeerError`)
- **Functions/Methods:** snake_case (`lookup`, `parse_domain`, `rdap_lookup`)
- **Constants:** SCREAMING_SNAKE_CASE (`DEFAULT_TIMEOUT`, `MAX_RESPONSE_SIZE`)
- **Modules:** snake_case (`whois`, `dns`, `rdap`)

**Python:**
- Follow PEP 8
- Functions: snake_case (`lookup`, `bulk_lookup`)
- Classes: PascalCase (`BulkLookupRequest`)

### Module Organization Pattern

Each module follows this structure:

```
module_name/
├── mod.rs          # Public interface, re-exports
├── client.rs       # Network client implementation
├── types.rs        # Data structures
└── parser.rs       # Parsing logic (if needed)
```

**Example:**
```rust
// whois/mod.rs
mod client;
mod parser;
mod servers;

pub use client::WhoisClient;
pub use parser::WhoisResponse;
```

### Error Handling

**Always use the `SeerError` type:**

```rust
use crate::error::{Result, SeerError};

pub async fn lookup(domain: &str) -> Result<Response> {
    // Use ? operator for error propagation
    let data = fetch_data(domain).await?;

    // Convert errors with context
    parse_data(&data)
        .map_err(|e| SeerError::ParseError(format!("Failed to parse {}: {}", domain, e)))
}
```

**Error conversion patterns:**
```rust
// Use #[from] for automatic conversion
#[error("IO error: {0}")]
IoError(#[from] std::io::Error),

// Add context to errors
SeerError::WhoisError(format!("Failed to connect to {}: {}", server, e))

// Timeout handling
timeout(duration, operation)
    .await
    .map_err(|_| SeerError::Timeout("Operation timed out".to_string()))?
```

### Async Patterns

**Concurrent independent operations:**
```rust
use tokio::join;

let (http_result, ssl_result, expiry_result) = join!(
    check_http_status(domain),
    check_ssl_certificate(domain),
    check_domain_expiration(domain)
);
```

**Sequential dependent operations:**
```rust
// Don't do this
let (result1, result2) = join!(op1(), op2_that_needs_result1());  // ❌ Wrong

// Do this instead
let result1 = op1().await?;
let result2 = op2_that_needs(result1).await?;  // ✅ Correct
```

**Bulk concurrent operations:**
```rust
use futures::stream::{self, StreamExt};

let results: Vec<_> = stream::iter(domains)
    .map(|domain| async move {
        // Acquire semaphore permit for rate limiting
        let _permit = semaphore.acquire().await.unwrap();
        lookup(domain).await
    })
    .buffer_unordered(concurrency)
    .collect()
    .await;
```

### Serialization

**Use serde conventions:**

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]  // For RDAP (follows standard)
pub struct RdapResponse {
    pub handle: Option<String>,
    #[serde(flatten)]  // For extensibility
    pub extra: HashMap<String, Value>,
}
```

### Documentation

**Always document public APIs:**

```rust
/// Performs a smart lookup on a domain, trying RDAP first and falling back to WHOIS.
///
/// # Arguments
/// * `domain` - The domain name to look up (e.g., "example.com")
///
/// # Returns
/// * `Ok(LookupResult)` - Successful lookup result (RDAP or WHOIS)
/// * `Err(SeerError)` - If both RDAP and WHOIS fail
///
/// # Example
/// ```
/// let result = smart_lookup("example.com").await?;
/// ```
pub async fn smart_lookup(domain: &str) -> Result<LookupResult> {
    // Implementation
}
```

---

## Testing Strategy

### Unit Tests

Place unit tests in the same file as implementation:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_domain() {
        assert_eq!(normalize_domain("https://www.example.com"), "example.com");
        assert_eq!(normalize_domain("WWW.EXAMPLE.COM"), "example.com");
    }

    #[tokio::test]
    async fn test_whois_lookup() {
        let client = WhoisClient::new();
        let result = client.lookup("example.com").await;
        assert!(result.is_ok());
    }
}
```

### Integration Tests

For integration tests, use examples in documentation or separate test files:

```rust
// tests/integration_test.rs
use seer_core::*;

#[tokio::test]
async fn test_full_lookup_flow() {
    let result = lookup("example.com").await.unwrap();
    assert!(!result.is_empty());
}
```

### Testing Commands

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_normalize_domain

# Run tests with output
cargo test -- --nocapture

# Run tests with debug logging
RUST_LOG=debug cargo test
```

---

## Common Tasks

### Adding a New DNS Record Type

1. **Update `dns/records.rs`:**

```rust
pub enum RecordType {
    A,
    AAAA,
    MX,
    NewType,  // Add here
}

impl FromStr for RecordType {
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "A" => Ok(RecordType::A),
            // ...
            "NEWTYPE" => Ok(RecordType::NewType),  // Add here
        }
    }
}
```

2. **Update resolver in `dns/resolver.rs`:**

```rust
pub async fn resolve(&self, domain: &str, record_type: RecordType) -> Result<Vec<DnsRecord>> {
    match record_type {
        RecordType::A => /* ... */,
        // ...
        RecordType::NewType => {
            let records = self.resolver.newtype_lookup(domain).await?;
            // Parse and return
        }
    }
}
```

3. **Update CLI help text in `seer-cli/src/main.rs`**

4. **Add tests**

### Adding a New Output Formatter

1. **Create `output/newformat.rs`:**

```rust
use crate::error::Result;

pub struct NewFormatFormatter;

impl NewFormatFormatter {
    pub fn format_whois(response: &WhoisResponse) -> Result<String> {
        // Implementation
    }

    pub fn format_rdap(response: &RdapResponse) -> Result<String> {
        // Implementation
    }
}
```

2. **Update `output/mod.rs`:**

```rust
pub enum OutputFormat {
    Human,
    Json,
    NewFormat,  // Add here
}

pub fn format(data: &impl Serialize, format: OutputFormat) -> Result<String> {
    match format {
        OutputFormat::Human => human::format(data),
        OutputFormat::Json => json::format(data),
        OutputFormat::NewFormat => newformat::format(data),  // Add here
    }
}
```

3. **Update CLI `--format` argument in `seer-cli/src/main.rs`**

### Adding a New API Endpoint

1. **Create router in `seer-api/seer_api/routers/newfeature.py`:**

```python
from fastapi import APIRouter, HTTPException
import seer

router = APIRouter(prefix="/newfeature", tags=["newfeature"])

@router.get("/{domain}")
async def newfeature(domain: str):
    try:
        result = seer.newfeature(domain)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
```

2. **Register router in `seer-api/seer_api/main.py`:**

```python
from .routers import newfeature

app.include_router(newfeature.router)
```

3. **Update MCP server in `seer-api/seer_api/mcp/server.py`** (if needed for AI assistants)

### Updating Dependencies

```bash
# Update all dependencies in Cargo.lock
cargo update

# Update specific dependency
cargo update -p reqwest

# Update Python dependencies
cd seer-api && pip install -U -e .
```

### Adding Configuration Options

**For Rust (seer-core):**

```rust
// Use builder pattern
pub struct ClientBuilder {
    timeout: Duration,
    max_retries: usize,
}

impl ClientBuilder {
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn build(self) -> Client {
        Client { timeout: self.timeout, /* ... */ }
    }
}
```

**For Python API (seer-api):**

Use environment variables:

```python
import os

CORS_ORIGINS = os.getenv("SEER_CORS_ORIGINS", "*").split(",")
```

---

## Key Patterns

### 1. Domain Normalization

**Always normalize domains before processing:**

```rust
fn normalize_domain(domain: &str) -> String {
    domain
        .trim()
        .to_lowercase()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_start_matches("www.")
        .to_string()
}
```

Apply this in all public-facing functions that accept domain input.

### 2. Timeout Protection

**All network operations must have timeouts:**

```rust
use tokio::time::{timeout, Duration};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

async fn network_operation() -> Result<String> {
    timeout(DEFAULT_TIMEOUT, async {
        // Network call here
    })
    .await
    .map_err(|_| SeerError::Timeout("Operation timed out".to_string()))?
}
```

**Current timeout values:**
- WHOIS: 10 seconds
- RDAP: 30 seconds
- DNS: 5 seconds (with 2 retries)
- HTTP/SSL checks: 10 seconds

### 3. Lazy Initialization with Caching

**Pattern for expensive initialization:**

```rust
use std::sync::RwLock;
use once_cell::sync::Lazy;

static CACHE: Lazy<RwLock<HashMap<String, Data>>> = Lazy::new(|| {
    RwLock::new(HashMap::new())
});

async fn get_or_load(key: &str) -> Result<Data> {
    // Try read lock first
    {
        let cache = CACHE.read().unwrap();
        if let Some(data) = cache.get(key) {
            return Ok(data.clone());
        }
    }

    // Load data
    let data = expensive_load(key).await?;

    // Store with write lock
    {
        let mut cache = CACHE.write().unwrap();
        cache.insert(key.to_string(), data.clone());
    }

    Ok(data)
}
```

**Used in:** RDAP bootstrap data caching

### 4. Referral Following (WHOIS)

**Pattern for following referrals with cycle detection:**

```rust
const MAX_REFERRAL_DEPTH: usize = 3;

async fn follow_referrals(&self, domain: &str) -> Result<String> {
    let mut visited = HashSet::new();
    let mut current_server = self.find_server(domain)?;
    let mut depth = 0;

    loop {
        if depth >= MAX_REFERRAL_DEPTH {
            return Err(SeerError::WhoisError("Max referral depth exceeded".into()));
        }

        if !visited.insert(current_server.clone()) {
            return Err(SeerError::WhoisError("Circular referral detected".into()));
        }

        let response = self.query(&current_server, domain).await?;

        if let Some(referral) = extract_referral(&response) {
            current_server = referral;
            depth += 1;
        } else {
            return Ok(response);
        }
    }
}
```

### 5. Fallback Chains

**Pattern for graceful degradation:**

```rust
pub async fn smart_lookup(&self, domain: &str) -> Result<LookupResult> {
    // Try primary method
    match self.rdap_client.lookup(domain).await {
        Ok(data) if is_useful(&data) => Ok(LookupResult::Rdap(data)),
        Ok(_) | Err(_) => {
            // Fall back to secondary method
            let whois_data = self.whois_client.lookup(domain).await?;
            Ok(LookupResult::Whois(whois_data))
        }
    }
}
```

**Used in:** Smart lookup (RDAP → WHOIS)

### 6. Bulk Operation Pattern

**Pattern for concurrent bulk operations:**

```rust
use tokio::sync::Semaphore;
use futures::stream::{self, StreamExt};

pub async fn bulk_operation<T, F>(
    items: Vec<T>,
    concurrency: usize,
    operation: F,
) -> Vec<Result<Output>>
where
    F: Fn(T) -> Future<Output = Result<Output>>,
{
    let semaphore = Arc::new(Semaphore::new(concurrency));

    stream::iter(items)
        .map(|item| {
            let sem = semaphore.clone();
            let op = operation.clone();
            async move {
                let _permit = sem.acquire().await.unwrap();
                op(item).await
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await
}
```

**Features:**
- Semaphore-based rate limiting
- Configurable concurrency (default: 10, max: 50)
- Error collection without stopping execution
- Duration tracking per operation

### 7. Builder Pattern for Configuration

**Pattern for flexible configuration:**

```rust
pub struct ClientBuilder {
    timeout: Duration,
    max_retries: usize,
}

impl ClientBuilder {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            max_retries: 3,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_max_retries(mut self, retries: usize) -> Self {
        self.max_retries = retries;
        self
    }

    pub fn build(self) -> Client {
        Client {
            timeout: self.timeout,
            max_retries: self.max_retries,
        }
    }
}

// Usage:
let client = ClientBuilder::new()
    .with_timeout(Duration::from_secs(30))
    .with_max_retries(5)
    .build();
```

### 8. Extension Trait Pattern (Colors)

**Pattern for extending types without modification:**

```rust
pub trait ColorExt {
    fn color(&self, color: CatppuccinColor) -> String;
}

impl ColorExt for str {
    fn color(&self, color: CatppuccinColor) -> String {
        format!("{}{}{}", color.as_ansi(), self, RESET)
    }
}

// Usage:
println!("{}", "Success!".color(CatppuccinColor::Green));
```

---

## Things to Avoid

### ❌ Don't Do This

**1. Don't add business logic to CLI/API layers:**

```rust
// ❌ Bad: Logic in CLI
fn main() {
    let domain = normalize_domain(&args.domain);  // Logic in CLI
    let whois = query_whois(&domain);
}

// ✅ Good: Logic in core
fn main() {
    let result = seer_core::whois(&args.domain);  // Core handles normalization
}
```

**2. Don't use unwrap() in library code:**

```rust
// ❌ Bad
let data = fetch_data().unwrap();

// ✅ Good
let data = fetch_data()
    .map_err(|e| SeerError::FetchError(e.to_string()))?;
```

**3. Don't skip timeout protection:**

```rust
// ❌ Bad: No timeout
let response = reqwest::get(url).await?;

// ✅ Good: With timeout
let response = timeout(
    Duration::from_secs(30),
    reqwest::get(url)
).await??;
```

**4. Don't block async code:**

```rust
// ❌ Bad: Blocking in async context
async fn bad() {
    std::thread::sleep(Duration::from_secs(1));  // Blocks thread
}

// ✅ Good: Use async sleep
async fn good() {
    tokio::time::sleep(Duration::from_secs(1)).await;
}
```

**5. Don't create multiple Tokio runtimes:**

```rust
// ❌ Bad: Multiple runtimes
fn call_from_python() {
    let rt = Runtime::new().unwrap();  // Creates new runtime every call
    rt.block_on(async_fn());
}

// ✅ Good: Single shared runtime
static RUNTIME: Lazy<Runtime> = Lazy::new(|| Runtime::new().unwrap());

fn call_from_python() {
    RUNTIME.block_on(async_fn());
}
```

**6. Don't hardcode configuration:**

```rust
// ❌ Bad
const TIMEOUT: Duration = Duration::from_secs(10);

// ✅ Good: Configurable with sensible default
pub struct Client {
    timeout: Duration,
}

impl Default for Client {
    fn default() -> Self {
        Self { timeout: Duration::from_secs(10) }
    }
}
```

**7. Don't ignore domain normalization:**

```rust
// ❌ Bad: No normalization
fn lookup(domain: &str) -> Result<Data> {
    query_api(domain)  // "HTTPS://WWW.EXAMPLE.COM" will fail
}

// ✅ Good: Always normalize
fn lookup(domain: &str) -> Result<Data> {
    let normalized = normalize_domain(domain);
    query_api(&normalized)
}
```

**8. Don't expose internal types in public APIs:**

```rust
// ❌ Bad: Exposing hickory_resolver types
pub async fn resolve(domain: &str) -> hickory_resolver::lookup::Lookup {
    // ...
}

// ✅ Good: Use own types
pub async fn resolve(domain: &str) -> Result<Vec<DnsRecord>> {
    // Convert internal types to our own
}
```

---

## Troubleshooting

### Common Build Issues

**Issue: Maturin build fails**
```bash
# Solution: Ensure maturin is installed
pip install maturin

# Build with verbose output
maturin develop --release -v
```

**Issue: Rust compilation fails with linking errors**
```bash
# Solution: Clean and rebuild
cargo clean
cargo build --release
```

**Issue: Python can't find seer module**
```bash
# Solution: Reinstall in development mode
cd seer-py
maturin develop --release
```

### Runtime Issues

**Issue: WHOIS queries timeout**
- Check firewall allows outbound port 43
- Some networks block WHOIS
- Try increasing timeout in client code

**Issue: RDAP bootstrap fails**
- Check internet connectivity
- IANA servers may be temporarily unavailable
- Bootstrap data is cached after first load

**Issue: DNS resolution fails**
- Check DNS connectivity (try `dig example.com`)
- Default resolver is 8.8.8.8 (Google DNS)
- Can specify custom nameserver

**Issue: MCP server not responding**
- Verify stdio transport is working
- Check logs for errors
- Ensure seer Python package is installed

### Debugging Tips

**Enable debug logging:**
```bash
RUST_LOG=debug cargo run -- lookup example.com
RUST_LOG=seer_core=trace cargo test
```

**Log levels:**
- `trace`: Very detailed
- `debug`: Debug information
- `info`: General information
- `warn`: Warnings
- `error`: Errors only

**Test specific module:**
```bash
cargo test -p seer-core whois::tests
cargo test -p seer-cli repl::tests
```

**Profile performance:**
```bash
cargo build --release
CARGO_PROFILE_RELEASE_DEBUG=true cargo flamegraph
```

---

## Working with Git

### Branch Strategy

- `main`: Production-ready code
- Feature branches: `feature/description` or `claude/description-{sessionId}`
- Always create pull requests for review

### Commit Conventions

Follow conventional commits:

```
feat: Add DNSSEC record support
fix: Handle WHOIS timeout errors correctly
docs: Update API documentation
test: Add tests for DNS propagation
refactor: Simplify RDAP client code
perf: Optimize bulk operation concurrency
```

### Pre-commit Checklist

Before committing:

1. ✅ Run tests: `cargo test`
2. ✅ Run clippy: `cargo clippy -- -D warnings`
3. ✅ Format code: `cargo fmt`
4. ✅ Update documentation if needed
5. ✅ Test Python bindings if changed: `cd seer-py && maturin develop`
6. ✅ Test API if changed: `cd seer-api && pytest`

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `RUST_LOG` | Logging level (trace, debug, info, warn, error) | - |
| `SEER_CORS_ORIGINS` | Comma-separated allowed CORS origins for API | `*` |

---

## Performance Considerations

### Concurrency Limits

- **Bulk operations**: Default 10, max 50
- **DNS propagation**: 29 concurrent queries (one per server)
- **RDAP bootstrap**: 4 concurrent requests (one per registry)

### Timeout Values

- **WHOIS**: 10 seconds
- **RDAP**: 30 seconds
- **DNS**: 5 seconds (with 2 retries)
- **HTTP**: 10 seconds
- **SSL check**: 10 seconds

### Memory Considerations

- **WHOIS responses**: Limited to 1MB per response
- **RDAP bootstrap**: Cached in memory (~100KB total)
- **Bulk operations**: Process streaming, don't load all results at once

### Rate Limiting

- Semaphore-based concurrency control
- No hard rate limits, but respect server capacity
- Default 10 concurrent operations for bulk

---

## Security Considerations

### Input Validation

- Always validate and normalize domain input
- Reject invalid domain formats
- Sanitize user input before network operations

### Network Security

- Use HTTPS for RDAP queries
- Validate SSL certificates in status checks
- Timeout protection on all network calls

### Error Messages

- Don't expose internal system details in errors
- Sanitize error messages before returning to users
- Log detailed errors internally, return generic messages externally

---

## Contributing Guidelines for AI Assistants

When making changes to this codebase:

1. **Understand before modifying**: Read relevant code before making changes
2. **Test changes**: Run `cargo test` after modifications
3. **Follow conventions**: Match existing code style and patterns
4. **Document changes**: Update documentation for public APIs
5. **Keep core pure**: All business logic stays in seer-core
6. **Handle errors**: Use `Result<T>` and proper error types
7. **Add timeouts**: All network operations need timeout protection
8. **Normalize input**: Always normalize domains before processing
9. **Think concurrent**: Use async/await and tokio patterns
10. **Be explicit**: Avoid unwrap(), use proper error handling

---

## Quick Reference

### Common Commands

```bash
# Install CLI to PATH
cargo install --path seer-cli

# Run CLI (after installation)
seer lookup example.com

# Run REPL (after installation)
seer

# Build everything (without installing)
cargo build --release

# Run tests
cargo test

# Build Python bindings
cd seer-py && maturin develop --release

# Start API server
seer-api

# Start MCP server
seer-mcp

# Format code
cargo fmt

# Lint code
cargo clippy -- -D warnings

# Check without building
cargo check
```

### File a domain lookup flows through:

1. **CLI**: `seer-cli/src/main.rs` → parse args
2. **Core**: `seer-core/src/lookup.rs` → smart lookup
3. **RDAP**: `seer-core/src/rdap/client.rs` → try RDAP first
4. **WHOIS**: `seer-core/src/whois/client.rs` → fallback to WHOIS
5. **Output**: `seer-core/src/output/human.rs` → format for display
6. **CLI**: `seer-cli/src/main.rs` → print result

---

## Version Information

- **Rust Edition**: 2021
- **Minimum Rust Version**: 1.70+
- **Python**: 3.9+ (ABI3 compatibility)
- **License**: MIT

---

## Additional Resources

- **README.md**: User-facing documentation
- **Cargo.toml**: Workspace configuration and dependencies
- **pyproject.toml files**: Python package configuration
- **/docs**: OpenAPI documentation (http://localhost:8000/docs when API running)

---

## Contact and Support

For issues and questions:
- GitHub Issues: [Repository Issues](https://github.com/TheZacillac/seer/issues)
- Discussions: [Repository Discussions](https://github.com/TheZacillac/seer/discussions)

---

**Last Updated**: 2026-01-16
**Document Version**: 1.0.0
