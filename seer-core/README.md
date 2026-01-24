# seer-core

Core Rust library containing all business logic for the Seer domain utility suite.

## Overview

`seer-core` is the foundation of Seer, providing WHOIS, RDAP, DNS, and domain status functionality. All other Seer packages (CLI, Python bindings, API) are thin wrappers around this library.

## Modules

| Module | Description |
|--------|-------------|
| [`whois`](src/whois/) | WHOIS protocol client with referral following |
| [`rdap`](src/rdap/) | RDAP (Registration Data Access Protocol) client |
| [`dns`](src/dns/) | DNS resolver, propagation checker, and DNS follower |
| [`status`](src/status/) | Domain health checking (HTTP, SSL, expiration) |
| [`bulk`](src/bulk/) | Concurrent bulk operation executor |
| [`output`](src/output/) | Human and JSON output formatters |
| [`lookup`](src/lookup.rs) | Smart lookup orchestration (RDAP → WHOIS fallback) |
| [`validation`](src/validation.rs) | Domain normalization and SSRF protection |
| [`error`](src/error.rs) | Centralized error types |
| [`colors`](src/colors.rs) | Catppuccin color palette for terminal output |

## Public API

### Core Types

```rust
use seer_core::{SeerError, Result};
```

- `SeerError` - Comprehensive error enum for all operations
- `Result<T>` - Type alias for `std::result::Result<T, SeerError>`

### Clients

```rust
use seer_core::{
    WhoisClient,      // WHOIS lookups
    RdapClient,       // RDAP lookups (domain, IP, ASN)
    DnsResolver,      // DNS queries
    StatusClient,     // Domain health checks
    SmartLookup,      // RDAP-first with WHOIS fallback
    BulkExecutor,     // Concurrent bulk operations
};
```

### Data Types

```rust
use seer_core::{
    // WHOIS
    WhoisResponse,

    // RDAP
    RdapResponse,

    // DNS
    DnsRecord, RecordType, PropagationResult,
    DnsFollower, FollowConfig, FollowResult,

    // Status
    StatusResponse, CertificateInfo, DomainExpiration, DnsResolution,

    // Lookup
    LookupResult,

    // Bulk
    BulkOperation, BulkResult,

    // Output
    OutputFormat, OutputFormatter,
};
```

### Utility Functions

```rust
use seer_core::{normalize_domain, validate_domain_safe};
```

## Usage Examples

### Smart Lookup (RDAP with WHOIS Fallback)

```rust
use seer_core::SmartLookup;

#[tokio::main]
async fn main() -> seer_core::Result<()> {
    let lookup = SmartLookup::new();
    let result = lookup.lookup("example.com").await?;

    match result {
        seer_core::LookupResult::Rdap { data, .. } => {
            println!("RDAP: {:?}", data.domain_name());
        }
        seer_core::LookupResult::Whois { data, .. } => {
            println!("WHOIS: {}", data.domain);
        }
    }
    Ok(())
}
```

### WHOIS Lookup

```rust
use seer_core::WhoisClient;

#[tokio::main]
async fn main() -> seer_core::Result<()> {
    let client = WhoisClient::new();
    let response = client.lookup("example.com").await?;

    println!("Registrar: {:?}", response.registrar);
    println!("Expires: {:?}", response.expiration_date);
    Ok(())
}
```

### RDAP Lookups

```rust
use seer_core::RdapClient;

#[tokio::main]
async fn main() -> seer_core::Result<()> {
    let client = RdapClient::new();

    // Domain lookup
    let domain = client.lookup_domain("example.com").await?;

    // IP lookup
    let ip = client.lookup_ip("8.8.8.8").await?;

    // ASN lookup
    let asn = client.lookup_asn(15169).await?;

    Ok(())
}
```

### DNS Resolution

```rust
use seer_core::{DnsResolver, RecordType};

#[tokio::main]
async fn main() -> seer_core::Result<()> {
    let resolver = DnsResolver::new();

    // Basic A record lookup
    let records = resolver.resolve("example.com", RecordType::A, None).await?;

    // MX records with custom nameserver
    let mx = resolver.resolve("example.com", RecordType::MX, Some("8.8.8.8")).await?;

    for record in records {
        println!("{}: {}", record.record_type, record.data);
    }
    Ok(())
}
```

### DNS Propagation Check

```rust
use seer_core::dns::{PropagationChecker, RecordType};

#[tokio::main]
async fn main() -> seer_core::Result<()> {
    let checker = PropagationChecker::new();
    let result = checker.check("example.com", RecordType::A).await?;

    println!("Propagation: {:.1}%", result.propagation_percentage);
    println!("Servers responding: {}/{}", result.servers_responding, result.servers_checked);
    Ok(())
}
```

### Domain Status Check

```rust
use seer_core::StatusClient;

#[tokio::main]
async fn main() -> seer_core::Result<()> {
    let client = StatusClient::new();
    let status = client.check("example.com").await?;

    println!("HTTP Status: {:?}", status.http_status);
    println!("SSL Valid: {:?}", status.certificate.map(|c| c.is_valid));
    println!("Domain Expires: {:?}", status.domain_expiration.map(|e| e.expiration_date));
    Ok(())
}
```

### Bulk Operations

```rust
use seer_core::BulkExecutor;

#[tokio::main]
async fn main() -> seer_core::Result<()> {
    let executor = BulkExecutor::new()
        .with_concurrency(20);

    let domains = vec![
        "example.com".to_string(),
        "google.com".to_string(),
        "github.com".to_string(),
    ];

    let results = executor.execute_lookup(domains).await;

    for result in results {
        println!("{}: success={}",
            result.operation, result.success);
    }
    Ok(())
}
```

## Configuration

### Timeouts

All clients support configurable timeouts via builder pattern:

```rust
use std::time::Duration;
use seer_core::{WhoisClient, RdapClient, DnsResolver, StatusClient};

let whois = WhoisClient::new().with_timeout(Duration::from_secs(15));
let rdap = RdapClient::new().with_timeout(Duration::from_secs(45));
let dns = DnsResolver::new().with_timeout(Duration::from_secs(10));
let status = StatusClient::new().with_timeout(Duration::from_secs(20));
```

### Default Timeout Values

| Client | Default Timeout |
|--------|-----------------|
| WHOIS | 10 seconds |
| RDAP | 30 seconds |
| DNS | 5 seconds (with 2 retries) |
| HTTP/SSL | 10 seconds |

## Error Handling

All operations return `Result<T, SeerError>`. Error variants include:

- `WhoisError` - WHOIS lookup failures
- `WhoisServerNotFound` - No WHOIS server for TLD
- `RdapError` - RDAP lookup failures
- `RdapBootstrapError` - IANA bootstrap failures
- `DnsError` - DNS resolution failures
- `InvalidDomain` - Invalid domain format
- `InvalidIpAddress` - Invalid IP address format
- `HttpError` - HTTP request failures
- `Timeout` - Operation timeout
- `CertificateError` - SSL certificate issues
- `LookupFailed` - Both RDAP and WHOIS failed

## Dependencies

- **tokio** - Async runtime
- **reqwest** - HTTP client (rustls-tls)
- **hickory-resolver** - DNS resolution with DNSSEC
- **serde** / **serde_json** - Serialization
- **thiserror** - Error handling
- **chrono** - Date/time handling
- **regex** - WHOIS parsing
- **native-tls** / **x509-parser** - SSL certificate handling

## License

MIT License - See LICENSE file in repository root.
