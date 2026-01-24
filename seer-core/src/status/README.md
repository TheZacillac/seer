# Status Module

Domain health checking for HTTP, SSL certificates, and registration expiration.

## Overview

This module provides comprehensive domain health checking:
- HTTP status code and page title
- SSL certificate validation and expiration
- Domain registration expiration (via WHOIS/RDAP)
- DNS resolution status (A, AAAA, CNAME, NS records)
- SSRF protection for all network operations

## Files

| File | Description |
|------|-------------|
| `mod.rs` | Module exports and public interface |
| `client.rs` | Status client with HTTP/SSL/expiration checking |
| `types.rs` | Response structures |

## Public API

### Types

```rust
pub use client::StatusClient;
pub use types::{CertificateInfo, DnsResolution, DomainExpiration, StatusResponse};
```

### StatusClient

Main client for domain status checks.

```rust
impl StatusClient {
    /// Create a new client with default settings
    pub fn new() -> Self;

    /// Set timeout for HTTP and TLS operations (default: 10s)
    pub fn with_timeout(self, timeout: Duration) -> Self;

    /// Check the status of a domain
    pub async fn check(&self, domain: &str) -> Result<StatusResponse>;
}
```

### StatusResponse

Complete domain status information.

```rust
pub struct StatusResponse {
    pub domain: String,

    // HTTP status
    pub http_status: Option<u16>,
    pub http_status_text: Option<String>,
    pub title: Option<String>,

    // SSL certificate
    pub certificate: Option<CertificateInfo>,

    // Domain registration
    pub domain_expiration: Option<DomainExpiration>,

    // DNS resolution
    pub dns_resolution: Option<DnsResolution>,
}

impl StatusResponse {
    /// Create new response for a domain
    pub fn new(domain: String) -> Self;
}
```

### CertificateInfo

SSL certificate information.

```rust
pub struct CertificateInfo {
    pub issuer: String,
    pub subject: String,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub days_until_expiry: i64,
    pub is_valid: bool,
}
```

### DomainExpiration

Domain registration expiration.

```rust
pub struct DomainExpiration {
    pub expiration_date: DateTime<Utc>,
    pub days_until_expiry: i64,
    pub registrar: Option<String>,
}
```

### DnsResolution

DNS resolution status.

```rust
pub struct DnsResolution {
    pub a_records: Vec<String>,
    pub aaaa_records: Vec<String>,
    pub cname_target: Option<String>,
    pub nameservers: Vec<String>,
    pub resolves: bool,
}
```

## Usage Examples

### Basic Status Check

```rust
use seer_core::StatusClient;

let client = StatusClient::new();
let status = client.check("example.com").await?;

println!("Domain: {}", status.domain);

// HTTP status
if let Some(code) = status.http_status {
    println!("HTTP: {} {}", code, status.http_status_text.unwrap_or_default());
}
if let Some(title) = &status.title {
    println!("Title: {}", title);
}

// SSL certificate
if let Some(cert) = &status.certificate {
    println!("SSL Issuer: {}", cert.issuer);
    println!("SSL Valid: {}", cert.is_valid);
    println!("SSL Expires: {} ({} days)", cert.valid_until, cert.days_until_expiry);
}

// Domain expiration
if let Some(exp) = &status.domain_expiration {
    println!("Domain Expires: {} ({} days)", exp.expiration_date, exp.days_until_expiry);
    if let Some(registrar) = &exp.registrar {
        println!("Registrar: {}", registrar);
    }
}

// DNS resolution
if let Some(dns) = &status.dns_resolution {
    println!("Resolves: {}", dns.resolves);
    println!("A Records: {:?}", dns.a_records);
    println!("Nameservers: {:?}", dns.nameservers);
}
```

### Custom Timeout

```rust
use std::time::Duration;

let client = StatusClient::new()
    .with_timeout(Duration::from_secs(30));
```

## Concurrent Checks

The status client performs all checks concurrently for efficiency:

```rust
// All of these run in parallel:
// 1. HTTP status and title fetch
// 2. SSL certificate validation
// 3. Domain expiration lookup (WHOIS/RDAP)
// 4. DNS resolution (A, AAAA, CNAME, NS)
```

## Security

### SSRF Protection

All HTTP and TLS connections include SSRF (Server-Side Request Forgery) protection:

1. Domain is resolved to IP addresses
2. Each resolved IP is checked against blocked ranges:
   - Private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
   - Loopback (127.0.0.0/8, ::1)
   - Link-local (169.254.0.0/16, fe80::/10)
   - Cloud metadata (169.254.169.254)
   - Documentation ranges
   - Multicast and broadcast
3. Connection is blocked if any IP is in a reserved range

### Certificate Validation

The SSL check:
- Connects via TLS and retrieves the peer certificate
- Parses certificate using x509-parser
- Extracts issuer, subject, and validity dates
- Calculates days until expiration
- Validates that current time is within validity period

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `DEFAULT_TIMEOUT` | 10s | HTTP/TLS operation timeout |

## Error Handling

- `SeerError::HttpError` - HTTP request failures
- `SeerError::CertificateError` - SSL certificate issues
- `SeerError::Timeout` - Operation timeout
- `SeerError::InvalidDomain` - Invalid domain or SSRF blocked

Note: Individual check failures don't fail the entire status check. If HTTP fails but SSL succeeds, you'll get partial results with `None` for failed components.
