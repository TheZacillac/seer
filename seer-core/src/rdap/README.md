# RDAP Module

RDAP (Registration Data Access Protocol) client with IANA bootstrap support.

## Overview

This module provides an RDAP client that:
- Queries RDAP servers using HTTP/HTTPS
- Uses IANA bootstrap files to discover RDAP servers
- Supports domain, IP address, and ASN lookups
- Returns structured JSON-based responses
- Caches bootstrap data for performance

## Files

| File | Description |
|------|-------------|
| `mod.rs` | Module exports and public interface |
| `client.rs` | RDAP HTTP client with IANA bootstrap |
| `types.rs` | RDAP response structures and parsing |

## Public API

### Types

```rust
pub use client::RdapClient;
pub use types::{ContactInfo, RdapResponse};
```

### RdapClient

Main client for performing RDAP lookups.

```rust
impl RdapClient {
    /// Create a new client with default settings
    pub fn new() -> Self;

    /// Set timeout for HTTP operations (default: 30s)
    pub fn with_timeout(self, timeout: Duration) -> Self;

    /// Look up domain registration information
    pub async fn lookup_domain(&self, domain: &str) -> Result<RdapResponse>;

    /// Look up IP address registration information
    pub async fn lookup_ip(&self, ip: &str) -> Result<RdapResponse>;

    /// Look up ASN (Autonomous System Number) information
    pub async fn lookup_asn(&self, asn: u32) -> Result<RdapResponse>;
}
```

### RdapResponse

Structured RDAP response data.

```rust
pub struct RdapResponse {
    // Domain information
    pub ldh_name: Option<String>,      // LDH (Letter-Digit-Hyphen) domain name
    pub unicode_name: Option<String>,  // Unicode domain name (IDN)
    pub handle: Option<String>,        // Registry handle

    // Status and dates
    pub status: Vec<String>,           // Domain status codes
    pub events: Vec<RdapEvent>,        // Registration events

    // Related entities
    pub entities: Vec<RdapEntity>,     // Registrar, registrant, etc.
    pub nameservers: Vec<RdapNameserver>,

    // IP/ASN specific fields
    pub start_address: Option<String>,
    pub end_address: Option<String>,
    pub ip_version: Option<String>,
    pub name: Option<String>,
    pub asn_type: Option<String>,

    // Links and remarks
    pub links: Vec<RdapLink>,
    pub remarks: Vec<RdapRemark>,
}

impl RdapResponse {
    /// Get the domain name
    pub fn domain_name(&self) -> Option<&str>;

    /// Get the registrar name
    pub fn get_registrar(&self) -> Option<String>;

    /// Get registrant organization
    pub fn get_registrant_organization(&self) -> Option<String>;

    /// Get creation date
    pub fn creation_date(&self) -> Option<DateTime<Utc>>;

    /// Get expiration date
    pub fn expiration_date(&self) -> Option<DateTime<Utc>>;

    /// Get last updated date
    pub fn last_updated(&self) -> Option<DateTime<Utc>>;
}
```

### ContactInfo

Contact information extracted from entities.

```rust
pub struct ContactInfo {
    pub name: Option<String>,
    pub organization: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub address: Option<String>,
}
```

## Usage Examples

### Domain Lookup

```rust
use seer_core::RdapClient;

let client = RdapClient::new();
let response = client.lookup_domain("example.com").await?;

println!("Domain: {:?}", response.domain_name());
println!("Registrar: {:?}", response.get_registrar());
println!("Created: {:?}", response.creation_date());
println!("Expires: {:?}", response.expiration_date());
println!("Status: {:?}", response.status);
```

### IP Address Lookup

```rust
let client = RdapClient::new();
let response = client.lookup_ip("8.8.8.8").await?;

println!("Network: {:?} - {:?}", response.start_address, response.end_address);
println!("Name: {:?}", response.name);
```

### ASN Lookup

```rust
let client = RdapClient::new();
let response = client.lookup_asn(15169).await?;  // Google's ASN

println!("Name: {:?}", response.name);
println!("Handle: {:?}", response.handle);
```

### Custom Timeout

```rust
use std::time::Duration;

let client = RdapClient::new()
    .with_timeout(Duration::from_secs(60));
```

## Protocol Details

### IANA Bootstrap

RDAP uses IANA bootstrap files to discover which RDAP server handles each TLD, IP range, or ASN range:

- **DNS Bootstrap**: `https://data.iana.org/rdap/dns.json`
- **IPv4 Bootstrap**: `https://data.iana.org/rdap/ipv4.json`
- **IPv6 Bootstrap**: `https://data.iana.org/rdap/ipv6.json`
- **ASN Bootstrap**: `https://data.iana.org/rdap/asn.json`

Bootstrap data is loaded on first use and cached in memory.

### RDAP vs WHOIS

| Feature | RDAP | WHOIS |
|---------|------|-------|
| Protocol | HTTP/HTTPS | TCP |
| Data Format | JSON | Plain text |
| Schema | Standardized | Varies by registrar |
| Auth Support | Yes | No |
| Internationalization | Native Unicode | Limited |

RDAP is the modern replacement for WHOIS but not all TLDs support it yet.

### Response Structure

RDAP responses follow RFC 7483 structure:
- **Events**: Registration lifecycle events (registration, expiration, last changed)
- **Entities**: Organizations/people with roles (registrar, registrant, admin, tech)
- **Nameservers**: DNS nameserver information
- **Status**: Domain/IP status codes (active, inactive, etc.)

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `DEFAULT_TIMEOUT` | 30s | Default HTTP timeout |
| `IANA_BOOTSTRAP_DNS` | `https://data.iana.org/rdap/dns.json` | DNS bootstrap URL |
| `IANA_BOOTSTRAP_IPV4` | `https://data.iana.org/rdap/ipv4.json` | IPv4 bootstrap URL |
| `IANA_BOOTSTRAP_IPV6` | `https://data.iana.org/rdap/ipv6.json` | IPv6 bootstrap URL |
| `IANA_BOOTSTRAP_ASN` | `https://data.iana.org/rdap/asn.json` | ASN bootstrap URL |

## Error Handling

- `SeerError::RdapError` - General RDAP failures
- `SeerError::RdapBootstrapError` - Bootstrap loading/parsing failures
- `SeerError::InvalidDomain` - Invalid domain format
- `SeerError::InvalidIpAddress` - Invalid IP address format
- `SeerError::Timeout` - HTTP request timeout
