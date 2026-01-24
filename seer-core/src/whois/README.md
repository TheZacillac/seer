# WHOIS Module

WHOIS protocol client with automatic referral following and server discovery.

## Overview

This module provides a complete WHOIS client implementation that:
- Queries WHOIS servers over TCP port 43
- Automatically follows referrals (up to 3 levels deep)
- Discovers WHOIS servers for unknown TLDs via IANA
- Caches discovered servers for performance
- Parses responses into structured data

## Files

| File | Description |
|------|-------------|
| `mod.rs` | Module exports and public interface |
| `client.rs` | WHOIS TCP client with referral following |
| `parser.rs` | Response parser for extracting structured data |
| `servers.rs` | TLD-to-WHOIS-server mapping database |

## Public API

### Types

```rust
pub use client::WhoisClient;
pub use parser::WhoisResponse;
pub use servers::{get_registry_url, get_tld};
```

### WhoisClient

Main client for performing WHOIS lookups.

```rust
impl WhoisClient {
    /// Create a new client with default settings
    pub fn new() -> Self;

    /// Set timeout for network operations (default: 10s)
    pub fn with_timeout(self, timeout: Duration) -> Self;

    /// Perform WHOIS lookup with automatic referral following
    pub async fn lookup(&self, domain: &str) -> Result<WhoisResponse>;

    /// Query a specific WHOIS server directly
    pub async fn lookup_with_server(&self, domain: &str, server: &str) -> Result<WhoisResponse>;
}
```

### WhoisResponse

Structured WHOIS response data.

```rust
pub struct WhoisResponse {
    pub domain: String,
    pub whois_server: String,
    pub raw_data: String,

    // Parsed fields (Option<T> because not all TLDs provide all fields)
    pub registrar: Option<String>,
    pub organization: Option<String>,
    pub creation_date: Option<DateTime<Utc>>,
    pub expiration_date: Option<DateTime<Utc>>,
    pub updated_date: Option<DateTime<Utc>>,
    pub status: Vec<String>,
    pub nameservers: Vec<String>,
}

impl WhoisResponse {
    /// Parse raw WHOIS response into structured data
    pub fn parse(domain: &str, server: &str, raw: &str) -> Self;

    /// Check if domain appears available for registration
    pub fn is_available(&self) -> bool;

    /// Check if response indicates domain not found
    pub fn indicates_not_found(&self) -> bool;
}
```

### Utility Functions

```rust
/// Get the TLD from a domain name
pub fn get_tld(domain: &str) -> Option<&str>;

/// Get the registry URL for a TLD (for manual lookup)
pub fn get_registry_url(tld: &str) -> Option<String>;
```

## Usage Examples

### Basic Lookup

```rust
use seer_core::WhoisClient;

let client = WhoisClient::new();
let response = client.lookup("example.com").await?;

println!("Domain: {}", response.domain);
println!("Registrar: {:?}", response.registrar);
println!("Created: {:?}", response.creation_date);
println!("Expires: {:?}", response.expiration_date);
println!("Nameservers: {:?}", response.nameservers);
```

### Query Specific Server

```rust
let client = WhoisClient::new();
let response = client.lookup_with_server("example.com", "whois.verisign-grs.com").await?;
```

### Custom Timeout

```rust
use std::time::Duration;

let client = WhoisClient::new()
    .with_timeout(Duration::from_secs(30));
```

## Protocol Details

### Referral Following

The client automatically follows WHOIS referrals:

1. Query the TLD's registry WHOIS server
2. Parse response for referral patterns:
   - `Registrar WHOIS Server: ...`
   - `Whois Server: ...`
   - `ReferralServer: whois://...`
3. Follow referral to registrar's WHOIS server
4. Return registrar response (contains more detailed info)

**Safeguards:**
- Maximum referral depth: 3
- Circular referral detection
- Graceful fallback to registry response on referral failure

### Server Discovery

For TLDs not in the built-in database:

1. Query IANA WHOIS server (`whois.iana.org`) with TLD
2. Extract WHOIS server from response (`whois: ...` line)
3. Cache discovered server for future lookups
4. If no WHOIS server exists, extract registry URL for manual lookup

### Response Parsing

The parser uses regex patterns to extract:
- Registrar name
- Organization name
- Registration/expiration/update dates
- Domain status codes
- Nameserver hostnames

Date parsing supports multiple formats common across registrars.

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `WHOIS_PORT` | 43 | Standard WHOIS TCP port |
| `DEFAULT_TIMEOUT` | 10s | Default operation timeout |
| `MAX_RESPONSE_SIZE` | 1MB | Maximum response size |
| `MAX_REFERRAL_DEPTH` | 3 | Maximum referral chain length |

## Error Handling

- `SeerError::WhoisError` - General WHOIS failures
- `SeerError::WhoisServerNotFound` - No WHOIS server for TLD
- `SeerError::Timeout` - Connection or read timeout
- `SeerError::InvalidDomain` - Invalid domain format
