# DNS Module

DNS resolution, propagation checking, and record monitoring.

## Overview

This module provides comprehensive DNS functionality:
- DNS record resolution for all common record types
- Global DNS propagation checking across 29 nameservers
- DNS record monitoring over time (follow mode)
- Custom nameserver support

## Files

| File | Description |
|------|-------------|
| `mod.rs` | Module exports and public interface |
| `resolver.rs` | DNS resolver using hickory-resolver |
| `records.rs` | DNS record type definitions |
| `propagation.rs` | Global DNS propagation checker |
| `follow.rs` | DNS record monitoring over time |

## Public API

### Types

```rust
// Resolver
pub use resolver::DnsResolver;

// Records
pub use records::{DnsRecord, RecordData, RecordType};

// Propagation
pub use propagation::{DnsServer, PropagationChecker, PropagationResult};

// Follow
pub use follow::{DnsFollower, FollowConfig, FollowIteration, FollowProgressCallback, FollowResult};
```

### DnsResolver

DNS resolver for querying records.

```rust
impl DnsResolver {
    /// Create a new resolver with default settings
    pub fn new() -> Self;

    /// Set timeout for DNS queries (default: 5s)
    pub fn with_timeout(self, timeout: Duration) -> Self;

    /// Resolve DNS records
    pub async fn resolve(
        &self,
        domain: &str,
        record_type: RecordType,
        nameserver: Option<&str>,
    ) -> Result<Vec<DnsRecord>>;

    /// Resolve SRV records (requires service/protocol format)
    pub async fn resolve_srv(
        &self,
        service: &str,
        protocol: &str,
        domain: &str,
        nameserver: Option<&str>,
    ) -> Result<Vec<DnsRecord>>;
}
```

### RecordType

Supported DNS record types.

```rust
pub enum RecordType {
    A,       // IPv4 address
    AAAA,    // IPv6 address
    CNAME,   // Canonical name
    MX,      // Mail exchange
    NS,      // Nameserver
    TXT,     // Text record
    SOA,     // Start of authority
    PTR,     // Pointer (reverse DNS)
    SRV,     // Service locator
    CAA,     // Certification authority authorization
    DNSKEY,  // DNSSEC public key
    DS,      // Delegation signer (DNSSEC)
    ANY,     // All available records
}
```

### DnsRecord

DNS record with data.

```rust
pub struct DnsRecord {
    pub name: String,
    pub record_type: RecordType,
    pub ttl: u32,
    pub data: RecordData,
}

pub enum RecordData {
    A { address: String },
    AAAA { address: String },
    CNAME { target: String },
    MX { preference: u16, exchange: String },
    NS { nameserver: String },
    TXT { text: String },
    SOA { mname: String, rname: String, serial: u32, refresh: u32, retry: u32, expire: u32, minimum: u32 },
    PTR { target: String },
    SRV { priority: u16, weight: u16, port: u16, target: String },
    CAA { flags: u8, tag: String, value: String },
    DNSKEY { flags: u16, protocol: u8, algorithm: u8, public_key: String },
    DS { key_tag: u16, algorithm: u8, digest_type: u8, digest: String },
}
```

### PropagationChecker

Check DNS propagation across global nameservers.

```rust
impl PropagationChecker {
    /// Create with default 29 global DNS servers
    pub fn new() -> Self;

    /// Use custom DNS servers
    pub fn with_servers(self, servers: Vec<DnsServer>) -> Self;

    /// Add a DNS server
    pub fn add_server(self, server: DnsServer) -> Self;

    /// Set query timeout
    pub fn with_timeout(self, timeout: Duration) -> Self;

    /// Check propagation for a domain/record type
    pub async fn check(&self, domain: &str, record_type: RecordType) -> Result<PropagationResult>;
}
```

### PropagationResult

Result of propagation check.

```rust
pub struct PropagationResult {
    pub domain: String,
    pub record_type: RecordType,
    pub servers_checked: usize,
    pub servers_responding: usize,
    pub propagation_percentage: f64,
    pub results: Vec<ServerResult>,
    pub consensus_values: Vec<String>,
    pub inconsistencies: Vec<String>,
}

impl PropagationResult {
    /// Check if fully propagated (100%)
    pub fn is_fully_propagated(&self) -> bool;

    /// Check if there are inconsistencies
    pub fn has_inconsistencies(&self) -> bool;
}
```

### DnsFollower

Monitor DNS records over time.

```rust
impl DnsFollower {
    /// Create a new follower
    pub fn new() -> Self;

    /// Follow with custom resolver
    pub fn with_resolver(resolver: DnsResolver) -> Self;

    /// Monitor DNS records over time
    pub async fn follow(
        &self,
        domain: &str,
        record_type: RecordType,
        nameserver: Option<&str>,
        config: FollowConfig,
        callback: Option<FollowProgressCallback>,
        cancel_rx: Option<watch::Receiver<bool>>,
    ) -> Result<FollowResult>;

    /// Simple follow without callback/cancellation
    pub async fn follow_simple(
        &self,
        domain: &str,
        record_type: RecordType,
        nameserver: Option<&str>,
        config: FollowConfig,
    ) -> Result<FollowResult>;
}
```

### FollowConfig

Configuration for DNS following.

```rust
pub struct FollowConfig {
    pub iterations: usize,     // Number of checks
    pub interval_secs: u64,    // Seconds between checks
    pub changes_only: bool,    // Only report changes
}

impl FollowConfig {
    /// Create config with iterations and interval in minutes
    pub fn new(iterations: usize, interval_minutes: f64) -> Self;

    /// Only output when records change
    pub fn with_changes_only(self, changes_only: bool) -> Self;
}
```

## Usage Examples

### Basic DNS Resolution

```rust
use seer_core::{DnsResolver, RecordType};

let resolver = DnsResolver::new();

// A records
let a_records = resolver.resolve("example.com", RecordType::A, None).await?;

// MX records
let mx_records = resolver.resolve("example.com", RecordType::MX, None).await?;

// With custom nameserver
let records = resolver.resolve("example.com", RecordType::A, Some("8.8.8.8")).await?;

for record in records {
    println!("{} {} TTL:{} {}", record.name, record.record_type, record.ttl, record.data);
}
```

### SRV Records

```rust
let resolver = DnsResolver::new();

// _http._tcp.example.com
let srv = resolver.resolve_srv("http", "tcp", "example.com", None).await?;
```

### DNS Propagation Check

```rust
use seer_core::dns::{PropagationChecker, RecordType};

let checker = PropagationChecker::new();
let result = checker.check("example.com", RecordType::A).await?;

println!("Propagation: {:.1}%", result.propagation_percentage);
println!("Servers: {}/{}", result.servers_responding, result.servers_checked);
println!("Consensus: {:?}", result.consensus_values);

if result.has_inconsistencies() {
    println!("Inconsistencies:");
    for issue in &result.inconsistencies {
        println!("  - {}", issue);
    }
}
```

### DNS Monitoring (Follow)

```rust
use seer_core::dns::{DnsFollower, FollowConfig, RecordType};

let follower = DnsFollower::new();
let config = FollowConfig::new(10, 1.0)  // 10 checks, 1 minute interval
    .with_changes_only(true);

let result = follower.follow_simple("example.com", RecordType::A, None, config).await?;

println!("Total changes: {}", result.total_changes);
for iter in &result.iterations {
    if iter.changed {
        println!("Change at {}: +{:?} -{:?}",
            iter.timestamp, iter.added, iter.removed);
    }
}
```

## Global DNS Servers

The propagation checker uses 29 DNS servers across 6 regions:

**North America**
- Google (8.8.8.8), Cloudflare (1.1.1.1), OpenDNS (208.67.222.222), Quad9 (9.9.9.9), Level3 (4.2.2.1)

**Europe**
- DNS.Watch, Mullvad, dns0.eu, Yandex, UncensoredDNS

**Asia Pacific**
- AliDNS, 114DNS, Tencent DNSPod, TWNIC, HiNet

**Latin America**
- Claro Brasil, Telefonica Brasil, Antel Uruguay, Telmex Mexico, CenturyLink LATAM

**Africa**
- Liquid Telecom, SEACOM, Safaricom Kenya, MTN South Africa, Telecom Egypt

**Middle East**
- Etisalat UAE, STC Saudi, Bezeq Israel, Turk Telekom, Ooredoo Qatar

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `DEFAULT_TIMEOUT` | 5s | DNS query timeout |
| Retry attempts | 2 | Number of retries per query |

## Error Handling

- `SeerError::DnsError` - General DNS resolution failures
- `SeerError::DnsResolverError` - Underlying resolver errors
- `SeerError::InvalidDomain` - Invalid domain format
- `SeerError::InvalidRecordType` - Unknown record type
