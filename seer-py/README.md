# seer-py

Python bindings for the Seer domain utility library.

## Overview

`seer-py` provides Python bindings to the Rust `seer-core` library using PyO3, giving Python programs access to:
- Fast WHOIS and RDAP lookups
- DNS resolution and propagation checking
- Domain status checking (HTTP, SSL, expiration)
- Bulk operations with concurrent execution

## Installation

### From Source (Development)

```bash
# Install maturin
pip install maturin

# Build and install in development mode
cd seer-py
maturin develop --release
```

### Build Wheel

```bash
cd seer-py
maturin build --release
pip install target/wheels/seer-*.whl
```

## Files

| File | Description |
|------|-------------|
| `Cargo.toml` | Rust package configuration |
| `pyproject.toml` | Python/Maturin build configuration |
| `src/lib.rs` | PyO3 bindings implementation |
| `python/seer/__init__.py` | Python wrapper module |

## Python API

### Single Domain Functions

```python
import seer

# Smart lookup (RDAP with WHOIS fallback)
result = seer.lookup("example.com")

# WHOIS lookup
whois = seer.whois("example.com")

# RDAP lookups
rdap_domain = seer.rdap_domain("example.com")
rdap_ip = seer.rdap_ip("8.8.8.8")
rdap_asn = seer.rdap_asn(15169)

# Convenience function - auto-detects query type
rdap = seer.rdap("example.com")  # or IP or ASN

# DNS query
dns = seer.dig("example.com", record_type="A")
dns = seer.dig("example.com", record_type="MX", nameserver="8.8.8.8")

# DNS propagation check
prop = seer.propagation("example.com", record_type="A")

# Domain status
status = seer.status("example.com")
```

### Bulk Operations

```python
import seer

domains = ["example.com", "google.com", "github.com"]

# Bulk smart lookup
results = seer.bulk_lookup(domains, concurrency=10)

# Bulk WHOIS
results = seer.bulk_whois(domains, concurrency=10)

# Bulk DNS
results = seer.bulk_dig(domains, record_type="A", concurrency=10)

# Bulk propagation
results = seer.bulk_propagation(domains, record_type="A", concurrency=5)

# Bulk status
results = seer.bulk_status(domains, concurrency=10)
```

## Function Reference

### `lookup(domain: str) -> dict`

Smart domain lookup. Tries RDAP first, falls back to WHOIS.

**Returns:** Dictionary with lookup result including `source` ("rdap" or "whois")

### `whois(domain: str) -> dict`

WHOIS lookup for a domain.

**Returns:** Dictionary with fields:
- `domain`: Domain name
- `registrar`: Registrar name
- `creation_date`: Creation date (ISO string)
- `expiration_date`: Expiration date (ISO string)
- `updated_date`: Last update date (ISO string)
- `status`: List of status codes
- `nameservers`: List of nameserver hostnames
- `raw_data`: Raw WHOIS response

### `rdap_domain(domain: str) -> dict`

RDAP lookup for a domain.

**Returns:** Dictionary with RDAP response data

### `rdap_ip(ip: str) -> dict`

RDAP lookup for an IP address (IPv4 or IPv6).

**Returns:** Dictionary with network information

### `rdap_asn(asn: int) -> dict`

RDAP lookup for an ASN.

**Returns:** Dictionary with ASN information

### `dig(domain: str, record_type: str = "A", nameserver: str = None) -> list`

DNS query for a domain.

**Parameters:**
- `domain`: Domain name to query
- `record_type`: Record type (A, AAAA, MX, TXT, NS, SOA, etc.)
- `nameserver`: Optional custom nameserver IP

**Returns:** List of DNS record dictionaries

### `propagation(domain: str, record_type: str = "A") -> dict`

DNS propagation check across global nameservers.

**Returns:** Dictionary with:
- `propagation_percentage`: Percentage of servers with consensus
- `servers_checked`: Number of servers queried
- `servers_responding`: Number of servers that responded
- `consensus_values`: Most common record values
- `inconsistencies`: List of inconsistencies
- `results`: Per-server results

### `status(domain: str) -> dict`

Domain health check.

**Returns:** Dictionary with:
- `domain`: Domain name
- `http_status`: HTTP status code
- `http_status_text`: HTTP status text
- `title`: Page title
- `certificate`: SSL certificate info
- `domain_expiration`: Registration expiration info
- `dns_resolution`: DNS resolution info

### Bulk Functions

All bulk functions accept:
- `domains`: List of domain strings
- `concurrency`: Number of concurrent operations (default: 10)

**Returns:** List of result dictionaries with:
- `operation`: Operation details
- `success`: Boolean success flag
- `data`: Result data (if successful)
- `error`: Error message (if failed)
- `duration_ms`: Operation duration in milliseconds

## Examples

### Check Domain Availability

```python
import seer

result = seer.lookup("newdomain.com")
if result.get("source") == "whois":
    whois_data = result.get("data", {})
    if whois_data.get("is_available"):
        print("Domain is available!")
```

### Get Expiration Date

```python
result = seer.lookup("example.com")
if result["source"] == "rdap":
    for event in result["data"].get("events", []):
        if event["event_action"] == "expiration":
            print(f"Expires: {event['event_date']}")
```

### Check SSL Certificate

```python
status = seer.status("example.com")
if cert := status.get("certificate"):
    print(f"SSL Valid: {cert['is_valid']}")
    print(f"Expires: {cert['valid_until']}")
    print(f"Days until expiry: {cert['days_until_expiry']}")
```

### Bulk Domain Check

```python
domains = ["example.com", "google.com", "github.com"]
results = seer.bulk_status(domains, concurrency=3)

for r in results:
    domain = r["operation"]["domain"]
    if r["success"]:
        status = r["data"]
        print(f"{domain}: HTTP {status.get('http_status', 'N/A')}")
    else:
        print(f"{domain}: Error - {r['error']}")
```

## Implementation Details

### Async to Sync Conversion

The Rust core is async, but Python bindings are synchronous. A single Tokio runtime is shared across all calls using `OnceLock`:

```rust
fn get_runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create Tokio runtime")
    })
}
```

### JSON Conversion

Results are serialized to JSON in Rust and converted to Python dictionaries:

```rust
fn json_to_python(py: Python<'_>, value: &serde_json::Value) -> PyResult<PyObject>
```

### Error Handling

Rust errors are converted to Python exceptions:
- `SeerError` → `RuntimeError`
- Invalid arguments → `ValueError`

## Python Version Support

- Minimum: Python 3.9
- Uses ABI3 (stable ABI) for compatibility

## Dependencies

### Rust
- `pyo3` - Python bindings
- `seer-core` - Core library
- `tokio` - Async runtime
- `serde_json` - JSON serialization

### Python
None - pure native extension
