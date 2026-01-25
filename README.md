# Seer

**A multi-interface domain name utility suite for querying WHOIS, RDAP, DNS records, and domain health information.**

Seer provides a unified, high-performance toolkit for domain intelligence with multiple interfaces: CLI, Rust library, Python library, REST API, and MCP server for AI assistants.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Packages Overview](#packages-overview)
- [Installation](#installation)
  - [Installing seer-cli (Binary Only)](#installing-seer-cli-binary-only)
  - [Installing seer-core (Rust Library)](#installing-seer-core-rust-library)
  - [Full Installation (All Components)](#full-installation-all-components)
  - [Python Library Only](#python-library-only)
  - [REST API & MCP Server](#rest-api--mcp-server)
- [Usage](#usage)
  - [CLI](#cli)
  - [Python Library](#python-library)
  - [Rust Library](#rust-library)
  - [REST API](#rest-api)
  - [MCP Server](#mcp-server)
- [Supported DNS Record Types](#supported-dns-record-types)
- [Global DNS Servers](#global-dns-servers)
- [Configuration](#configuration)
- [Development](#development)
- [Project Structure](#project-structure)
- [Technology Stack](#technology-stack)
- [License](#license)

---

## Features

| Feature | Description |
|---------|-------------|
| **WHOIS Lookups** | Query domain registrant and registrar information via WHOIS protocol |
| **RDAP Lookups** | Modern Registration Data Access Protocol for domains, IPs, and ASNs |
| **DNS Resolution** | Query 13 DNS record types with custom nameserver support |
| **DNS Propagation** | Monitor global DNS propagation across 29 nameservers in 6 regions |
| **DNS Monitoring** | Track DNS record changes over time with configurable intervals |
| **Domain Status** | HTTP status, site title, SSL certificate info, and expiration dates |
| **Smart Lookups** | Intelligent fallback: tries RDAP first, then falls back to WHOIS |
| **Bulk Operations** | Process multiple domains concurrently with configurable rate limiting |
| **SSRF Protection** | Blocks requests to private/reserved IP ranges |
| **Multiple Interfaces** | CLI, Rust library, Python library, REST API, and MCP server |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           User Interfaces                                │
├──────────────┬──────────────┬──────────────┬────────────────────────────┤
│   seer-cli   │   seer-py    │   seer-api   │         seer-api           │
│  (Terminal)  │   (Python)   │  (REST API)  │       (MCP Server)         │
└──────┬───────┴──────┬───────┴──────┬───────┴────────────┬───────────────┘
       │              │              │                    │
       │              └──────────────┼────────────────────┘
       │                             │
       ▼                             ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                            seer-core                                      │
│                     (Core Rust Library)                                   │
├────────────┬────────────┬────────────┬────────────┬─────────────────────┤
│   WHOIS    │    RDAP    │    DNS     │   Status   │       Bulk          │
│   Client   │   Client   │  Resolver  │   Client   │     Executor        │
└────────────┴────────────┴────────────┴────────────┴─────────────────────┘
```

---

## Packages Overview

Seer is a monorepo containing four packages. The key distinction to understand:

| Package | Type | Published To | What You Get |
|---------|------|--------------|--------------|
| **seer-core** | Rust library | [crates.io](https://crates.io/crates/seer-core) | Core library for Rust projects — use as a dependency in your Rust code |
| **seer-cli** | Rust binary | [crates.io](https://crates.io/crates/seer-cli) | The `seer` command-line tool — for terminal usage |
| **seer-py** | Python extension | Source only | Python library `seer` — for Python scripts and applications |
| **seer-api** | Python package | Source only | REST API server (`seer-api`) and MCP server (`seer-mcp`) |

### seer-cli vs seer-core

**Choose `seer-cli` if you want:**
- A command-line tool to query domains from your terminal
- An interactive REPL for exploratory domain research
- A binary you can script with shell commands

**Choose `seer-core` if you want:**
- To integrate Seer functionality into your own Rust application
- Programmatic access to WHOIS, RDAP, DNS, and status checking
- Maximum performance and type safety

**Key differences:**

| Aspect | seer-cli | seer-core |
|--------|----------|-----------|
| **What it is** | Executable binary | Rust library (crate) |
| **Install command** | `cargo install seer-cli` | Add to `Cargo.toml` |
| **Usage** | Run `seer` in terminal | Import in Rust code |
| **Provides** | Commands like `seer lookup example.com` | Structs like `WhoisClient`, `DnsResolver` |
| **Depends on** | seer-core internally | Nothing (it's the foundation) |

---

## Installation

### Installing seer-cli (Binary Only)

For command-line usage, install the `seer-cli` crate:

```bash
cargo install seer-cli
```

This installs the `seer` binary to `~/.cargo/bin/`. Verify installation:

```bash
seer --version
seer --help
```

**Requirements:** Rust 1.70+ ([install Rust](https://rustup.rs/))

### Installing seer-core (Rust Library)

To use Seer in your Rust project, add `seer-core` to your `Cargo.toml`:

```toml
[dependencies]
seer-core = "0.1"
tokio = { version = "1", features = ["full"] }
```

Then import and use it:

```rust
use seer_core::{WhoisClient, DnsResolver, RecordType};

#[tokio::main]
async fn main() -> seer_core::Result<()> {
    let client = WhoisClient::new();
    let result = client.lookup("example.com").await?;
    println!("Registrar: {:?}", result.registrar);
    Ok(())
}
```

See the [Rust Library Usage](#rust-library) section for detailed examples.

### Full Installation (All Components)

To install everything (CLI + Python library + REST API + MCP server):

```bash
# Clone the repository
git clone https://github.com/TheZacillac/seer.git
cd seer

# Install CLI to PATH
cargo install --path seer-cli

# Install maturin (builds Python extensions from Rust)
uv pip install maturin

# Build and install Python bindings
cd seer-py
maturin develop --release
cd ..

# Install REST API and MCP server
cd seer-api
uv pip install -e .
cd ..
```

After installation, you'll have access to:
- `seer` — CLI tool
- `seer-api` — REST API server
- `seer-mcp` — MCP server for AI assistants
- `import seer` — Python library

**Requirements:**
- Rust 1.70+
- Python 3.9+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

### Python Library Only

```bash
# Clone and navigate to seer-py
git clone https://github.com/TheZacillac/seer.git
cd seer/seer-py

# Install maturin and build
uv pip install maturin
maturin develop --release
```

Or build a distributable wheel:

```bash
maturin build --release
uv pip install target/wheels/seer-*.whl
```

### REST API & MCP Server

> **Prerequisite:** The Python library must be installed first (see above).

```bash
cd seer-api
uv pip install -e .
```

This provides two commands:
- `seer-api` — Start the REST API server
- `seer-mcp` — Start the MCP server

---

## Usage

### CLI

The CLI offers two modes: **command mode** for scripts/one-off queries, and **interactive REPL** for exploratory work.

#### Command Mode

```bash
# Smart lookup (RDAP with WHOIS fallback)
seer lookup example.com

# WHOIS lookup
seer whois example.com

# RDAP lookups
seer rdap example.com          # Domain
seer rdap 8.8.8.8              # IP address
seer rdap AS15169              # ASN

# DNS queries
seer dig example.com           # A records (default)
seer dig example.com MX        # MX records
seer dig example.com A @8.8.8.8  # Custom nameserver

# DNS propagation check
seer propagation example.com A

# Domain status check (HTTP, SSL, expiration)
seer status example.com

# DNS monitoring over time
seer follow example.com              # 10 iterations, 1 min interval
seer follow example.com 20 0.5       # 20 iterations, 30 sec interval
seer follow example.com 10 1 MX --changes-only  # Only show changes

# Bulk operations
seer bulk lookup domains.txt
seer bulk whois domains.txt
seer bulk dig domains.txt A
seer bulk status domains.txt
seer bulk status domains.txt -o results.csv  # Export to CSV
```

#### Output Formats

```bash
seer lookup example.com --format human  # Human-readable (default)
seer lookup example.com --format json   # JSON output
```

#### Interactive REPL

Launch by running `seer` without arguments:

```bash
$ seer
seer> lookup example.com
seer> whois google.com
seer> dig github.com MX
seer> status cloudflare.com
seer> set output json
seer> help
seer> exit
```

**REPL features:**
- Command history (saved to `~/.seer_history`)
- Tab completion for commands
- Loading spinners during operations
- Persistent session state

### Python Library

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

# DNS queries
dns = seer.dig("example.com", record_type="A")
dns = seer.dig("example.com", record_type="MX", nameserver="8.8.8.8")

# DNS propagation
propagation = seer.propagation("example.com", record_type="A")

# Domain status (HTTP, SSL, expiration)
status = seer.status("example.com")

# Bulk operations
results = seer.bulk_lookup(["example.com", "google.com"], concurrency=10)
results = seer.bulk_whois(["example.com", "google.com"])
results = seer.bulk_dig(["example.com", "google.com"], record_type="A")
results = seer.bulk_status(["example.com", "google.com"])
```

#### Example: Check SSL Certificate

```python
status = seer.status("example.com")
if cert := status.get("certificate"):
    print(f"SSL Valid: {cert['is_valid']}")
    print(f"Expires: {cert['valid_until']}")
    print(f"Days until expiry: {cert['days_until_expiry']}")
```

### Rust Library

Add to `Cargo.toml`:

```toml
[dependencies]
seer-core = "0.1"
tokio = { version = "1", features = ["full"] }
```

#### Smart Lookup

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

#### DNS Resolution

```rust
use seer_core::{DnsResolver, RecordType};

#[tokio::main]
async fn main() -> seer_core::Result<()> {
    let resolver = DnsResolver::new();
    let records = resolver.resolve("example.com", RecordType::A, None).await?;

    for record in records {
        println!("{}: {}", record.record_type, record.data);
    }
    Ok(())
}
```

#### Domain Status Check

```rust
use seer_core::StatusClient;

#[tokio::main]
async fn main() -> seer_core::Result<()> {
    let client = StatusClient::new();
    let status = client.check("example.com").await?;

    println!("HTTP Status: {:?}", status.http_status);
    println!("SSL Valid: {:?}", status.certificate.map(|c| c.is_valid));
    Ok(())
}
```

See [seer-core/README.md](seer-core/README.md) for complete API documentation.

### REST API

Start the server:

```bash
seer-api
```

The API runs on `http://localhost:8000` with auto-reload enabled.

#### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | List available endpoints |
| `/health` | GET | Health check |
| `/lookup/{domain}` | GET | Smart lookup |
| `/lookup/bulk` | POST | Bulk smart lookups |
| `/whois/{domain}` | GET | WHOIS lookup |
| `/rdap/domain/{domain}` | GET | RDAP domain lookup |
| `/rdap/ip/{ip}` | GET | RDAP IP lookup |
| `/rdap/asn/{asn}` | GET | RDAP ASN lookup |
| `/dns/{domain}/{record_type}` | GET | DNS query |
| `/propagation/{domain}/{record_type}` | GET | DNS propagation check |
| `/status/{domain}` | GET | Domain status check |
| `/status/bulk` | POST | Bulk status checks |

#### Examples

```bash
# Smart lookup
curl http://localhost:8000/lookup/example.com

# DNS query
curl http://localhost:8000/dns/example.com/MX

# Bulk lookup
curl -X POST http://localhost:8000/lookup/bulk \
  -H "Content-Type: application/json" \
  -d '{"domains": ["example.com", "google.com"]}'
```

API documentation available at:
- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc

### MCP Server

Start the MCP server for AI assistant integration:

```bash
seer-mcp
```

#### Available Tools

| Tool | Description |
|------|-------------|
| `seer_lookup` | Smart domain lookup (RDAP/WHOIS) |
| `seer_whois` | WHOIS lookup |
| `seer_rdap_domain` | RDAP domain lookup |
| `seer_rdap_ip` | RDAP IP lookup |
| `seer_rdap_asn` | RDAP ASN lookup |
| `seer_dig` | DNS query |
| `seer_propagation` | DNS propagation check |
| `seer_status` | Domain status check |
| `seer_bulk_lookup` | Bulk smart lookups |
| `seer_bulk_whois` | Bulk WHOIS lookups |
| `seer_bulk_dig` | Bulk DNS queries |
| `seer_bulk_status` | Bulk status checks |

#### Claude Desktop Integration

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "seer": {
      "command": "seer-mcp"
    }
  }
}
```

---

## Supported DNS Record Types

| Type | Description |
|------|-------------|
| `A` | IPv4 address |
| `AAAA` | IPv6 address |
| `MX` | Mail exchange |
| `TXT` | Text records |
| `NS` | Nameserver |
| `SOA` | Start of authority |
| `CNAME` | Canonical name |
| `CAA` | Certification authority authorization |
| `PTR` | Pointer record |
| `SRV` | Service locator |
| `DNSKEY` | DNSSEC public key |
| `DS` | Delegation signer (DNSSEC) |
| `ANY` | All available records |

---

## Global DNS Servers

Propagation checks query 29 nameservers across 6 regions:

| Region | Nameservers |
|--------|-------------|
| **North America** | Google (8.8.8.8), Cloudflare (1.1.1.1), OpenDNS (208.67.222.222), Quad9 (9.9.9.9), Level3 (4.2.2.1) |
| **Europe** | DNS.Watch (84.200.69.80), Mullvad (194.242.2.2), dns0.eu (193.110.81.0), Yandex (77.88.8.8), UncensoredDNS (91.239.100.100) |
| **Asia Pacific** | AliDNS (223.5.5.5), 114DNS (114.114.114.114), Tencent DNSPod (119.29.29.29), TWNIC (101.101.101.101), HiNet (168.95.1.1) |
| **Latin America** | Claro Brasil, Telefonica Brasil, Antel Uruguay, Telmex Mexico, CenturyLink LATAM |
| **Africa** | Liquid Telecom, SEACOM, Safaricom Kenya, MTN South Africa, Telecom Egypt |
| **Middle East** | Etisalat UAE, STC Saudi, Bezeq Israel, Turk Telekom, Ooredoo Qatar |

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `RUST_LOG` | Logging level (`trace`, `debug`, `info`, `warn`, `error`) | — |
| `SEER_CORS_ORIGINS` | Comma-separated CORS origins for REST API | `*` (all) |
| `SEER_RATE_LIMIT` | Rate limit for REST API (requests/minute) | `30` |

### Timeouts

All clients support configurable timeouts:

| Client | Default Timeout |
|--------|-----------------|
| WHOIS | 10 seconds |
| RDAP | 30 seconds |
| DNS | 5 seconds (with 2 retries) |
| HTTP/SSL | 10 seconds |

### Bulk Operations

- **Input formats:** Plain text (one domain per line), CSV (uses first column)
- **Comments:** Lines starting with `#` are ignored
- **Default concurrency:** 10
- **Maximum concurrency:** 50
- **Maximum domains per API request:** 100

---

## Development

### Building

```bash
# Build all Rust packages
cargo build --release

# Build Python bindings
cd seer-py && maturin develop --release

# Install API package
cd seer-api && pip install -e .
```

### Running Tests

```bash
# Rust tests
cargo test

# Python tests
cd seer-api && pytest
```

### Logging

Enable debug logging:

```bash
RUST_LOG=debug seer lookup example.com
```

---

## Project Structure

```
seer/
├── README.md               # This file
├── Cargo.toml              # Workspace configuration
├── seer-core/              # Core Rust library (all business logic)
│   ├── README.md
│   └── src/
│       ├── lib.rs          # Module exports
│       ├── error.rs        # Error types
│       ├── lookup.rs       # Smart lookup (RDAP → WHOIS fallback)
│       ├── validation.rs   # Domain validation & SSRF protection
│       ├── colors.rs       # Catppuccin color palette
│       ├── whois/          # WHOIS client and parser
│       ├── rdap/           # RDAP client with IANA bootstrap
│       ├── dns/            # DNS resolver, propagation, and follow
│       ├── status/         # Domain status checker
│       ├── bulk/           # Bulk operation executor
│       └── output/         # Output formatters (human/JSON)
│
├── seer-cli/               # CLI application
│   ├── README.md
│   └── src/
│       ├── main.rs         # Entry point with clap commands
│       ├── display/        # Spinner and display utilities
│       └── repl/           # Interactive REPL
│
├── seer-py/                # Python bindings (PyO3)
│   ├── README.md
│   ├── pyproject.toml      # Maturin build config
│   └── src/lib.rs          # Python module definitions
│
└── seer-api/               # FastAPI REST server + MCP
    ├── README.md
    └── seer_api/
        ├── main.py         # FastAPI app
        ├── routers/        # API endpoints
        └── mcp/            # MCP server
```

---

## Technology Stack

### Core (Rust)

| Dependency | Purpose |
|------------|---------|
| Tokio | Async runtime |
| Reqwest | HTTP client (rustls-tls) |
| Hickory-resolver | DNS resolution with DNSSEC |
| Serde | Serialization |

### CLI

| Dependency | Purpose |
|------------|---------|
| Clap | Command-line parsing |
| Rustyline | REPL line editing |
| Indicatif | Progress indicators |
| Colored | Terminal colors |

### Python

| Dependency | Purpose |
|------------|---------|
| PyO3 | Rust/Python bindings |
| FastAPI | REST API framework |
| Pydantic | Data validation |
| MCP | Model Context Protocol |

### Data Sources

- WHOIS server list sourced from [WooMai/whois-servers](https://github.com/WooMai/whois-servers) (auto-synced with IANA Root Zone Database)

---

## License

MIT License

Copyright (c) 2026 Zac Roach

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
