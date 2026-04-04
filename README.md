<div align="center">

# 🔮 Seer

**Domain intelligence at your fingertips.**

A high-performance, multi-interface domain utility suite — query WHOIS, RDAP, DNS, SSL, and more from the terminal, Python, REST API, or AI assistants.

[![CI](https://github.com/TheZacillac/seer/actions/workflows/ci.yml/badge.svg)](https://github.com/TheZacillac/seer/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/seer-cli.svg)](https://crates.io/crates/seer-cli)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org)

[Features](#-features) · [Quick Start](#-quick-start) · [CLI Usage](#-cli-usage) · [Python](#-python-library) · [REST API](#-rest-api) · [MCP Server](#-mcp-server)

</div>

---

## ✨ Features

<table>
<tr>
<td width="50%">

**🔍 Lookups & Discovery**
- **Smart Lookup** — concurrent RDAP + WHOIS with fallback
- **WHOIS** — registrant, registrar, and expiration data
- **RDAP** — modern protocol for domains, IPs, and ASNs
- **Domain Info** — merged RDAP + WHOIS in a flat structure
- **Reverse DNS** — PTR lookups for IP addresses
- **TLD Info** — WHOIS server, RDAP endpoint, and registry
- **Subdomain Enumeration** — via Certificate Transparency logs
- **Domain Availability** — check if a domain is registered

</td>
<td width="50%">

**🌐 DNS & Propagation**
- **DNS Resolution** — 13 record types with custom nameservers
- **DNS Propagation** — 29 servers across 6 global regions
- **DNS Monitoring** — track record changes over time
- **DNS Comparison** — compare records across two nameservers
- **DNSSEC Validation** — check DNSSEC configuration

</td>
</tr>
<tr>
<td>

**🛡️ Security & Health**
- **Domain Status** — HTTP status, title, SSL, and expiration
- **SSL Chain Inspection** — full chain, SANs, key details, validity
- **Domain Watchlist** — monitor expiring certs and registrations
- **SSRF Protection** — blocks requests to private/reserved IPs

</td>
<td>

**⚡ Power Features**
- **Bulk Operations** — process domain lists with CSV export
- **Domain Diff** — side-by-side comparison of two domains
- **Field Extraction** — `--quiet --fields` for scriptable output
- **4 Output Formats** — human, JSON, YAML, markdown
- **Interactive REPL** — with tab completion and history
- **Semantic Exit Codes** — for CI/CD scripting
- **Shell Completions** — bash, zsh, fish, PowerShell

</td>
</tr>
</table>

### 🏗️ Five Interfaces, One Core

```
┌──────────────────────────────────────────────────────────────────┐
│                        User Interfaces                           │
├─────────────┬─────────────┬──────────────┬───────────────────────┤
│  seer-cli   │   seer-py   │   seer-api   │       seer-api        │
│  Terminal   │   Python    │   REST API   │     MCP Server        │
└──────┬──────┴──────┬──────┴──────┬───────┴──────────┬────────────┘
       │             │             │                   │
       │             └─────────────┼───────────────────┘
       │                           │
       ▼                           ▼
┌──────────────────────────────────────────────────────────────────┐
│                          seer-core                                │
│                      Core Rust Library                            │
├──────────┬────────┬──────┬────────┬──────┬──────┬───────────────┤
│  WHOIS   │  RDAP  │ DNS  │ Status │ SSL  │ Bulk │  Diff/Watch   │
└──────────┴────────┴──────┴────────┴──────┴──────┴───────────────┘
```

---

## 🚀 Quick Start

### Install the CLI

```bash
cargo install seer-cli
```

### Run your first lookup

```bash
seer lookup example.com        # Smart RDAP + WHOIS lookup
seer dig example.com MX        # DNS query
seer status example.com        # HTTP, SSL, and expiration check
seer ssl example.com           # Full SSL chain inspection
seer                           # Launch interactive REPL
```

### Use as a Rust library

```toml
[dependencies]
seer-core = "0.18"
tokio = { version = "1", features = ["full"] }
```

> **Requirements:** Rust 1.70+ · Python 3.9+ (for Python bindings/API)

---

## 📦 Packages

| Package | Type | Install | Description |
|---------|------|---------|-------------|
| **seer-core** | Rust library | `cargo add seer-core` | Core library — all business logic |
| **seer-cli** | Rust binary | `cargo install seer-cli` | The `seer` command-line tool |
| **seer-py** | Python extension | `maturin develop --release` | Python bindings via PyO3 |
| **seer-api** | Python package | `pip install -e .` | REST API + MCP server |

<details>
<summary><b>seer-cli vs seer-core — which do I need?</b></summary>

| | seer-cli | seer-core |
|---|----------|-----------|
| **What** | Executable binary | Rust library crate |
| **Install** | `cargo install seer-cli` | `cargo add seer-core` |
| **Use** | Run `seer` in your terminal | `use seer_core::*` in Rust code |
| **Provides** | Commands, REPL, formatted output | Structs, clients, async APIs |
| **Depends on** | seer-core internally | Nothing — it's the foundation |

</details>

---

## 💻 CLI Usage

### Command Mode

```bash
# Smart lookup (concurrent RDAP + WHOIS)
seer lookup example.com

# Comprehensive domain info (merged RDAP + WHOIS)
seer info example.com

# WHOIS / RDAP
seer whois example.com
seer rdap example.com           # Domain
seer rdap 8.8.8.8               # IP address
seer rdap AS15169               # ASN

# DNS queries
seer dig example.com             # A records (default)
seer dig example.com MX          # Specific record type
seer dig example.com A -s 8.8.8.8  # Custom nameserver

# DNS propagation & monitoring
seer prop example.com A
seer follow example.com 20 0.5       # 20 checks, 30s interval
seer follow example.com 10 1 MX --changes-only

# DNSSEC & DNS comparison
seer dnssec example.com
seer compare example.com A 8.8.8.8 1.1.1.1

# Domain health & SSL
seer status example.com
seer ssl example.com

# Reverse DNS
seer reverse 8.8.8.8

# Discovery
seer avail example.com
seer subdomains example.com
seer tld .com

# Domain diff
seer diff example.com google.com

# Watchlist
seer watch add example.com
seer watch list
seer watch                        # Check all watched domains
seer watch remove example.com

# Lookup history
seer history example.com
seer history --clear

# Bulk operations (with CSV export)
seer bulk lookup domains.txt
seer bulk status domains.txt -o results.csv
seer bulk dig domains.txt MX
seer bulk avail domains.txt
seer bulk info domains.txt

# Scriptable field extraction
seer --quiet --fields registrar lookup example.com
seer --quiet --fields certificate.issuer status example.com

# Shell completions
seer completions bash >> ~/.bashrc
seer completions zsh >> ~/.zshrc
```

### Output Formats

```bash
seer --format human lookup example.com      # Colored, human-readable (default)
seer --format json lookup example.com       # JSON
seer --format yaml lookup example.com       # YAML
seer --format markdown lookup example.com   # Markdown table
```

### Interactive REPL

Launch by running `seer` with no arguments:

```
$ seer
seer> lookup example.com
seer> dig github.com MX
seer> status cloudflare.com
seer> set output json
seer> help
seer> exit
```

Features: command history (`~/.seer_history`), tab completion, loading spinners, persistent session state.

---

## 🐍 Python Library

```python
import seer

# Smart lookup
result = seer.lookup("example.com")

# WHOIS / RDAP
whois = seer.whois("example.com")
rdap  = seer.rdap_domain("example.com")
rdap  = seer.rdap_ip("8.8.8.8")
rdap  = seer.rdap_asn(15169)

# DNS
records     = seer.dig("example.com", record_type="MX")
propagation = seer.propagation("example.com", record_type="A")

# Domain health & SSL
status = seer.status("example.com")
ssl    = seer.ssl("example.com")
dnssec = seer.dnssec("example.com")

# Availability & info
available = seer.availability("example.com")
info      = seer.info("example.com")

# Comparison & enumeration
diff       = seer.diff("example.com", "google.com")
comparison = seer.dns_compare("example.com", "A", "8.8.8.8", "1.1.1.1")
subdomains = seer.subdomains("example.com")

# Bulk operations
results = seer.bulk_lookup(["example.com", "google.com"], concurrency=10)
results = seer.bulk_status(["example.com", "google.com"])
results = seer.bulk_dig(["example.com", "google.com"], record_type="A")
results = seer.bulk_info(["example.com", "google.com"])
```

<details>
<summary><b>Example: Check SSL Certificate</b></summary>

```python
status = seer.status("example.com")
if cert := status.get("certificate"):
    print(f"SSL Valid: {cert['is_valid']}")
    print(f"Expires:   {cert['valid_until']}")
    print(f"Days left: {cert['days_until_expiry']}")
```

</details>

---

## 🦀 Rust Library

```toml
[dependencies]
seer-core = "0.18"
tokio = { version = "1", features = ["full"] }
```

```rust
use seer_core::{SmartLookup, DnsResolver, RecordType, StatusClient};

#[tokio::main]
async fn main() -> seer_core::Result<()> {
    // Smart lookup (RDAP → WHOIS fallback)
    let lookup = SmartLookup::new();
    let result = lookup.lookup("example.com").await?;

    // DNS resolution
    let resolver = DnsResolver::new();
    let records = resolver.resolve("example.com", RecordType::MX, None).await?;
    for record in records {
        println!("{}: {}", record.record_type, record.data);
    }

    // Domain status check
    let client = StatusClient::new();
    let status = client.check("example.com").await?;
    println!("HTTP: {:?}", status.http_status);

    Ok(())
}
```

See [seer-core/README.md](seer-core/README.md) for the full API reference.

---

## 🌍 REST API

```bash
seer-api   # Starts on http://localhost:8000
```

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/lookup/{domain}` | GET | Smart lookup (RDAP + WHOIS) |
| `/lookup/bulk` | POST | Bulk smart lookups |
| `/whois/{domain}` | GET | WHOIS lookup |
| `/rdap/domain/{domain}` | GET | RDAP domain lookup |
| `/rdap/ip/{ip}` | GET | RDAP IP lookup |
| `/rdap/asn/{asn}` | GET | RDAP ASN lookup |
| `/dns/{domain}/{record_type}` | GET | DNS query |
| `/dns/bulk` | POST | Bulk DNS queries |
| `/propagation/{domain}/{record_type}` | GET | DNS propagation check |
| `/propagation/bulk` | POST | Bulk propagation checks |
| `/status/{domain}` | GET | Domain status check |
| `/status/bulk` | POST | Bulk status checks |
| `/health` | GET | Health check |

```bash
# Examples
curl http://localhost:8000/lookup/example.com
curl http://localhost:8000/dns/example.com/MX
curl -X POST http://localhost:8000/lookup/bulk \
  -H "Content-Type: application/json" \
  -d '{"domains": ["example.com", "google.com"]}'
```

API docs: [Swagger UI](http://localhost:8000/docs) · [ReDoc](http://localhost:8000/redoc)

---

## 🤖 MCP Server

Integrate Seer with AI assistants via the [Model Context Protocol](https://modelcontextprotocol.io/):

```bash
seer-mcp   # Runs on stdio transport
```

**16 tools available:**

| Tool | Description |
|------|-------------|
| `seer_lookup` | Smart domain lookup |
| `seer_info` | Comprehensive domain info |
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
| `seer_bulk_propagation` | Bulk propagation checks |
| `seer_bulk_info` | Bulk domain info |

<details>
<summary><b>Claude Desktop configuration</b></summary>

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

</details>

---

## 📡 DNS Record Types

| Type | Description | | Type | Description |
|------|-------------|---|------|-------------|
| `A` | IPv4 address | | `CAA` | CA authorization |
| `AAAA` | IPv6 address | | `PTR` | Pointer record |
| `MX` | Mail exchange | | `SRV` | Service locator |
| `TXT` | Text records | | `DNSKEY` | DNSSEC public key |
| `NS` | Nameserver | | `DS` | Delegation signer |
| `SOA` | Start of authority | | `ANY` | All records |
| `CNAME` | Canonical name | | | |

---

## 🌏 Global DNS Propagation Servers

Propagation checks query **29 nameservers** across **6 regions**:

| Region | Servers |
|--------|---------|
| 🇺🇸 **North America** | Google `8.8.8.8` · Cloudflare `1.1.1.1` · OpenDNS · Quad9 · Level3 |
| 🇪🇺 **Europe** | DNS.Watch · Mullvad · dns0.eu · Yandex · UncensoredDNS |
| 🌏 **Asia Pacific** | AliDNS · 114DNS · Tencent DNSPod · TWNIC · HiNet |
| 🌎 **Latin America** | Claro Brasil · Telefonica Brasil · Antel Uruguay · Telmex · CenturyLink |
| 🌍 **Africa** | Liquid Telecom · SEACOM · Safaricom · MTN South Africa · Telecom Egypt |
| 🌐 **Middle East** | Etisalat UAE · STC Saudi · Bezeq Israel · Turk Telekom · Ooredoo Qatar |

---

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `RUST_LOG` | Logging level (`trace` / `debug` / `info` / `warn` / `error`) | — |
| `SEER_CORS_ORIGINS` | Comma-separated CORS origins for REST API | `*` |
| `SEER_RATE_LIMIT` | REST API rate limit (requests/minute) | `30` |

### Config File

Initialize a config file at `~/.seer/config.toml`:

```bash
seer config --init
```

### Timeouts

| Client | Default |
|--------|---------|
| WHOIS | 10s |
| RDAP | 30s |
| DNS | 5s (2 retries) |
| HTTP / SSL | 10s |
| Propagation | 15s |

### Bulk Operations

- **Input:** plain text (one domain per line) or CSV (first column)
- **Comments:** lines starting with `#` are skipped
- **Concurrency:** default 10, max 50
- **API limit:** max 100 domains per request

---

## 🔮 Roadmap

- **Scheduled Monitoring Daemon** — `seer monitor --config monitors.toml` as a background service with notifications (email, Slack, PagerDuty) for expiring domains, SSL certificates, and unexpected DNS changes. The natural evolution of `watch`, `follow`, and `status` into persistent monitoring.

---

## 🛠️ Development

### Building

```bash
cargo build --release                        # All Rust packages
cd seer-py && maturin develop --release      # Python bindings
cd seer-api && pip install -e .              # REST API + MCP server
```

### Testing

```bash
cargo test                    # All Rust tests
cargo test -p seer-core       # Core library only
cd seer-api && pytest         # Python API tests
RUST_LOG=debug cargo test     # With debug logging
```

### Linting

```bash
cargo fmt --all -- --check    # Format check
cargo clippy -- -D warnings   # Lint
```

### Project Structure

```
seer/
├── Cargo.toml                # Workspace root
├── seer-core/                # Core Rust library (all business logic)
│   └── src/
│       ├── lib.rs            # Module exports
│       ├── error.rs          # Centralized error types
│       ├── lookup.rs         # Smart lookup (RDAP + WHOIS)
│       ├── validation.rs     # Domain validation & SSRF protection
│       ├── config.rs         # Configuration management
│       ├── whois/            # WHOIS client, parser, server mapping
│       ├── rdap/             # RDAP client with IANA bootstrap
│       ├── dns/              # Resolver, propagation, DNSSEC, follow
│       ├── ssl/              # SSL certificate chain inspection
│       ├── status/           # HTTP, SSL, and expiration checking
│       ├── bulk/             # Concurrent bulk executor
│       ├── diff/             # Domain comparison
│       ├── availability/     # Domain availability checking
│       ├── subdomains/       # CT log enumeration
│       ├── tld/              # TLD information
│       ├── watchlist/        # Domain monitoring
│       ├── history/          # Lookup history tracking
│       ├── domain_info/      # Flat domain info structure
│       ├── cache/            # TTL and single-value caching
│       ├── retry/            # Network retry with classification
│       ├── logging/          # Structured logging + OpenTelemetry
│       ├── output/           # Formatters (human/JSON/YAML/markdown)
│       └── colors.rs         # Catppuccin color palette
│
├── seer-cli/                 # CLI application
│   └── src/
│       ├── main.rs           # Clap commands & dispatch
│       ├── display/          # Spinner and progress utilities
│       └── repl/             # Interactive REPL
│
├── seer-py/                  # Python bindings (PyO3)
│   ├── src/lib.rs            # Rust → Python bridge
│   └── python/seer/          # Python package wrapper
│
└── seer-api/                 # FastAPI REST server + MCP
    └── seer_api/
        ├── main.py           # FastAPI app
        ├── routers/          # API endpoint modules
        └── mcp/              # MCP server (16 tools)
```

---

## 🔧 Technology Stack

| Layer | Technologies |
|-------|-------------|
| **Core** | Rust · Tokio · Reqwest (rustls) · Hickory-resolver (DNSSEC) · Serde · OpenTelemetry |
| **CLI** | Clap v4 · Rustyline · Indicatif · Colored · Crossterm |
| **Python** | PyO3 (ABI3) · FastAPI · Pydantic · MCP |
| **Data** | WHOIS servers from [WooMai/whois-servers](https://github.com/WooMai/whois-servers) · IANA RDAP bootstrap |

---

## 📄 License

MIT License — Copyright (c) 2026 Zac Roach

See [LICENSE](LICENSE) for the full text.
