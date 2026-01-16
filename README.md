# Seer

A multi-interface domain name utility tool for querying domain registration information, DNS records, and network data. Seer provides a unified interface across CLI, Python library, REST API, and MCP (Model Context Protocol) server.

## Features

- **WHOIS Lookups** - Query domain registrant and registrar information
- **RDAP Lookups** - Modern Registration Data Access Protocol queries for domains, IPs, and ASNs
- **DNS Resolution** - Query DNS records (A, AAAA, MX, TXT, NS, SOA, CNAME, CAA, PTR, SRV, DNSKEY, DS)
- **DNS Propagation Checking** - Monitor global DNS propagation across multiple nameservers
- **Domain Status** - Quick health check: HTTP status, site title, SSL certificate info, expiration dates
- **Smart Lookups** - Intelligent fallback that tries RDAP first, then falls back to WHOIS
- **Bulk Operations** - Process multiple domains/queries concurrently with rate limiting
- **Multiple Interfaces** - CLI, Python library, REST API, and MCP server

## Installation

### Prerequisites

- [Rust](https://rustup.rs/) 1.70+ (required for CLI and building Python bindings)
- Python 3.9+ (required for Python library, REST API, and MCP server)
- [uv](https://docs.astral.sh/uv/) (recommended Python package manager)

### CLI Only

Install from [crates.io](https://crates.io/crates/seer-cli):

```bash
cargo install seer-cli
```

This installs the `seer` binary to `~/.cargo/bin/`, which is typically already in your PATH if you have Rust installed.

### Full Installation (CLI + Python Library + REST API + MCP Server)

```bash
# Clone the repository
git clone https://github.com/TheZacillac/seer.git
cd seer

# Install CLI to PATH
cargo install --path seer-cli

# Install maturin (needed to build Python bindings)
uv pip install maturin

# Build and install Python bindings (required before installing the API)
cd seer-py
maturin develop --release
cd ..

# Install REST API and MCP server
cd seer-api
uv pip install -e .
cd ..
```

After installation, you'll have access to:
- `seer` - CLI tool
- `seer-api` - REST API server
- `seer-mcp` - MCP server for AI assistants

### Individual Components

#### Python Library Only

```bash
git clone https://github.com/TheZacillac/seer.git
cd seer/seer-py
uv pip install maturin
maturin develop --release
```

Or build a wheel for distribution:

```bash
maturin build --release
uv pip install target/wheels/seer-*.whl
```

#### REST API & MCP Server

> **Note:** The Python library must be installed first (see above).

```bash
cd seer-api
uv pip install -e .
```

This provides two commands:
- `seer-api` - Start the REST API server
- `seer-mcp` - Start the MCP server

## Usage

### CLI

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

# Bulk operations
seer bulk lookup domains.txt
seer bulk whois domains.txt
seer bulk dig domains.txt A
seer bulk status domains.txt
```

#### Output Formats

```bash
# Human-readable output (default)
seer lookup example.com --format human

# JSON output
seer lookup example.com --format json
```

#### Interactive REPL

Launch the interactive shell by running `seer` without arguments:

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

REPL features:
- Command history (saved to `~/.seer_history`)
- Tab completion
- Loading spinners for long operations

### Python Library

```python
import seer

# Smart lookup
result = seer.lookup("example.com")

# WHOIS lookup
whois = seer.whois("example.com")

# RDAP lookups
rdap_domain = seer.rdap_domain("example.com")
rdap_ip = seer.rdap_ip("8.8.8.8")
rdap_asn = seer.rdap_asn("AS15169")

# DNS queries
dns = seer.dig("example.com", record_type="A")
dns_custom = seer.dig("example.com", record_type="MX", nameserver="8.8.8.8")

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
| `/propagation/{domain}/{record_type}` | GET | Propagation check |
| `/status/{domain}` | GET | Domain status check |
| `/status/bulk` | POST | Bulk status checks |

#### Examples

```bash
# Smart lookup
curl http://localhost:8000/lookup/example.com

# WHOIS lookup
curl http://localhost:8000/whois/example.com

# DNS query
curl http://localhost:8000/dns/example.com/MX

# Domain status
curl http://localhost:8000/status/example.com

# Bulk lookup
curl -X POST http://localhost:8000/lookup/bulk \
  -H "Content-Type: application/json" \
  -d '{"domains": ["example.com", "google.com"]}'
```

API documentation is available at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

#### CORS Configuration

Set allowed origins via environment variable:

```bash
export SEER_CORS_ORIGINS="https://example.com,https://app.example.com"
seer-api
```

### MCP Server

Start the MCP server for AI assistant integration:

```bash
seer-mcp
```

The MCP server exposes these tools:
- `seer_lookup` - Smart domain lookup
- `seer_whois` - WHOIS lookup
- `seer_rdap_domain` / `seer_rdap_ip` / `seer_rdap_asn` - RDAP lookups
- `seer_dig` - DNS queries
- `seer_propagation` - Propagation checking
- `seer_status` - Domain status (HTTP, SSL, expiration)
- `seer_bulk_lookup` / `seer_bulk_whois` / `seer_bulk_dig` / `seer_bulk_status` - Bulk operations

## Project Structure

```
seer/
├── seer-core/          # Core Rust library
│   └── src/
│       ├── lib.rs      # Module exports
│       ├── error.rs    # Error types
│       ├── lookup.rs   # Smart lookup implementation
│       ├── bulk/       # Bulk operation executor
│       ├── dns/        # DNS resolver and propagation
│       ├── whois/      # WHOIS client and parser
│       ├── rdap/       # RDAP client
│       ├── status/     # Domain status checker
│       └── output/     # Output formatters
│
├── seer-cli/           # CLI application
│   └── src/
│       ├── main.rs     # Entry point with clap commands
│       ├── display/    # Spinner and display utilities
│       └── repl/       # Interactive REPL
│
├── seer-py/            # Python bindings (PyO3)
│   ├── pyproject.toml  # Maturin build config
│   └── src/lib.rs      # Python module definitions
│
└── seer-api/           # FastAPI REST server + MCP
    └── seer_api/
        ├── main.py     # FastAPI app
        ├── routers/    # API endpoints
        └── mcp/        # MCP server
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `RUST_LOG` | Logging level (trace, debug, info, warn, error) | - |
| `SEER_CORS_ORIGINS` | Comma-separated list of allowed CORS origins | `*` (all) |

### Bulk Operations

Bulk operations support:
- Plain text files (one domain per line)
- Comments (lines starting with `#`)
- CSV files (uses first column)

Default concurrency: 10 (max: 50)

## Supported DNS Record Types

- `A` - IPv4 address
- `AAAA` - IPv6 address
- `MX` - Mail exchange
- `TXT` - Text records
- `NS` - Nameserver
- `SOA` - Start of authority
- `CNAME` - Canonical name
- `CAA` - Certification authority authorization
- `PTR` - Pointer record
- `SRV` - Service locator
- `DNSKEY` - DNSSEC public key
- `DS` - Delegation signer (DNSSEC)
- `ANY` - All available records

## Global DNS Servers for Propagation Checks

Propagation checks query these nameservers:
- Google DNS (8.8.8.8, 8.8.4.4)
- Cloudflare DNS (1.1.1.1, 1.0.0.1)
- OpenDNS (208.67.222.222, 208.67.220.220)
- Quad9 (9.9.9.9)
- Level3 (4.2.2.1, 4.2.2.2)
- Comodo (8.26.56.26)
- DNS.Watch (84.200.69.80)

## Development

### Prerequisites

- Rust 1.70+
- Python 3.9+
- [maturin](https://github.com/PyO3/maturin) (for Python bindings)

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

## Technology Stack

**Core (Rust)**
- Tokio - Async runtime
- Reqwest - HTTP client
- Hickory-resolver - DNS resolution
- Serde - Serialization

**CLI**
- Clap - Command-line parsing
- Rustyline - REPL line editing
- Indicatif - Progress indicators
- Colored - Terminal colors

**Python**
- PyO3 - Rust/Python bindings
- FastAPI - REST API framework
- Pydantic - Data validation
- MCP - Model Context Protocol

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
