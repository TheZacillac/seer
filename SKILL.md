# Seer - Domain Name Utility

## What is Seer?

Seer is a domain intelligence toolkit for querying WHOIS, RDAP, DNS, and domain health information. It provides a CLI with an interactive REPL, a Rust library, Python bindings, a REST API, and an MCP server.

## Quick Start

```bash
# Install
cargo install seer-cli

# Or run from source
cargo run --release -p seer-cli -- <command>
```

## CLI Commands

### Lookup Commands

```bash
# Smart lookup (concurrent RDAP + WHOIS, availability fallback)
seer lookup example.com

# WHOIS only
seer whois example.com

# RDAP (domains, IPs, ASNs)
seer rdap example.com
seer rdap 8.8.8.8
seer rdap AS15169
```

### DNS Commands

```bash
# Query DNS records (default: A)
seer dig example.com
seer dig example.com MX
seer dig example.com A -s @8.8.8.8    # Custom nameserver

# Check DNS propagation across 29 global servers
seer prop example.com
seer prop example.com AAAA

# Compare DNS records across two nameservers
seer compare example.com A 8.8.8.8 1.1.1.1

# Monitor DNS records over time
seer follow example.com                           # 10 checks, 1 min apart
seer follow example.com 20 0.5                    # 20 checks, 30s apart
seer follow example.com 10 1 MX --changes-only    # Only show changes

# Reverse DNS
seer reverse 8.8.8.8
```

### Utility Commands

```bash
# Check domain availability (exit code: 0=available, 1=taken)
seer avail example.com

# Check DNSSEC configuration (exit code: 0=secure, 1=not secure)
seer dnssec example.com

# Look up TLD info (WHOIS server, RDAP endpoint, registry)
seer tld .com
seer tld uk

# Enumerate subdomains via Certificate Transparency logs
seer subdomains example.com
```

### Status & SSL

```bash
# Full domain health (exit code: 0=healthy, 1=issues)
seer status example.com

# Inspect SSL certificate chain, SANs, and key details
seer ssl example.com
```

### Domain Comparison

```bash
# Compare two domains side-by-side (registration, DNS, SSL)
seer diff example.com google.com
```

### Monitoring

```bash
# Domain watchlist
seer watch add example.com        # Add domain
seer watch add google.com
seer watch list                   # Show watchlist
seer watch                        # Check all domains for expiring certs/registrations
seer watch remove example.com     # Remove domain

# Lookup history (persisted to ~/.seer/history.json)
seer history example.com          # Show past lookups for a domain
seer history                      # Show all domains with history
seer history --clear              # Clear history
```

### Bulk Operations

Process domains from a file, output to CSV:

```bash
seer bulk lookup domains.txt
seer bulk whois domains.txt
seer bulk rdap domains.txt
seer bulk dig domains.txt MX
seer bulk prop domains.txt
seer bulk status domains.txt
seer bulk avail domains.txt
seer bulk status domains.txt -o results.csv    # Custom output path
```

Input file format: one domain per line (# for comments), or CSV (first column).

### Output Formats

The `--format` flag goes **before** the subcommand:

```bash
seer --format json lookup example.com       # JSON
seer --format yaml dig example.com MX       # YAML
seer --format markdown status example.com   # Markdown
seer --format human lookup example.com      # Human-readable (default)
```

### Field Extraction (Scripting)

Use `--quiet` with `--fields` for scriptable output:

```bash
seer --quiet --fields registrar lookup example.com
seer --quiet --fields certificate.issuer status example.com
seer --quiet --fields available avail example.com
seer --quiet --fields registrar,expires lookup example.com   # Multiple fields
```

### Exit Codes

| Command | Exit 0 | Exit 1 |
|---------|--------|--------|
| `avail` | Domain available | Domain taken |
| `status` | Healthy (HTTP 2xx, valid SSL, not expiring) | Any issue |
| `dnssec` | DNSSEC secure | Not secure |
| `compare` | Records match | Records differ |
| All others | Success | Error |

### Configuration

```bash
seer config --init    # Create ~/.seer/config.toml with defaults
seer config           # Show current config as JSON
```

Config file (`~/.seer/config.toml`):

```toml
output_format = "human"    # human, json, yaml, markdown
# nameserver = "8.8.8.8"   # Optional default nameserver

[timeouts]
whois_secs = 15
rdap_secs = 30
dns_secs = 5
http_secs = 10

[bulk]
concurrency = 10
rate_limit_ms = 100
```

### Shell Completions

```bash
seer completions bash > ~/.local/share/bash-completion/completions/seer
seer completions zsh > ~/.zfunc/_seer
seer completions fish > ~/.config/fish/completions/seer.fish
```

## Interactive REPL

Run `seer` with no arguments to enter the REPL:

```
$ seer
seer> lookup example.com
seer> dig github.com MX @1.1.1.1
seer> status cloudflare.com
seer> ssl cloudflare.com
seer> compare example.com A @8.8.8.8 @1.1.1.1
seer> subdomains example.com
seer> diff example.com google.com
seer> tld .com
seer> watch add example.com
seer> watch
seer> history example.com
seer> set output json
seer> help
seer> exit
```

REPL features:
- Tab completion for commands, record types, bulk operations, output formats, and watch actions
- Usage hints (type a command and press space)
- Command history saved to `~/.seer_history`
- Just type a domain name directly to run a smart lookup
- Ctrl+C or Ctrl+D to exit

## DNS Record Types

`A`, `AAAA`, `MX`, `TXT`, `NS`, `SOA`, `CNAME`, `CAA`, `PTR`, `SRV`, `DNSKEY`, `DS`, `ANY`

## CSV Output Columns

| Operation | Columns |
|-----------|---------|
| **status** | domain, success, http_status, http_status_text, title, ssl_issuer, ssl_valid_until, ssl_days_remaining, domain_expires, domain_days_remaining, registrar, dns_resolves, dns_a_records, dns_aaaa_records, dns_cname, dns_nameservers, duration_ms, error |
| **lookup/whois/rdap** | domain, success, registrar, created, expires, updated, duration_ms, error |
| **dig** | domain, success, record_type, records, duration_ms, error |
| **prop** | domain, success, propagation_pct, servers_total, servers_responded, duration_ms, error |
| **avail** | domain, success, available, confidence, method, details, duration_ms, error |

## REST API

```bash
seer-api    # Starts on http://localhost:8000
```

| Endpoint | Description |
|----------|-------------|
| `GET /lookup/{domain}` | Smart lookup |
| `POST /lookup/bulk` | Bulk lookups (JSON body: `{"domains": [...]}`) |
| `GET /whois/{domain}` | WHOIS lookup |
| `GET /rdap/domain/{domain}` | RDAP domain |
| `GET /rdap/ip/{ip}` | RDAP IP |
| `GET /rdap/asn/{asn}` | RDAP ASN |
| `GET /dns/{domain}/{type}` | DNS query |
| `GET /propagation/{domain}/{type}` | Propagation check |
| `GET /status/{domain}` | Domain status |
| `POST /status/bulk` | Bulk status checks |

Docs: http://localhost:8000/docs (Swagger) or http://localhost:8000/redoc

## MCP Server

```bash
seer-mcp    # Runs on stdio
```

Claude Desktop config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "seer": {
      "command": "seer-mcp"
    }
  }
}
```

Tools: `seer_lookup`, `seer_whois`, `seer_rdap_domain`, `seer_rdap_ip`, `seer_rdap_asn`, `seer_dig`, `seer_propagation`, `seer_status`, `seer_bulk_lookup`, `seer_bulk_whois`, `seer_bulk_dig`, `seer_bulk_status`, `seer_bulk_propagation`

## Python Library

```python
import seer

result = seer.lookup("example.com")
whois = seer.whois("example.com")
rdap = seer.rdap_domain("example.com")
dns = seer.dig("example.com", record_type="MX")
prop = seer.propagation("example.com", record_type="A")
status = seer.status("example.com")

# Bulk
results = seer.bulk_lookup(["example.com", "google.com"], concurrency=10)
results = seer.bulk_status(["example.com", "google.com"])
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `RUST_LOG` | Log level: trace, debug, info, warn, error | warn |
| `SEER_CORS_ORIGINS` | CORS origins for REST API (comma-separated) | `*` |
| `SEER_RATE_LIMIT` | REST API rate limit (requests/minute) | `30` |
