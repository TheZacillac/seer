# seer-cli

Command-line interface for the Seer domain utility suite.

## Overview

`seer-cli` provides a feature-rich command-line interface with:
- Command mode for scripting and one-off queries
- Interactive REPL for exploratory work
- Human-readable and JSON output formats
- Bulk operations with CSV output
- Progress indicators and colored output

## Installation

### From crates.io

```bash
cargo install seer-cli
```

### From Source

```bash
cd seer-cli
cargo install --path .
```

This installs the `seer` binary to `~/.cargo/bin/`.

## Modules

| Directory | Description |
|-----------|-------------|
| [`src/main.rs`](src/main.rs) | Entry point, Clap commands, subcommand dispatch |
| [`src/repl/`](src/repl/) | Interactive REPL implementation |
| [`src/display/`](src/display/) | UI utilities (spinners, etc.) |

## Commands

### Smart Lookup

Tries RDAP first, falls back to WHOIS.

```bash
seer lookup example.com
seer lookup example.com --format json
```

### WHOIS Lookup

Query domain registrant information.

```bash
seer whois example.com
```

### RDAP Lookup

Query RDAP for domains, IPs, or ASNs.

```bash
seer rdap example.com       # Domain
seer rdap 8.8.8.8           # IP address
seer rdap AS15169           # ASN
```

### DNS Query

Query DNS records (like `dig`).

```bash
seer dig example.com           # A records (default)
seer dig example.com MX        # MX records
seer dig example.com A @8.8.8.8  # Custom nameserver
```

Supported record types: `A`, `AAAA`, `MX`, `TXT`, `NS`, `SOA`, `CNAME`, `CAA`, `PTR`, `SRV`, `DNSKEY`, `DS`, `ANY`

### DNS Propagation

Check DNS propagation across global servers.

```bash
seer propagation example.com A
seer propagation example.com MX
```

### Domain Status

Check domain health (HTTP, SSL, expiration).

```bash
seer status example.com
```

### DNS Follow

Monitor DNS records over time.

```bash
seer follow example.com                      # 10 iterations, 1 minute interval
seer follow example.com 20 0.5               # 20 iterations, 30 second interval
seer follow example.com 10 1 MX              # Monitor MX records
seer follow example.com 10 1 A --changes-only  # Only show changes
```

Press `Esc` or `Ctrl+C` to stop early.

### Bulk Operations

Process multiple domains from a file.

```bash
seer bulk lookup domains.txt
seer bulk whois domains.txt
seer bulk dig domains.txt MX
seer bulk status domains.txt
seer bulk propagation domains.txt A

# Custom output file
seer bulk status domains.txt -o results.csv
```

Input file formats:
- Plain text (one domain per line)
- Comments (lines starting with `#`)
- CSV (uses first column)

## Output Formats

```bash
# Human-readable (default)
seer lookup example.com --format human

# JSON
seer lookup example.com --format json
```

The `--format` flag works with all commands.

## Interactive REPL

Start the REPL by running `seer` without arguments:

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
- Tab completion for commands
- Loading spinners during operations
- Persistent session state

## Examples

### Check If Domain Is Available

```bash
seer lookup newdomain.com --format json | jq '.source'
```

### Export Domain Status to CSV

```bash
seer bulk status domains.txt -o report.csv
```

### Monitor DNS After Change

```bash
seer follow example.com 60 0.5 A --changes-only
# Checks every 30 seconds for 30 minutes, shows only changes
```

### Quick DNS Check with JSON

```bash
seer dig example.com A --format json | jq '.[].data.address'
```

### Verify SSL Certificate

```bash
seer status example.com --format json | jq '.certificate'
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `RUST_LOG` | Logging level (trace, debug, info, warn, error) |

Enable debug logging:

```bash
RUST_LOG=debug seer lookup example.com
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (invalid input, lookup failure, etc.) |

## Dependencies

- **seer-core** - Core library
- **clap** - Command-line parsing
- **rustyline** - REPL line editing
- **indicatif** - Progress indicators
- **colored** - Terminal colors
- **crossterm** - Terminal control
- **tokio** - Async runtime
- **anyhow** - Error handling

## Build

```bash
# Debug build
cargo build -p seer-cli

# Release build
cargo build --release -p seer-cli

# Run without installing
cargo run -p seer-cli -- lookup example.com
```
