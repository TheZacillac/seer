# Output Module

Output formatters for human-readable and JSON output.

## Overview

This module provides output formatting for all Seer data types:
- Human-readable colored terminal output
- JSON output for machine processing
- Consistent formatting across all operation types

## Files

| File | Description |
|------|-------------|
| `mod.rs` | OutputFormat enum and formatter trait |
| `human.rs` | Human-readable terminal formatter |
| `json.rs` | JSON formatter |

## Public API

### Types

```rust
pub use human::HumanFormatter;
pub use json::JsonFormatter;

pub enum OutputFormat {
    Human,  // Default, colored terminal output
    Json,   // JSON output
}

pub fn get_formatter(format: OutputFormat) -> Box<dyn OutputFormatter>;
```

### OutputFormat

Output format selection.

```rust
impl FromStr for OutputFormat {
    // Accepts: "human", "text", "pretty" -> Human
    // Accepts: "json" -> Json
}

impl Default for OutputFormat {
    fn default() -> Self {
        OutputFormat::Human
    }
}
```

### OutputFormatter Trait

Trait implemented by all formatters.

```rust
pub trait OutputFormatter {
    fn format_whois(&self, response: &WhoisResponse) -> String;
    fn format_rdap(&self, response: &RdapResponse) -> String;
    fn format_dns(&self, records: &[DnsRecord]) -> String;
    fn format_propagation(&self, result: &PropagationResult) -> String;
    fn format_lookup(&self, result: &LookupResult) -> String;
    fn format_status(&self, response: &StatusResponse) -> String;
    fn format_follow_iteration(&self, iteration: &FollowIteration) -> String;
    fn format_follow(&self, result: &FollowResult) -> String;
}
```

### HumanFormatter

Human-readable terminal formatter with Catppuccin colors.

```rust
impl HumanFormatter {
    pub fn new() -> Self;
}
```

Features:
- Catppuccin Frappe color palette
- Structured output with labeled fields
- Table formatting for record lists
- Status indicators (checkmarks, crosses)
- Date formatting

### JsonFormatter

JSON formatter for machine processing.

```rust
impl JsonFormatter {
    pub fn new() -> Self;
}
```

Features:
- Pretty-printed JSON
- Full data serialization
- Consistent with Rust struct names
- Suitable for piping to `jq`

## Usage Examples

### Get Formatter by Format

```rust
use seer_core::output::{get_formatter, OutputFormat};

let format: OutputFormat = "json".parse().unwrap();
let formatter = get_formatter(format);

let output = formatter.format_lookup(&result);
println!("{}", output);
```

### Human-Readable Output

```rust
use seer_core::output::HumanFormatter;

let formatter = HumanFormatter::new();
let output = formatter.format_status(&status);
println!("{}", output);
```

Example output:
```
Domain Status: example.com
================================================================================

HTTP Status
  Status:     200 OK
  Title:      Example Domain

SSL Certificate
  Issuer:     DigiCert Inc
  Valid:      2024-01-15 to 2025-01-15
  Expires in: 89 days

Domain Registration
  Registrar:  Internet Assigned Numbers Authority
  Expires:    2025-08-13 (204 days)

DNS Resolution
  A Records:  93.184.216.34
  AAAA:       2606:2800:220:1:248:1893:25c8:1946
  Nameservers: a.iana-servers.net, b.iana-servers.net
```

### JSON Output

```rust
use seer_core::output::JsonFormatter;

let formatter = JsonFormatter::new();
let output = formatter.format_status(&status);
println!("{}", output);
```

Example output:
```json
{
  "domain": "example.com",
  "http_status": 200,
  "http_status_text": "OK",
  "title": "Example Domain",
  "certificate": {
    "issuer": "DigiCert Inc",
    "subject": "example.com",
    "valid_from": "2024-01-15T00:00:00Z",
    "valid_until": "2025-01-15T00:00:00Z",
    "days_until_expiry": 89,
    "is_valid": true
  }
}
```

### Format Selection from CLI

```rust
use seer_core::output::OutputFormat;

let format_str = "json";
let format: OutputFormat = format_str.parse().unwrap_or_default();
```

## Color Palette

The human formatter uses the Catppuccin Frappe color palette:

| Element | Color |
|---------|-------|
| Headers/Labels | Blue |
| Success/OK | Green |
| Warnings | Yellow |
| Errors | Red |
| Domain names | Teal |
| Values | Lavender |

Colors are applied using ANSI escape codes and require a terminal that supports them.

## Format Comparison

| Feature | Human | JSON |
|---------|-------|------|
| Colors | Yes | No |
| Structure | Visual | Data |
| Parsing | Difficult | Easy |
| Use case | Terminal | Scripting |
