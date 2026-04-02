# DomainInfo: Flattened Merged RDAP+WHOIS Result

**Date:** 2026-04-02
**Status:** Approved

## Problem

`bulk_lookup` runs RDAP and WHOIS concurrently per domain, but the result is a tagged enum (`LookupResult`) where:
- The `Rdap` variant carries `whois_fallback: Option<WhoisResponse>` (good)
- The `Whois` variant only keeps `rdap_error: Option<String>`, dropping any partial RDAP data (data loss)
- Consumers must match on the enum variant and dig into nested structures (RDAP entities with vCard arrays, WHOIS regex-extracted fields) to access individual values

For bulk use cases, users want a flat, column-per-field result where both sources are merged to maximize completeness.

## Solution

Add a new `DomainInfo` struct that flattens all extractable registration data into top-level fields, merging RDAP and WHOIS to fill gaps. Expose it as a new operation (`info` / `bulk_info`) across all layers.

## Design

### DomainInfo Struct

New file: `seer-core/src/domain_info.rs`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainInfo {
    // Core
    pub domain: String,
    pub source: DomainInfoSource,

    // Registration
    pub registrar: Option<String>,
    pub registrant: Option<String>,
    pub organization: Option<String>,

    // Dates
    pub creation_date: Option<DateTime<Utc>>,
    pub expiration_date: Option<DateTime<Utc>>,
    pub updated_date: Option<DateTime<Utc>>,

    // DNS
    pub nameservers: Vec<String>,
    pub status: Vec<String>,
    pub dnssec: Option<String>,

    // Registrant contact
    pub registrant_email: Option<String>,
    pub registrant_phone: Option<String>,
    pub registrant_address: Option<String>,
    pub registrant_country: Option<String>,

    // Admin contact
    pub admin_name: Option<String>,
    pub admin_organization: Option<String>,
    pub admin_email: Option<String>,
    pub admin_phone: Option<String>,

    // Tech contact
    pub tech_name: Option<String>,
    pub tech_organization: Option<String>,
    pub tech_email: Option<String>,
    pub tech_phone: Option<String>,

    // Protocol metadata
    pub whois_server: Option<String>,
    pub rdap_url: Option<String>,  // extracted from RDAP response links where rel == "self"
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DomainInfoSource {
    Both,
    Rdap,
    Whois,
    Available,
}
```

### Merge Logic

`DomainInfo::from_lookup(rdap: Option<&RdapResponse>, whois: Option<&WhoisResponse>, domain: &str) -> DomainInfo`

For each field:
1. Try RDAP extraction first (entity vCard parsing for contacts, events for dates, etc.)
2. If `None`, fall back to the corresponding WHOIS field

For vec fields (nameservers, status):
- Use RDAP if non-empty, otherwise WHOIS

For dnssec:
- RDAP: `secure_dns.delegation_signed` mapped to "signed"/"unsigned"
- Fall back to WHOIS `dnssec` field

The `source` field reflects what data was available:
- `Both` — both RDAP and WHOIS returned data
- `Rdap` — only RDAP succeeded
- `Whois` — only WHOIS succeeded
- `Available` — neither succeeded, availability check fallback

A convenience `DomainInfo::from_lookup_result(result: &LookupResult) -> DomainInfo` method extracts the RDAP/WHOIS components from the enum and delegates to `from_lookup`.

### Prerequisite: Preserve Partial RDAP in LookupResult::Whois

Add `rdap_fallback: Option<Box<RdapResponse>>` to the `Whois` variant:

```rust
LookupResult::Whois {
    data: WhoisResponse,
    rdap_error: Option<String>,
    rdap_fallback: Option<Box<RdapResponse>>,  // NEW
}
```

Update `SmartLookup::lookup_concurrent()` to preserve partial RDAP data:
- When RDAP succeeds but `is_rdap_response_useful()` returns false, store the response in `rdap_fallback` instead of discarding it
- When RDAP fails entirely, `rdap_fallback` is `None`

This is a breaking change to the enum variant. Callers that destructure `LookupResult::Whois` will need to add the new field. The serialized JSON gains an optional `rdap_fallback` key.

### Bulk Executor Changes

In `seer-core/src/bulk/executor.rs`:

```rust
// New operation variant
BulkOperation::Info { domain: String }

// New result variant
BulkResultData::Info(DomainInfo)
```

`execute_operation` for `BulkOperation::Info`: calls `SmartLookup::lookup()`, then `DomainInfo::from_lookup_result()`.

New convenience method: `BulkExecutor::execute_info(domains: Vec<String>) -> Vec<BulkResult>`.

### Output Formatting

Add `format_domain_info(&self, info: &DomainInfo) -> String` to the `OutputFormatter` trait.

Implement for all 4 formatters:
- **Human**: Colored sections matching existing lookup formatter style
- **Json**: Serialize via serde (automatic)
- **Yaml**: Serialize via the existing YAML formatter
- **Markdown**: Table/sections matching existing markdown style

### Python Bindings (seer-py)

In `seer-py/src/lib.rs`:

```python
# Single domain
def info(domain: str) -> dict: ...

# Bulk
def bulk_info(domains: list[str], concurrency: int = 10) -> list[dict]: ...
```

Both serialize `DomainInfo` to JSON then convert to Python dict via the existing `json_to_python()` helper.

### MCP Server (seer-api)

Two new tools:

- `seer_info` — single domain, returns flat dict
- `seer_bulk_info` — list of domains, same schema as other bulk tools (concurrency param, max 100 domains)

### CLI (seer-cli)

New `info` subcommand:
```
seer info example.com
seer info example.com --format json
```

REPL support: `info example.com`

Respects global `--format` flag.

## Files Changed

| File | Change |
|------|--------|
| `seer-core/src/domain_info.rs` | **NEW** — `DomainInfo`, `DomainInfoSource`, merge logic |
| `seer-core/src/lib.rs` | Add `pub mod domain_info` export |
| `seer-core/src/lookup.rs` | Add `rdap_fallback` to `Whois` variant, preserve partial RDAP |
| `seer-core/src/bulk/executor.rs` | Add `Info` variants to `BulkOperation` and `BulkResultData`, `execute_info()` |
| `seer-core/src/output/mod.rs` | Add `format_domain_info` to trait |
| `seer-core/src/output/human.rs` | Implement `format_domain_info` |
| `seer-core/src/output/json.rs` | Implement `format_domain_info` |
| `seer-core/src/output/yaml.rs` | Implement `format_domain_info` (via YamlFormatter) |
| `seer-core/src/output/markdown.rs` | Implement `format_domain_info` |
| `seer-py/src/lib.rs` | Add `info()` and `bulk_info()` functions |
| `seer-api/seer_api/mcp/server.py` | Add `seer_info` and `seer_bulk_info` tools |
| `seer-cli/src/main.rs` | Add `info` subcommand |
| `seer-cli/src/repl/commands.rs` | Add `info` REPL command |

## Not Changed

- `bulk_lookup`, `bulk_whois`, and all other existing operations remain as-is
- `LookupResult::Rdap` variant is unchanged (already has `whois_fallback`)
- No changes to RDAP client, WHOIS client, or their parsers

## Testing

- Unit tests for `DomainInfo::from_lookup` with:
  - Both RDAP and WHOIS present (verify RDAP takes priority, WHOIS fills gaps)
  - RDAP only
  - WHOIS only
  - Neither (Available fallback)
- Unit test for `rdap_fallback` preservation in `SmartLookup`
- Integration test for `BulkExecutor::execute_info()` with a known domain
- Serialization round-trip test for `DomainInfo`
