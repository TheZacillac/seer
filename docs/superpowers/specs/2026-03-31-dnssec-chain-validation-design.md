# DNSSEC DS-to-DNSKEY Chain Validation

**Date:** 2026-03-31
**Status:** Approved
**Scope:** seer-core DNSSEC checker enhancement

## Problem

The current DNSSEC checker (`seer-core/src/dns/dnssec.rs`) reports whether DS and DNSKEY records exist but does not validate that they actually match. A domain can have both record types present yet be completely broken if the DS record at the registry points to a key that doesn't exist or has the wrong digest. The checker currently reports this as "secure" when it should flag it as misconfigured.

## Solution

Add DS-to-DNSKEY cross-validation using hickory-resolver's built-in `DNSKEY::calculate_key_tag()` and `DNSKEY::to_digest(name, digest_type)` methods (available via the existing `dnssec-ring` feature). The checker will make raw hickory-level resolve calls to access native DNSKEY objects for crypto operations, while continuing to produce our own report structs.

## Approach

Validation logic lives entirely in `dnssec.rs` (Approach A). The resolver and `RecordData` enum are untouched. The DNSSEC checker is the only consumer of key tag computation and digest matching.

## Data Model Changes

### DsInfo (existing struct, new fields)

```rust
pub struct DsInfo {
    // ... existing fields unchanged ...
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: String,
    pub algorithm_name: String,
    pub digest_type_name: String,
    // NEW:
    pub matched_key: bool,       // DS key_tag+algorithm matched a DNSKEY
    pub digest_verified: bool,   // Computed digest from matched DNSKEY equals DS digest
}
```

### DnskeyInfo (existing struct, changed field)

```rust
pub struct DnskeyInfo {
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    pub key_tag: u16,            // CHANGED: was key_tag_hint: String (truncated pubkey)
    pub is_ksk: bool,
    pub is_zsk: bool,
    pub algorithm_name: String,
}
```

The `key_tag_hint: String` field is replaced by `key_tag: u16` — the actual RFC 4034 computed key tag. This is a breaking change to the serialized output (field name and type change).

### DnssecReport (existing struct, new field)

```rust
pub struct DnssecReport {
    // ... existing fields unchanged ...
    pub domain: String,
    pub enabled: bool,
    pub has_ds_records: bool,
    pub has_dnskey_records: bool,
    pub ds_records: Vec<DsInfo>,
    pub dnskey_records: Vec<DnskeyInfo>,
    pub issues: Vec<String>,
    pub status: String,
    // NEW:
    pub chain_valid: bool,       // true only when every DS matches + verifies
}
```

## Validation Logic

### Cross-validation flow (in `DnssecChecker::check()`)

1. **Resolve raw hickory DNSKEYs** — make a direct hickory `lookup(domain, DNSKEY)` call to get native `DNSKEY` objects (separate from the existing resolve call that produces `RecordData`)
2. **Compute key tags** — for each raw DNSKEY, call `calculate_key_tag()`. Build a lookup map: `HashMap<(u16, u8), &DNSKEY>` keyed by `(key_tag, algorithm)`
3. **Populate `DnskeyInfo.key_tag`** — set the computed key tag on each `DnskeyInfo` struct
4. **Match each DS to a DNSKEY** — for each DS record, look up `(ds.key_tag, ds.algorithm)` in the map. Set `matched_key = true` if found.
5. **Verify digest** — if matched, call `dnskey.to_digest(domain_name, ds.digest_type)`, hex-encode the result, and compare case-insensitively against `ds.digest`. Set `digest_verified = true` if equal.
6. **Derive `chain_valid`** — `true` only if `has_ds && has_dnskey && all DS records have matched_key && digest_verified`

### Issue strings

| Condition | Issue text |
|-----------|-----------|
| DS has no matching DNSKEY | `"DS record (key_tag=XXXXX) has no matching DNSKEY"` |
| DS matches DNSKEY but digest differs | `"DS record (key_tag=XXXXX) digest mismatch — registry and DNS keys do not match"` |
| KSK has no corresponding DS | `"DNSKEY (key_tag=XXXXX) is a KSK with no corresponding DS record"` |

### Status derivation

| Condition | Status |
|-----------|--------|
| Both DS + DNSKEY exist, `chain_valid` true, no deprecated algo issues | `"secure"` |
| Both DS + DNSKEY exist, `chain_valid` false | `"misconfigured"` |
| Only one side present | `"partial"` |
| Neither present | `"insecure"` |

Note: the existing code sets status to "partial" when both DS and DNSKEY exist but there are any issues (including deprecated algorithm warnings). The new logic replaces this: status is derived from chain validity, not from the issues list. Deprecated algorithm warnings still appear in `issues` but do not affect `status` or `chain_valid`. A domain with a valid chain using a deprecated algorithm gets `status: "secure"`, `chain_valid: true`, with a warning in `issues`.

## Files Modified

| File | Change |
|------|--------|
| `seer-core/src/dns/dnssec.rs` | New struct fields, raw hickory resolve, cross-validation logic, updated status derivation |
| `seer-core/src/output/human.rs` | Display `chain_valid`, per-DS match/verify indicators, computed key tags on DNSKEYs |
| `seer-core/src/output/json.rs` | Update if explicit DNSSEC formatting exists (new fields serialize via serde automatically) |
| `seer-core/src/output/markdown.rs` | Update if explicit DNSSEC formatting exists |

## Files Unchanged

| File | Reason |
|------|--------|
| `seer-core/src/dns/resolver.rs` | Checker makes its own raw hickory calls |
| `seer-core/src/dns/records.rs` | `RecordData` enum untouched |
| `seer-py/src/lib.rs` | Uses `json_to_python()` on serialized report — new fields flow through |
| `seer-cli/src/main.rs` | Calls `format_dnssec()` which is updated |
| `seer-cli/src/repl/mod.rs` | Same — delegates to formatter |
| `seer-api/` | Passes through serde output |

## Testing

- Unit test: known DNSKEY wire data produces expected key tag (RFC 4034 Appendix B test vectors)
- Unit test: `chain_valid` is false when DS digest doesn't match any DNSKEY
- Update existing `test_report_serialization` to include new fields (`chain_valid`, `matched_key`, `digest_verified`, `key_tag`)
- Integration test: run `check()` against a known DNSSEC-signed domain (e.g., `cloudflare.com`) and verify `chain_valid == true`

## Breaking Changes

- `DnskeyInfo.key_tag_hint: String` is replaced by `DnskeyInfo.key_tag: u16` — different field name and type in serialized JSON output
- New `"misconfigured"` status value — consumers matching on status strings need to handle this
- `DnssecReport` gains `chain_valid: bool` — additive, but older consumers won't expect it
