# DNSSEC DS-to-DNSKEY Chain Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Validate that DS records at the registry match DNSKEY records in DNS, flagging mismatches with both structured per-record detail and a simple `chain_valid` boolean.

**Architecture:** The DNSSEC checker (`dnssec.rs`) makes its own raw hickory-level resolve calls to access native `DNSKEY` objects, calls `calculate_key_tag()` and `to_digest()` on them, and cross-validates against DS records. No changes to the resolver or `RecordData` enum. Human and markdown formatters are updated to display the new fields.

**Tech Stack:** Rust, hickory-resolver (dnssec-ring feature), tokio

**Spec:** `docs/superpowers/specs/2026-03-31-dnssec-chain-validation-design.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `seer-core/src/dns/dnssec.rs` | Modify | Data model changes + cross-validation logic |
| `seer-core/src/output/human.rs` | Modify | Display chain_valid, per-DS match status, key tags |
| `seer-core/src/output/markdown.rs` | Modify | Same for markdown tables |

Files unchanged: `dns/resolver.rs`, `dns/records.rs`, `seer-py/src/lib.rs`, `seer-cli/`, `seer-api/`, `output/json.rs` (serde auto), `output/mod.rs` (YAML auto).

---

### Task 1: Update data model structs

**Files:**
- Modify: `seer-core/src/dns/dnssec.rs:14-55` (struct definitions)

- [ ] **Step 1: Update `DsInfo` struct — add `matched_key` and `digest_verified` fields**

In `seer-core/src/dns/dnssec.rs`, replace the `DsInfo` struct:

```rust
/// Summary of a DS record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsInfo {
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: String,
    pub algorithm_name: String,
    pub digest_type_name: String,
    /// Whether this DS record's key_tag+algorithm matched a DNSKEY.
    pub matched_key: bool,
    /// Whether the computed digest from the matched DNSKEY equals this DS digest.
    pub digest_verified: bool,
}
```

- [ ] **Step 2: Update `DnskeyInfo` struct — replace `key_tag_hint` with `key_tag`**

Replace the `DnskeyInfo` struct:

```rust
/// Summary of a DNSKEY record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnskeyInfo {
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    /// The RFC 4034 computed key tag.
    pub key_tag: u16,
    pub is_ksk: bool,
    pub is_zsk: bool,
    pub algorithm_name: String,
}
```

- [ ] **Step 3: Update `DnssecReport` struct — add `chain_valid` field**

Add `chain_valid: bool` after `status`:

```rust
/// DNSSEC validation report for a domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnssecReport {
    /// The domain that was checked.
    pub domain: String,
    /// Whether the domain has DNSSEC enabled.
    pub enabled: bool,
    /// Whether DS records exist at the parent zone.
    pub has_ds_records: bool,
    /// Whether DNSKEY records exist at the domain.
    pub has_dnskey_records: bool,
    /// DS records found at the parent zone.
    pub ds_records: Vec<DsInfo>,
    /// DNSKEY records found at the domain.
    pub dnskey_records: Vec<DnskeyInfo>,
    /// Validation issues found.
    pub issues: Vec<String>,
    /// Overall status: "secure", "insecure", "partial", or "misconfigured".
    pub status: String,
    /// Whether the full DS-to-DNSKEY chain validates.
    /// True only when every DS record matches a DNSKEY and all digests verify.
    pub chain_valid: bool,
}
```

- [ ] **Step 4: Update `test_report_serialization` to compile with new fields**

Replace the existing test at the bottom of `dnssec.rs`:

```rust
    #[test]
    fn test_report_serialization() {
        let report = DnssecReport {
            domain: "example.com".to_string(),
            enabled: true,
            has_ds_records: true,
            has_dnskey_records: true,
            ds_records: vec![DsInfo {
                key_tag: 12345,
                algorithm: 13,
                digest_type: 2,
                digest: "ABCDEF".to_string(),
                algorithm_name: "ECDSA P-256/SHA-256".to_string(),
                digest_type_name: "SHA-256".to_string(),
                matched_key: true,
                digest_verified: true,
            }],
            dnskey_records: vec![DnskeyInfo {
                flags: 257,
                protocol: 3,
                algorithm: 13,
                key_tag: 12345,
                is_ksk: true,
                is_zsk: false,
                algorithm_name: "ECDSA P-256/SHA-256".to_string(),
            }],
            issues: vec![],
            status: "secure".to_string(),
            chain_valid: true,
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"enabled\":true"));
        assert!(json.contains("\"chain_valid\":true"));
        assert!(json.contains("\"matched_key\":true"));
        assert!(json.contains("\"digest_verified\":true"));
        assert!(json.contains("\"key_tag\":12345"));
    }
```

- [ ] **Step 5: Verify it compiles**

Run: `cargo check -p seer-core 2>&1 | head -30`

Expected: Compilation errors in `check()` method body (references to removed `key_tag_hint` field) and in output formatters. The structs and test should compile. This is expected — we fix `check()` in Task 2 and formatters in Task 4.

- [ ] **Step 6: Commit**

```bash
git add seer-core/src/dns/dnssec.rs
git commit -m "feat(dnssec): update data model for DS-to-DNSKEY chain validation

Add matched_key, digest_verified to DsInfo. Replace key_tag_hint with
computed key_tag on DnskeyInfo. Add chain_valid to DnssecReport."
```

---

### Task 2: Implement cross-validation logic

**Files:**
- Modify: `seer-core/src/dns/dnssec.rs:57-234` (the `DnssecChecker` impl and `check()` method)

- [ ] **Step 1: Add hickory imports at top of `dnssec.rs`**

Add these imports below the existing `use` statements at the top of the file:

```rust
use std::collections::HashMap;

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::dnssec::rdata::DNSKEY;
use hickory_resolver::proto::rr::dnssec::DigestType;
use hickory_resolver::proto::rr::rdata::DNSSEC;
use hickory_resolver::proto::rr::{Name, RData, RecordType as HickoryRecordType};
use hickory_resolver::TokioAsyncResolver;
```

- [ ] **Step 2: Add a raw hickory resolver to `DnssecChecker`**

Replace the `DnssecChecker` struct and its `Default`/`new` impls:

```rust
/// Checks DNSSEC configuration for a domain.
pub struct DnssecChecker {
    resolver: DnsResolver,
    raw_resolver: TokioAsyncResolver,
}

impl Default for DnssecChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl DnssecChecker {
    pub fn new() -> Self {
        let mut opts = ResolverOpts::default();
        opts.timeout = std::time::Duration::from_secs(5);
        opts.attempts = 2;
        opts.use_hosts_file = false;

        Self {
            resolver: DnsResolver::new(),
            raw_resolver: TokioAsyncResolver::tokio(ResolverConfig::google(), opts),
        }
    }
```

- [ ] **Step 3: Add helper method to resolve raw hickory DNSKEY objects**

Add this method inside the `impl DnssecChecker` block, after `new()` and before `check()`:

```rust
    /// Resolves raw hickory DNSKEY records for crypto operations.
    /// Returns a vec of (DNSKEY, computed_key_tag) pairs.
    async fn resolve_raw_dnskeys(&self, domain: &str) -> Vec<(DNSKEY, u16)> {
        let lookup = match self.raw_resolver.lookup(domain, HickoryRecordType::DNSKEY).await {
            Ok(lookup) => lookup,
            Err(_) => return vec![],
        };

        lookup
            .record_iter()
            .filter_map(|record| {
                if let Some(RData::DNSSEC(DNSSEC::DNSKEY(dnskey))) = record.data() {
                    match dnskey.calculate_key_tag() {
                        Ok(tag) => Some((dnskey.clone(), tag)),
                        Err(_) => None,
                    }
                } else {
                    None
                }
            })
            .collect()
    }
```

- [ ] **Step 4: Add helper to convert digest_type u8 to hickory DigestType**

Add this below `resolve_raw_dnskeys`:

```rust
    /// Converts a DS digest type number to hickory's DigestType.
    fn to_hickory_digest_type(digest_type: u8) -> Option<DigestType> {
        DigestType::from_u8(digest_type).ok()
    }
```

- [ ] **Step 5: Rewrite the `check()` method**

Replace the entire `check()` method body with the new implementation that adds cross-validation:

```rust
    /// Generate a DNSSEC validation report for a domain.
    #[instrument(skip(self), fields(domain = %domain))]
    pub async fn check(&self, domain: &str) -> Result<DnssecReport> {
        let domain = crate::validation::normalize_domain(domain)?;
        debug!(domain = %domain, "Checking DNSSEC");

        let mut issues = Vec::new();

        // Query DS records (at parent zone)
        let ds_records: Vec<crate::dns::DnsRecord> =
            match self.resolver.resolve(&domain, RecordType::DS, None).await {
                Ok(records) => records,
                Err(e) => {
                    issues.push(format!("DS query failed: {}", e));
                    vec![]
                }
            };

        // Query DNSKEY records (at the domain itself)
        let dnskey_records: Vec<crate::dns::DnsRecord> = match self
            .resolver
            .resolve(&domain, RecordType::DNSKEY, None)
            .await
        {
            Ok(records) => records,
            Err(e) => {
                issues.push(format!("DNSKEY query failed: {}", e));
                vec![]
            }
        };

        let has_ds = !ds_records.is_empty();
        let has_dnskey = !dnskey_records.is_empty();

        // Resolve raw hickory DNSKEYs for crypto operations
        let raw_dnskeys = self.resolve_raw_dnskeys(&domain).await;

        // Build lookup map: (key_tag, algorithm) -> raw DNSKEY
        let dnskey_map: HashMap<(u16, u8), &DNSKEY> = raw_dnskeys
            .iter()
            .map(|(dnskey, tag)| ((*tag, u8::from(dnskey.algorithm())), dnskey))
            .collect();

        // Build set of DS key_tags for KSK orphan detection
        let ds_key_tags: std::collections::HashSet<u16> = ds_records
            .iter()
            .filter_map(|r| {
                if let RecordData::DS { key_tag, .. } = r.data {
                    Some(key_tag)
                } else {
                    None
                }
            })
            .collect();

        // Parse DNSKEY record info with computed key tags
        let dnskey_info: Vec<DnskeyInfo> = dnskey_records
            .iter()
            .zip(raw_dnskeys.iter().chain(std::iter::repeat(&(DNSKEY::new(0, 3, hickory_resolver::proto::rr::dnssec::Algorithm::ECDSAP256SHA256, vec![]), 0))))
            .filter_map(|(r, (_, computed_tag))| {
                if let RecordData::DNSKEY {
                    flags,
                    protocol,
                    algorithm,
                    ..
                } = r.data
                {
                    let is_sep = flags & 0x0001 != 0;
                    let is_zone = flags & 0x0100 != 0;
                    let is_ksk = is_sep && is_zone;
                    let is_zsk = is_zone && !is_sep;
                    Some(DnskeyInfo {
                        flags,
                        protocol,
                        algorithm,
                        key_tag: *computed_tag,
                        is_ksk,
                        is_zsk,
                        algorithm_name: algorithm_name(algorithm),
                    })
                } else {
                    None
                }
            })
            .collect();

        // Build Name for digest computation
        let domain_name = Name::from_ascii(&domain)
            .unwrap_or_else(|_| Name::from_ascii("invalid.").unwrap());

        // Parse DS record info with cross-validation
        let ds_info: Vec<DsInfo> = ds_records
            .iter()
            .map(|r| {
                if let RecordData::DS {
                    key_tag,
                    algorithm,
                    digest_type,
                    ref digest,
                } = r.data
                {
                    let mut matched_key = false;
                    let mut digest_verified = false;

                    // Try to match this DS to a DNSKEY
                    if let Some(raw_dnskey) = dnskey_map.get(&(key_tag, algorithm)) {
                        matched_key = true;

                        // Verify digest
                        if let Some(hickory_dt) = Self::to_hickory_digest_type(digest_type) {
                            if let Ok(computed) = raw_dnskey.to_digest(&domain_name, hickory_dt) {
                                let computed_hex: String = computed
                                    .as_ref()
                                    .iter()
                                    .map(|b| format!("{:02X}", b))
                                    .collect();
                                digest_verified = computed_hex.eq_ignore_ascii_case(digest);
                            }
                        }

                        if !digest_verified {
                            issues.push(format!(
                                "DS record (key_tag={}) digest mismatch \u{2014} registry and DNS keys do not match",
                                key_tag
                            ));
                        }
                    } else if has_dnskey {
                        issues.push(format!(
                            "DS record (key_tag={}) has no matching DNSKEY",
                            key_tag
                        ));
                    }

                    DsInfo {
                        key_tag,
                        algorithm,
                        digest_type,
                        digest: digest.clone(),
                        algorithm_name: algorithm_name(algorithm),
                        digest_type_name: digest_type_name(digest_type),
                        matched_key,
                        digest_verified,
                    }
                } else {
                    // Should not happen — we only have DS records here
                    DsInfo {
                        key_tag: 0,
                        algorithm: 0,
                        digest_type: 0,
                        digest: String::new(),
                        algorithm_name: String::new(),
                        digest_type_name: String::new(),
                        matched_key: false,
                        digest_verified: false,
                    }
                }
            })
            .collect();

        // Check for KSK orphans (DNSKEY KSKs with no corresponding DS)
        for key in &dnskey_info {
            if key.is_ksk && !ds_key_tags.contains(&key.key_tag) {
                issues.push(format!(
                    "DNSKEY (key_tag={}) is a KSK with no corresponding DS record",
                    key.key_tag
                ));
            }
        }

        // Check for deprecated algorithms in DS records
        for ds in &ds_info {
            if ds.algorithm == 1 || ds.algorithm == 3 || ds.algorithm == 5 || ds.algorithm == 6 {
                issues.push(format!(
                    "DS record uses deprecated algorithm {} ({})",
                    ds.algorithm, ds.algorithm_name
                ));
            }
            if ds.digest_type == 1 {
                issues.push(
                    "DS record uses SHA-1 digest (type 1) - consider upgrading to SHA-256 (type 2)"
                        .to_string(),
                );
            }
        }

        // Check for deprecated algorithms in DNSKEY records
        for key in &dnskey_info {
            if key.algorithm == 1 || key.algorithm == 3 || key.algorithm == 5 || key.algorithm == 6
            {
                issues.push(format!(
                    "DNSKEY record uses deprecated algorithm {} ({})",
                    key.algorithm, key.algorithm_name
                ));
            }
        }

        // Derive chain_valid
        let chain_valid = has_ds
            && has_dnskey
            && !ds_info.is_empty()
            && ds_info.iter().all(|ds| ds.matched_key && ds.digest_verified);

        // Derive status from chain validity (not from issues list)
        let enabled = has_ds || has_dnskey;
        let status = if has_ds && has_dnskey {
            if chain_valid {
                "secure".to_string()
            } else {
                "misconfigured".to_string()
            }
        } else if !has_ds && !has_dnskey {
            "insecure".to_string()
        } else {
            "partial".to_string()
        };

        // Also flag the old structural issues
        if has_ds && !has_dnskey {
            issues.push(
                "DS records exist but no DNSKEY records found - DNSSEC may be broken".to_string(),
            );
        }
        if !has_ds && has_dnskey {
            issues.push(
                "DNSKEY records exist but no DS records at parent - DNSSEC chain incomplete"
                    .to_string(),
            );
        }

        Ok(DnssecReport {
            domain,
            enabled,
            has_ds_records: has_ds,
            has_dnskey_records: has_dnskey,
            ds_records: ds_info,
            dnskey_records: dnskey_info,
            issues,
            status,
            chain_valid,
        })
    }
```

- [ ] **Step 6: Verify it compiles**

Run: `cargo check -p seer-core 2>&1 | head -30`

Expected: May have compilation errors in output formatters (they reference `key_tag_hint`). The core logic should compile. Fix any import issues.

- [ ] **Step 7: Commit**

```bash
git add seer-core/src/dns/dnssec.rs
git commit -m "feat(dnssec): implement DS-to-DNSKEY cross-validation

Use hickory's calculate_key_tag() and to_digest() to verify that DS
records at the registry match DNSKEY records in DNS. Adds chain_valid
boolean and per-DS matched_key/digest_verified fields."
```

---

### Task 3: Fix DNSKEY-to-key-tag pairing robustness

The zip-based pairing in Task 2 step 5 between `dnskey_records` (from our resolver) and `raw_dnskeys` (from hickory) assumes they return in the same order and count. This is fragile. This task replaces it with a proper key-tag lookup.

**Files:**
- Modify: `seer-core/src/dns/dnssec.rs` (the DNSKEY info parsing section)

- [ ] **Step 1: Replace the zip-based DNSKEY parsing with key-tag map lookup**

Replace the DNSKEY info parsing section (the block starting with `// Parse DNSKEY record info with computed key tags`) with:

```rust
        // Build a map from (flags, algorithm, public_key_prefix) -> computed key_tag
        // to reliably match our RecordData DNSKEYs to the raw hickory ones.
        let key_tag_by_algo_flags: HashMap<(u16, u8), Vec<u16>> = {
            let mut map: HashMap<(u16, u8), Vec<u16>> = HashMap::new();
            for (dnskey, tag) in &raw_dnskeys {
                map.entry((dnskey.flags(), u8::from(dnskey.algorithm())))
                    .or_default()
                    .push(*tag);
            }
            map
        };

        // Parse DNSKEY record info with computed key tags
        let mut dnskey_tag_indices: HashMap<(u16, u8), usize> = HashMap::new();
        let dnskey_info: Vec<DnskeyInfo> = dnskey_records
            .iter()
            .filter_map(|r| {
                if let RecordData::DNSKEY {
                    flags,
                    protocol,
                    algorithm,
                    ..
                } = r.data
                {
                    let is_sep = flags & 0x0001 != 0;
                    let is_zone = flags & 0x0100 != 0;
                    let is_ksk = is_sep && is_zone;
                    let is_zsk = is_zone && !is_sep;

                    // Find the computed key tag for this DNSKEY
                    let idx = dnskey_tag_indices
                        .entry((flags, algorithm))
                        .or_insert(0);
                    let key_tag = key_tag_by_algo_flags
                        .get(&(flags, algorithm))
                        .and_then(|tags| tags.get(*idx))
                        .copied()
                        .unwrap_or(0);
                    *idx += 1;

                    Some(DnskeyInfo {
                        flags,
                        protocol,
                        algorithm,
                        key_tag,
                        is_ksk,
                        is_zsk,
                        algorithm_name: algorithm_name(algorithm),
                    })
                } else {
                    None
                }
            })
            .collect();
```

- [ ] **Step 2: Remove the unused DNSKEY dummy in the old zip chain**

Verify there are no remaining references to the old zip-based approach or the `DNSKEY::new(...)` dummy value. The `std::iter::repeat` import is no longer needed.

- [ ] **Step 3: Verify it compiles**

Run: `cargo check -p seer-core 2>&1 | head -30`

Expected: Core compiles. Formatter errors may remain (fixed in Task 4).

- [ ] **Step 4: Commit**

```bash
git add seer-core/src/dns/dnssec.rs
git commit -m "fix(dnssec): use robust key-tag matching instead of zip pairing

Match DNSKEYs by (flags, algorithm) groups with index tracking instead
of assuming raw hickory and our resolver return records in same order."
```

---

### Task 4: Update output formatters

**Files:**
- Modify: `seer-core/src/output/human.rs:1744-1819`
- Modify: `seer-core/src/output/markdown.rs:994-1054`

- [ ] **Step 1: Update the human formatter**

Replace the `format_dnssec` method in `seer-core/src/output/human.rs` (lines 1744-1820):

```rust
    fn format_dnssec(&self, report: &crate::dns::DnssecReport) -> String {
        let mut output = Vec::new();

        output.push(format!(
            "DNSSEC Report for {}",
            self.success(&sanitize_display(&report.domain))
        ));
        output.push(String::new());

        let status_colored = match report.status.as_str() {
            "secure" => self.success(&report.status),
            "insecure" | "partial" => self.warning(&report.status),
            _ => self.error(&report.status),
        };
        output.push(format!("  {}: {}", self.label("Status"), status_colored));
        let chain_colored = if report.chain_valid {
            self.success("valid")
        } else if report.has_ds_records && report.has_dnskey_records {
            self.error("invalid")
        } else {
            self.warning("n/a")
        };
        output.push(format!("  {}: {}", self.label("Chain Valid"), chain_colored));
        output.push(format!(
            "  {}: {}",
            self.label("Enabled"),
            self.value(&report.enabled.to_string())
        ));
        output.push(format!(
            "  {}: {}",
            self.label("DS Records"),
            self.value(&report.ds_records.len().to_string())
        ));
        output.push(format!(
            "  {}: {}",
            self.label("DNSKEY Records"),
            self.value(&report.dnskey_records.len().to_string())
        ));

        if !report.ds_records.is_empty() {
            output.push(String::new());
            output.push(format!("  {}:", self.label("DS Records")));
            for ds in &report.ds_records {
                let match_indicator = if ds.matched_key && ds.digest_verified {
                    self.success("\u{2713} verified")
                } else if ds.matched_key {
                    self.error("\u{2717} digest mismatch")
                } else {
                    self.error("\u{2717} no matching key")
                };
                output.push(format!(
                    "    Key Tag: {}, Algorithm: {} ({}), Digest: {} ({}) [{}]",
                    ds.key_tag,
                    ds.algorithm,
                    sanitize_display(&ds.algorithm_name),
                    ds.digest_type,
                    sanitize_display(&ds.digest_type_name),
                    match_indicator,
                ));
            }
        }

        if !report.dnskey_records.is_empty() {
            output.push(String::new());
            output.push(format!("  {}:", self.label("DNSKEY Records")));
            for key in &report.dnskey_records {
                let role = if key.is_ksk {
                    "KSK"
                } else if key.is_zsk {
                    "ZSK"
                } else {
                    "Other"
                };
                output.push(format!(
                    "    Key Tag: {}, Flags: {}, Role: {}, Algorithm: {} ({})",
                    key.key_tag,
                    key.flags,
                    role,
                    key.algorithm,
                    sanitize_display(&key.algorithm_name)
                ));
            }
        }

        if !report.issues.is_empty() {
            output.push(String::new());
            output.push(format!("  {}:", self.label("Issues")));
            for issue in &report.issues {
                output.push(format!("    - {}", sanitize_display(issue)));
            }
        }

        output.join("\n")
    }
```

- [ ] **Step 2: Update the markdown formatter**

Replace the `format_dnssec` method in `seer-core/src/output/markdown.rs` (starting at line 994). Read the full method first to find its end, then replace:

```rust
    fn format_dnssec(&self, report: &crate::dns::DnssecReport) -> String {
        let mut output = Vec::new();

        output.push(format!("## DNSSEC: {}", report.domain));
        output.push(String::new());

        output.push(format!("- **Status**: `{}`", report.status));
        output.push(format!(
            "- **Chain Valid**: {}",
            if report.chain_valid { "yes" } else { "no" }
        ));
        output.push(format!("- **Enabled**: {}", report.enabled));
        output.push(format!("- **DS Records**: {}", report.ds_records.len()));
        output.push(format!(
            "- **DNSKEY Records**: {}",
            report.dnskey_records.len()
        ));

        if !report.ds_records.is_empty() {
            output.push(String::new());
            output.push("### DS Records".to_string());
            output.push(String::new());
            output.push(
                "| Key Tag | Algorithm | Digest Type | Matched | Verified |".to_string(),
            );
            output.push("| --- | --- | --- | --- | --- |".to_string());
            for ds in &report.ds_records {
                output.push(format!(
                    "| {} | {} ({}) | {} ({}) | {} | {} |",
                    ds.key_tag,
                    ds.algorithm,
                    ds.algorithm_name,
                    ds.digest_type,
                    ds.digest_type_name,
                    if ds.matched_key { "yes" } else { "no" },
                    if ds.digest_verified { "yes" } else { "no" },
                ));
            }
        }

        if !report.dnskey_records.is_empty() {
            output.push(String::new());
            output.push("### DNSKEY Records".to_string());
            output.push(String::new());
            output.push("| Key Tag | Flags | Role | Algorithm |".to_string());
            output.push("| --- | --- | --- | --- |".to_string());
            for key in &report.dnskey_records {
                let role = if key.is_ksk {
                    "KSK"
                } else if key.is_zsk {
                    "ZSK"
                } else {
                    "Other"
                };
                output.push(format!(
                    "| {} | {} | {} | {} ({}) |",
                    key.key_tag, key.flags, role, key.algorithm, key.algorithm_name
                ));
            }
        }

        if !report.issues.is_empty() {
            output.push(String::new());
            output.push("### Issues".to_string());
            output.push(String::new());
            for issue in &report.issues {
                output.push(format!("- {}", issue));
            }
        }

        output.join("\n")
    }
```

- [ ] **Step 3: Verify everything compiles**

Run: `cargo check -p seer-core 2>&1 | head -30`

Expected: Clean compilation with no errors.

- [ ] **Step 4: Commit**

```bash
git add seer-core/src/output/human.rs seer-core/src/output/markdown.rs
git commit -m "feat(dnssec): update human and markdown formatters for chain validation

Display chain_valid, per-DS verification status, and computed key tags."
```

---

### Task 5: Add unit tests

**Files:**
- Modify: `seer-core/src/dns/dnssec.rs` (tests module at bottom)

- [ ] **Step 1: Add test for chain_valid derivation — all DS verified**

Add to the `#[cfg(test)] mod tests` block:

```rust
    #[test]
    fn test_chain_valid_all_verified() {
        let report = DnssecReport {
            domain: "example.com".to_string(),
            enabled: true,
            has_ds_records: true,
            has_dnskey_records: true,
            ds_records: vec![
                DsInfo {
                    key_tag: 12345,
                    algorithm: 13,
                    digest_type: 2,
                    digest: "ABCDEF".to_string(),
                    algorithm_name: "ECDSA P-256/SHA-256".to_string(),
                    digest_type_name: "SHA-256".to_string(),
                    matched_key: true,
                    digest_verified: true,
                },
                DsInfo {
                    key_tag: 12345,
                    algorithm: 13,
                    digest_type: 4,
                    digest: "FEDCBA".to_string(),
                    algorithm_name: "ECDSA P-256/SHA-256".to_string(),
                    digest_type_name: "SHA-384".to_string(),
                    matched_key: true,
                    digest_verified: true,
                },
            ],
            dnskey_records: vec![DnskeyInfo {
                flags: 257,
                protocol: 3,
                algorithm: 13,
                key_tag: 12345,
                is_ksk: true,
                is_zsk: false,
                algorithm_name: "ECDSA P-256/SHA-256".to_string(),
            }],
            issues: vec![],
            status: "secure".to_string(),
            chain_valid: true,
        };
        assert!(report.chain_valid);
        assert_eq!(report.status, "secure");
    }
```

- [ ] **Step 2: Add test for chain_valid derivation — DS unmatched**

```rust
    #[test]
    fn test_chain_valid_ds_unmatched() {
        let report = DnssecReport {
            domain: "broken.com".to_string(),
            enabled: true,
            has_ds_records: true,
            has_dnskey_records: true,
            ds_records: vec![DsInfo {
                key_tag: 99999,
                algorithm: 13,
                digest_type: 2,
                digest: "ABCDEF".to_string(),
                algorithm_name: "ECDSA P-256/SHA-256".to_string(),
                digest_type_name: "SHA-256".to_string(),
                matched_key: false,
                digest_verified: false,
            }],
            dnskey_records: vec![DnskeyInfo {
                flags: 257,
                protocol: 3,
                algorithm: 13,
                key_tag: 12345,
                is_ksk: true,
                is_zsk: false,
                algorithm_name: "ECDSA P-256/SHA-256".to_string(),
            }],
            issues: vec!["DS record (key_tag=99999) has no matching DNSKEY".to_string()],
            status: "misconfigured".to_string(),
            chain_valid: false,
        };
        assert!(!report.chain_valid);
        assert_eq!(report.status, "misconfigured");
    }
```

- [ ] **Step 3: Add test for chain_valid — digest mismatch**

```rust
    #[test]
    fn test_chain_valid_digest_mismatch() {
        let report = DnssecReport {
            domain: "mismatch.com".to_string(),
            enabled: true,
            has_ds_records: true,
            has_dnskey_records: true,
            ds_records: vec![DsInfo {
                key_tag: 12345,
                algorithm: 13,
                digest_type: 2,
                digest: "WRONG".to_string(),
                algorithm_name: "ECDSA P-256/SHA-256".to_string(),
                digest_type_name: "SHA-256".to_string(),
                matched_key: true,
                digest_verified: false,
            }],
            dnskey_records: vec![DnskeyInfo {
                flags: 257,
                protocol: 3,
                algorithm: 13,
                key_tag: 12345,
                is_ksk: true,
                is_zsk: false,
                algorithm_name: "ECDSA P-256/SHA-256".to_string(),
            }],
            issues: vec![],
            status: "misconfigured".to_string(),
            chain_valid: false,
        };
        assert!(!report.chain_valid);
        assert!(report.ds_records[0].matched_key);
        assert!(!report.ds_records[0].digest_verified);
    }
```

- [ ] **Step 4: Add integration test — live DNSSEC check against cloudflare.com**

```rust
    #[tokio::test]
    async fn test_live_dnssec_check_cloudflare() {
        let checker = DnssecChecker::new();
        let report = checker.check("cloudflare.com").await.unwrap();

        // cloudflare.com has DNSSEC enabled
        assert!(report.enabled, "cloudflare.com should have DNSSEC enabled");
        assert!(report.has_ds_records, "should have DS records");
        assert!(report.has_dnskey_records, "should have DNSKEY records");
        assert!(report.chain_valid, "cloudflare.com chain should be valid");
        assert_eq!(report.status, "secure");

        // All DS records should be verified
        for ds in &report.ds_records {
            assert!(ds.matched_key, "DS key_tag={} should match", ds.key_tag);
            assert!(
                ds.digest_verified,
                "DS key_tag={} digest should verify",
                ds.key_tag
            );
        }

        // Should have computed key tags on DNSKEYs
        for key in &report.dnskey_records {
            assert!(key.key_tag > 0, "key_tag should be computed");
        }
    }
```

- [ ] **Step 5: Add integration test — insecure domain**

```rust
    #[tokio::test]
    async fn test_live_dnssec_check_insecure() {
        let checker = DnssecChecker::new();
        // example.com does not have DNSSEC
        let report = checker.check("example.com").await.unwrap();

        assert!(!report.chain_valid);
        assert_eq!(report.status, "insecure");
    }
```

- [ ] **Step 6: Run all tests**

Run: `cargo test -p seer-core dnssec 2>&1`

Expected: All tests pass. The live tests require network access.

- [ ] **Step 7: Commit**

```bash
git add seer-core/src/dns/dnssec.rs
git commit -m "test(dnssec): add unit and integration tests for chain validation

Test chain_valid derivation for verified, unmatched, and mismatch cases.
Integration tests against cloudflare.com (secure) and example.com (insecure)."
```

---

### Task 6: Full build verification

**Files:** None (verification only)

- [ ] **Step 1: Run clippy**

Run: `cargo clippy -p seer-core -- -D warnings 2>&1 | tail -20`

Expected: No warnings or errors. Fix any clippy issues.

- [ ] **Step 2: Run cargo fmt**

Run: `cargo fmt -- --check 2>&1`

Expected: No formatting issues. If there are, run `cargo fmt` to fix.

- [ ] **Step 3: Run full test suite**

Run: `cargo test 2>&1 | tail -20`

Expected: All tests pass across all crates (seer-core, seer-cli, seer-py).

- [ ] **Step 4: Verify CLI works end-to-end**

Run: `cargo run -p seer-cli -- --format json dnssec cloudflare.com 2>&1 | head -5`

Expected: JSON output containing `"chain_valid":true`, `"matched_key":true`, `"digest_verified":true`, `"status":"secure"`.

- [ ] **Step 5: Commit any final fixes**

If any clippy/fmt fixes were needed:

```bash
git add -u
git commit -m "fix(dnssec): address clippy warnings and formatting"
```
