# DomainInfo Flat Struct Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a flat `DomainInfo` struct that merges RDAP+WHOIS data into column-per-field results, exposed as `info`/`bulk_info` across all layers.

**Architecture:** New `DomainInfo` type in seer-core with merge logic that checks RDAP first, fills gaps from WHOIS. A small prerequisite change adds `rdap_fallback` to `LookupResult::Whois` so partial RDAP data is preserved. The new type is plumbed through bulk executor, Python bindings, MCP server, and CLI.

**Tech Stack:** Rust (serde, chrono, tokio), PyO3, FastAPI/MCP, Clap

---

### Task 1: Add `rdap_fallback` to `LookupResult::Whois`

**Files:**
- Modify: `seer-core/src/lookup.rs`

- [ ] **Step 1: Add `rdap_fallback` field to the `Whois` variant**

In `seer-core/src/lookup.rs`, change the `Whois` variant of the `LookupResult` enum (around line 33) from:

```rust
Whois {
    data: WhoisResponse,
    rdap_error: Option<String>,
},
```

to:

```rust
Whois {
    data: WhoisResponse,
    rdap_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rdap_fallback: Option<Box<RdapResponse>>,
},
```

- [ ] **Step 2: Update `lookup_concurrent` to preserve partial RDAP data**

In `lookup_concurrent()` (around line 243), update the three places where `LookupResult::Whois` is constructed:

**Case 1 — RDAP succeeded but not useful, WHOIS succeeded (around line 272):**
Change:
```rust
return Ok(LookupResult::Whois {
    data: whois_data,
    rdap_error: Some("RDAP response incomplete".to_string()),
});
```
to:
```rust
return Ok(LookupResult::Whois {
    data: whois_data,
    rdap_error: Some("RDAP response incomplete".to_string()),
    rdap_fallback: Some(Box::new(rdap_data)),
});
```

Note: `rdap_data` is already in scope from the `if let Ok(rdap_data) = rdap_result` at line 260. You need to clone it before this point since it may also be used in the availability fallback path. Add `let rdap_data_clone = rdap_data.clone();` after the `is_rdap_response_useful` check fails, then use `rdap_data_clone` in the Whois variant and `rdap_data` in the availability fallback.

**Case 2 — RDAP failed entirely, WHOIS succeeded (around line 302):**
Change:
```rust
return Ok(LookupResult::Whois {
    data: whois_data,
    rdap_error: Some(rdap_error_str),
});
```
to:
```rust
return Ok(LookupResult::Whois {
    data: whois_data,
    rdap_error: Some(rdap_error_str),
    rdap_fallback: None,
});
```

- [ ] **Step 3: Fix all pattern matches on `LookupResult::Whois`**

Search the codebase for all destructures of `LookupResult::Whois { data, rdap_error }` or `LookupResult::Whois { data, .. }` and add the new field. Key locations:

- `seer-core/src/lookup.rs` — tests (around lines 384, 423)
- `seer-core/src/output/human.rs` — `format_lookup` method
- `seer-core/src/output/markdown.rs` — `format_lookup` method
- `seer-cli/src/utils.rs` — `bulk_results_to_csv` function (line 150)

For test constructors, add `rdap_fallback: None`. For pattern matches using `..`, no change needed.

Run: `cargo build -p seer-core -p seer-cli 2>&1` to find any remaining compile errors.

- [ ] **Step 4: Run tests**

Run: `cargo test -p seer-core`
Expected: All existing tests pass (the new field is `None` in existing test data).

- [ ] **Step 5: Commit**

```bash
git add seer-core/src/lookup.rs seer-core/src/output/human.rs seer-core/src/output/markdown.rs seer-cli/src/utils.rs
git commit -m "feat(lookup): preserve partial RDAP data in Whois fallback variant

Add rdap_fallback field to LookupResult::Whois so partial RDAP responses
are not discarded when WHOIS is the primary source."
```

---

### Task 2: Create `DomainInfo` struct and merge logic

**Files:**
- Create: `seer-core/src/domain_info.rs`
- Modify: `seer-core/src/lib.rs`

- [ ] **Step 1: Write tests for `DomainInfo` merge logic**

Create `seer-core/src/domain_info.rs` with the struct, source enum, and tests at the bottom. Start with tests only (implementations will be stubs):

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::lookup::LookupResult;
use crate::rdap::RdapResponse;
use crate::whois::WhoisResponse;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DomainInfoSource {
    Both,
    Rdap,
    Whois,
    Available,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainInfo {
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
    pub rdap_url: Option<String>,
}

impl DomainInfo {
    /// Merge RDAP and WHOIS data into a flat DomainInfo.
    /// RDAP fields take priority; WHOIS fills gaps.
    pub fn from_sources(
        domain: &str,
        rdap: Option<&RdapResponse>,
        whois: Option<&WhoisResponse>,
    ) -> Self {
        todo!()
    }

    /// Build DomainInfo from an existing LookupResult.
    pub fn from_lookup_result(result: &LookupResult) -> Self {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdap::{RdapEvent, RdapEntity, RdapNameserver, SecureDns};

    fn make_whois() -> WhoisResponse {
        WhoisResponse {
            domain: "example.com".to_string(),
            registrar: Some("WHOIS Registrar Inc.".to_string()),
            registrant: Some("Jane Doe".to_string()),
            organization: Some("WHOIS Org".to_string()),
            registrant_email: Some("jane@example.com".to_string()),
            registrant_phone: Some("+1.5551234567".to_string()),
            registrant_address: Some("123 Main St".to_string()),
            registrant_country: Some("US".to_string()),
            admin_name: Some("Admin Person".to_string()),
            admin_organization: Some("Admin Org".to_string()),
            admin_email: Some("admin@example.com".to_string()),
            admin_phone: Some("+1.5559876543".to_string()),
            tech_name: Some("Tech Person".to_string()),
            tech_organization: Some("Tech Org".to_string()),
            tech_email: Some("tech@example.com".to_string()),
            tech_phone: Some("+1.5551112222".to_string()),
            creation_date: Some("2020-01-15T00:00:00Z".parse().unwrap()),
            expiration_date: Some("2025-01-15T00:00:00Z".parse().unwrap()),
            updated_date: Some("2024-06-01T00:00:00Z".parse().unwrap()),
            nameservers: vec!["ns1.whois.example.com".to_string(), "ns2.whois.example.com".to_string()],
            status: vec!["clientTransferProhibited".to_string()],
            dnssec: Some("unsigned".to_string()),
            whois_server: "whois.example.com".to_string(),
            raw_response: String::new(),
        }
    }

    fn make_rdap() -> RdapResponse {
        let mut response = RdapResponse {
            object_class_name: Some("domain".to_string()),
            handle: Some("EXAMPLE-DOM".to_string()),
            ldh_name: Some("example.com".to_string()),
            unicode_name: None,
            status: vec!["active".to_string()],
            events: vec![
                RdapEvent {
                    event_action: "registration".to_string(),
                    event_date: Some("2019-06-01T00:00:00Z".to_string()),
                    event_actor: None,
                },
                RdapEvent {
                    event_action: "expiration".to_string(),
                    event_date: Some("2026-06-01T00:00:00Z".to_string()),
                    event_actor: None,
                },
                RdapEvent {
                    event_action: "last changed".to_string(),
                    event_date: Some("2024-03-15T00:00:00Z".to_string()),
                    event_actor: None,
                },
            ],
            entities: vec![
                RdapEntity {
                    object_class_name: None,
                    handle: None,
                    roles: vec!["registrar".to_string()],
                    public_ids: vec![],
                    vcard_array: Some(serde_json::json!(["vcard", [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "RDAP Registrar LLC"]
                    ]])),
                    entities: vec![],
                    remarks: vec![],
                    links: vec![],
                    events: vec![],
                    status: vec![],
                },
            ],
            nameservers: vec![
                RdapNameserver {
                    object_class_name: None,
                    ldh_name: Some("ns1.rdap.example.com".to_string()),
                    unicode_name: None,
                    ip_addresses: None,
                    status: vec![],
                    links: vec![],
                },
            ],
            secure_dns: Some(SecureDns {
                delegation_signed: Some(true),
                ds_data: vec![],
                key_data: vec![],
            }),
            links: vec![
                crate::rdap::RdapLink {
                    value: None,
                    rel: Some("self".to_string()),
                    href: Some("https://rdap.example.com/domain/example.com".to_string()),
                    media_type: None,
                },
            ],
            remarks: vec![],
            notices: vec![],
            port43: Some("whois.example.com".to_string()),
            start_address: None,
            end_address: None,
            ip_version: None,
            name: None,
            network_type: None,
            country: None,
            parent_handle: None,
            start_autnum: None,
            end_autnum: None,
            extra: Default::default(),
        };
        response
    }

    #[test]
    fn test_from_sources_both() {
        let rdap = make_rdap();
        let whois = make_whois();
        let info = DomainInfo::from_sources("example.com", Some(&rdap), Some(&whois));

        assert_eq!(info.source, DomainInfoSource::Both);
        assert_eq!(info.domain, "example.com");
        // RDAP takes priority for registrar
        assert_eq!(info.registrar.as_deref(), Some("RDAP Registrar LLC"));
        // RDAP dates take priority
        assert_eq!(info.creation_date, Some("2019-06-01T00:00:00Z".parse().unwrap()));
        assert_eq!(info.expiration_date, Some("2026-06-01T00:00:00Z".parse().unwrap()));
        // RDAP nameservers take priority (non-empty)
        assert_eq!(info.nameservers, vec!["ns1.rdap.example.com"]);
        // RDAP has no registrant entity, so WHOIS fills the gap
        assert_eq!(info.registrant.as_deref(), Some("Jane Doe"));
        assert_eq!(info.organization.as_deref(), Some("WHOIS Org"));
        // RDAP has no registrant contact, WHOIS fills
        assert_eq!(info.registrant_email.as_deref(), Some("jane@example.com"));
        // RDAP dnssec
        assert_eq!(info.dnssec.as_deref(), Some("signed"));
        // RDAP status takes priority
        assert_eq!(info.status, vec!["active"]);
        // Metadata
        assert_eq!(info.rdap_url.as_deref(), Some("https://rdap.example.com/domain/example.com"));
        assert_eq!(info.whois_server.as_deref(), Some("whois.example.com"));
    }

    #[test]
    fn test_from_sources_whois_only() {
        let whois = make_whois();
        let info = DomainInfo::from_sources("example.com", None, Some(&whois));

        assert_eq!(info.source, DomainInfoSource::Whois);
        assert_eq!(info.registrar.as_deref(), Some("WHOIS Registrar Inc."));
        assert_eq!(info.creation_date, Some("2020-01-15T00:00:00Z".parse().unwrap()));
        assert_eq!(info.nameservers, vec!["ns1.whois.example.com", "ns2.whois.example.com"]);
        assert_eq!(info.admin_name.as_deref(), Some("Admin Person"));
        assert_eq!(info.tech_email.as_deref(), Some("tech@example.com"));
        assert!(info.rdap_url.is_none());
    }

    #[test]
    fn test_from_sources_rdap_only() {
        let rdap = make_rdap();
        let info = DomainInfo::from_sources("example.com", Some(&rdap), None);

        assert_eq!(info.source, DomainInfoSource::Rdap);
        assert_eq!(info.registrar.as_deref(), Some("RDAP Registrar LLC"));
        // No WHOIS to fill contact gaps
        assert!(info.registrant_email.is_none());
        assert!(info.whois_server.is_none());
    }

    #[test]
    fn test_from_sources_neither() {
        let info = DomainInfo::from_sources("example.com", None, None);

        assert_eq!(info.source, DomainInfoSource::Available);
        assert_eq!(info.domain, "example.com");
        assert!(info.registrar.is_none());
        assert!(info.nameservers.is_empty());
    }

    #[test]
    fn test_from_lookup_result_rdap_variant() {
        let rdap = make_rdap();
        let whois = make_whois();
        let result = LookupResult::Rdap {
            data: Box::new(rdap),
            whois_fallback: Some(whois),
        };
        let info = DomainInfo::from_lookup_result(&result);

        assert_eq!(info.source, DomainInfoSource::Both);
        assert_eq!(info.registrar.as_deref(), Some("RDAP Registrar LLC"));
        assert_eq!(info.registrant.as_deref(), Some("Jane Doe"));
    }

    #[test]
    fn test_from_lookup_result_whois_variant() {
        let whois = make_whois();
        let result = LookupResult::Whois {
            data: whois,
            rdap_error: Some("RDAP failed".to_string()),
            rdap_fallback: None,
        };
        let info = DomainInfo::from_lookup_result(&result);

        assert_eq!(info.source, DomainInfoSource::Whois);
        assert_eq!(info.registrar.as_deref(), Some("WHOIS Registrar Inc."));
    }

    #[test]
    fn test_serialization_round_trip() {
        let whois = make_whois();
        let info = DomainInfo::from_sources("example.com", None, Some(&whois));
        let json = serde_json::to_string(&info).unwrap();
        let deserialized: DomainInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.domain, "example.com");
        assert_eq!(deserialized.registrar, info.registrar);
        assert_eq!(deserialized.source, DomainInfoSource::Whois);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p seer-core domain_info`
Expected: FAIL — `todo!()` panics.

- [ ] **Step 3: Implement `from_sources`**

Replace the `todo!()` in `from_sources` with:

```rust
pub fn from_sources(
    domain: &str,
    rdap: Option<&RdapResponse>,
    whois: Option<&WhoisResponse>,
) -> Self {
    let source = match (rdap.is_some(), whois.is_some()) {
        (true, true) => DomainInfoSource::Both,
        (true, false) => DomainInfoSource::Rdap,
        (false, true) => DomainInfoSource::Whois,
        (false, false) => DomainInfoSource::Available,
    };

    // Helper: try RDAP first, then WHOIS
    let rdap_registrant_contact = rdap.and_then(|r| r.get_registrant_contact());
    let rdap_admin_contact = rdap.and_then(|r| r.get_admin_contact());
    let rdap_tech_contact = rdap.and_then(|r| r.get_tech_contact());

    let registrar = rdap
        .and_then(|r| r.get_registrar())
        .or_else(|| whois.and_then(|w| w.registrar.clone()));

    let registrant = rdap
        .and_then(|r| r.get_registrant())
        .or_else(|| whois.and_then(|w| w.registrant.clone()));

    let organization = rdap
        .and_then(|r| r.get_registrant_organization())
        .or_else(|| whois.and_then(|w| w.organization.clone()));

    let creation_date = rdap
        .and_then(|r| r.creation_date())
        .or_else(|| whois.and_then(|w| w.creation_date));

    let expiration_date = rdap
        .and_then(|r| r.expiration_date())
        .or_else(|| whois.and_then(|w| w.expiration_date));

    let updated_date = rdap
        .and_then(|r| r.last_updated())
        .or_else(|| whois.and_then(|w| w.updated_date));

    let rdap_nameservers = rdap.map(|r| r.nameserver_names()).unwrap_or_default();
    let nameservers = if !rdap_nameservers.is_empty() {
        rdap_nameservers
    } else {
        whois.map(|w| w.nameservers.clone()).unwrap_or_default()
    };

    let rdap_status = rdap.map(|r| r.status.clone()).unwrap_or_default();
    let status = if !rdap_status.is_empty() {
        rdap_status
    } else {
        whois.map(|w| w.status.clone()).unwrap_or_default()
    };

    let dnssec = rdap
        .and_then(|r| {
            r.secure_dns.as_ref().map(|s| {
                if s.delegation_signed.unwrap_or(false) {
                    "signed".to_string()
                } else {
                    "unsigned".to_string()
                }
            })
        })
        .or_else(|| whois.and_then(|w| w.dnssec.clone()));

    let registrant_email = rdap_registrant_contact
        .as_ref()
        .and_then(|c| c.email.clone())
        .or_else(|| whois.and_then(|w| w.registrant_email.clone()));

    let registrant_phone = rdap_registrant_contact
        .as_ref()
        .and_then(|c| c.phone.clone())
        .or_else(|| whois.and_then(|w| w.registrant_phone.clone()));

    let registrant_address = rdap_registrant_contact
        .as_ref()
        .and_then(|c| c.address.clone())
        .or_else(|| whois.and_then(|w| w.registrant_address.clone()));

    let registrant_country = rdap_registrant_contact
        .as_ref()
        .and_then(|c| c.country.clone())
        .or_else(|| whois.and_then(|w| w.registrant_country.clone()));

    let admin_name = rdap_admin_contact
        .as_ref()
        .and_then(|c| c.name.clone())
        .or_else(|| whois.and_then(|w| w.admin_name.clone()));

    let admin_organization = rdap_admin_contact
        .as_ref()
        .and_then(|c| c.organization.clone())
        .or_else(|| whois.and_then(|w| w.admin_organization.clone()));

    let admin_email = rdap_admin_contact
        .as_ref()
        .and_then(|c| c.email.clone())
        .or_else(|| whois.and_then(|w| w.admin_email.clone()));

    let admin_phone = rdap_admin_contact
        .as_ref()
        .and_then(|c| c.phone.clone())
        .or_else(|| whois.and_then(|w| w.admin_phone.clone()));

    let tech_name = rdap_tech_contact
        .as_ref()
        .and_then(|c| c.name.clone())
        .or_else(|| whois.and_then(|w| w.tech_name.clone()));

    let tech_organization = rdap_tech_contact
        .as_ref()
        .and_then(|c| c.organization.clone())
        .or_else(|| whois.and_then(|w| w.tech_organization.clone()));

    let tech_email = rdap_tech_contact
        .as_ref()
        .and_then(|c| c.email.clone())
        .or_else(|| whois.and_then(|w| w.tech_email.clone()));

    let tech_phone = rdap_tech_contact
        .as_ref()
        .and_then(|c| c.phone.clone())
        .or_else(|| whois.and_then(|w| w.tech_phone.clone()));

    let whois_server = whois
        .map(|w| w.whois_server.clone())
        .filter(|s| !s.is_empty());

    let rdap_url = rdap.and_then(|r| {
        r.links
            .iter()
            .find(|l| l.rel.as_deref() == Some("self"))
            .and_then(|l| l.href.clone())
    });

    DomainInfo {
        domain: domain.to_string(),
        source,
        registrar,
        registrant,
        organization,
        creation_date,
        expiration_date,
        updated_date,
        nameservers,
        status,
        dnssec,
        registrant_email,
        registrant_phone,
        registrant_address,
        registrant_country,
        admin_name,
        admin_organization,
        admin_email,
        admin_phone,
        tech_name,
        tech_organization,
        tech_email,
        tech_phone,
        whois_server,
        rdap_url,
    }
}
```

- [ ] **Step 4: Implement `from_lookup_result`**

Replace the `todo!()` in `from_lookup_result` with:

```rust
pub fn from_lookup_result(result: &LookupResult) -> Self {
    match result {
        LookupResult::Rdap {
            data,
            whois_fallback,
        } => {
            let domain = data
                .domain_name()
                .unwrap_or("unknown")
                .to_string();
            Self::from_sources(&domain, Some(data), whois_fallback.as_ref())
        }
        LookupResult::Whois {
            data,
            rdap_fallback,
            ..
        } => Self::from_sources(
            &data.domain,
            rdap_fallback.as_deref(),
            Some(data),
        ),
        LookupResult::Available { data, .. } => {
            let mut info = Self::from_sources(&data.domain, None, None);
            info.source = DomainInfoSource::Available;
            info
        }
    }
}
```

- [ ] **Step 5: Register module in lib.rs**

In `seer-core/src/lib.rs`, add after line 6 (`pub mod diff;`):

```rust
pub mod domain_info;
```

And add to the re-exports section (after line 41):

```rust
pub use domain_info::{DomainInfo, DomainInfoSource};
```

- [ ] **Step 6: Run tests**

Run: `cargo test -p seer-core domain_info`
Expected: All 7 tests pass.

- [ ] **Step 7: Commit**

```bash
git add seer-core/src/domain_info.rs seer-core/src/lib.rs
git commit -m "feat: add DomainInfo flat struct with RDAP+WHOIS merge logic

New DomainInfo type merges RDAP and WHOIS data into flat, column-per-field
results. RDAP fields take priority, WHOIS fills gaps."
```

---

### Task 3: Add `Info` variant to bulk executor

**Files:**
- Modify: `seer-core/src/bulk/executor.rs`

- [ ] **Step 1: Add `Info` variants to the enums**

In `seer-core/src/bulk/executor.rs`:

Add to `BulkOperation` enum (after `Avail` variant, around line 47):

```rust
Info {
    domain: String,
},
```

Add to `BulkResultData` enum (after `Avail` variant, around line 60):

```rust
Info(crate::domain_info::DomainInfo),
```

- [ ] **Step 2: Add `Info` to `execute_operation`**

In the `execute_operation` function (around line 314), add the new match arm after the `Avail` arm:

```rust
BulkOperation::Info { domain } => {
    let result = clients.lookup.lookup(domain).await?;
    Ok(BulkResultData::Info(crate::domain_info::DomainInfo::from_lookup_result(&result)))
}
```

- [ ] **Step 3: Add `Info` to the progress callback domain extraction**

In the `execute` method (around line 184), add `Info` to the match arm that extracts the domain string for progress reporting:

```rust
BulkOperation::Whois { domain }
| BulkOperation::Rdap { domain }
| BulkOperation::Dns { domain, .. }
| BulkOperation::Propagation { domain, .. }
| BulkOperation::Lookup { domain }
| BulkOperation::Status { domain }
| BulkOperation::Avail { domain }
| BulkOperation::Info { domain } => domain.as_str(),
```

- [ ] **Step 4: Add `execute_info` convenience method**

Add after `execute_avail` (around line 301):

```rust
pub async fn execute_info(&self, domains: Vec<String>) -> Vec<BulkResult> {
    let operations = domains
        .into_iter()
        .map(|domain| BulkOperation::Info { domain })
        .collect();
    self.execute(operations, None).await
}
```

- [ ] **Step 5: Update `get_domain_from_operation` in CLI utils**

In `seer-cli/src/utils.rs`, add to the `get_domain_from_operation` match (around line 357):

```rust
BulkOperation::Info { domain } => domain.clone(),
```

- [ ] **Step 6: Run tests**

Run: `cargo test -p seer-core bulk`
Expected: All existing bulk tests pass. The new `Info` variant is handled in all match arms.

Run: `cargo build -p seer-cli` to verify CLI compiles.

- [ ] **Step 7: Commit**

```bash
git add seer-core/src/bulk/executor.rs seer-cli/src/utils.rs
git commit -m "feat(bulk): add Info operation variant for DomainInfo results"
```

---

### Task 4: Add output formatting for DomainInfo

**Files:**
- Modify: `seer-core/src/output/mod.rs`
- Modify: `seer-core/src/output/human.rs`
- Modify: `seer-core/src/output/json.rs`
- Modify: `seer-core/src/output/markdown.rs`

- [ ] **Step 1: Add `format_domain_info` to the trait**

In `seer-core/src/output/mod.rs`, add to the `OutputFormatter` trait (after `format_ssl`, around line 54):

```rust
fn format_domain_info(&self, info: &crate::domain_info::DomainInfo) -> String;
```

Add to the `YamlFormatter` impl block (after `format_ssl`, around line 128):

```rust
fn format_domain_info(&self, info: &crate::domain_info::DomainInfo) -> String {
    self.to_yaml_value(info)
}
```

- [ ] **Step 2: Implement for JsonFormatter**

In `seer-core/src/output/json.rs`, add the method to the `OutputFormatter` impl (following the existing pattern of `serde_json::to_string_pretty`):

```rust
fn format_domain_info(&self, info: &crate::domain_info::DomainInfo) -> String {
    serde_json::to_string_pretty(info).unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
}
```

- [ ] **Step 3: Implement for HumanFormatter**

In `seer-core/src/output/human.rs`, add the method to the `OutputFormatter` impl. Follow the same `self.header()`, `self.label()`, `self.value()` pattern used in `format_lookup`:

```rust
fn format_domain_info(&self, info: &crate::domain_info::DomainInfo) -> String {
    let mut output = Vec::new();

    output.push(self.header(&format!(
        "Domain Info: {} (source: {:?})",
        sanitize_display(&info.domain),
        info.source
    )));

    // Registration
    if let Some(ref v) = info.registrar {
        output.push(format!("  {}: {}", self.label("Registrar"), self.value(&sanitize_display(v))));
    }
    if let Some(ref v) = info.registrant {
        output.push(format!("  {}: {}", self.label("Registrant"), self.value(&sanitize_display(v))));
    }
    if let Some(ref v) = info.organization {
        output.push(format!("  {}: {}", self.label("Organization"), self.value(&sanitize_display(v))));
    }

    // Dates
    if let Some(d) = info.creation_date {
        output.push(format!("  {}: {}", self.label("Created"), self.value(&d.format("%Y-%m-%d").to_string())));
    }
    if let Some(d) = info.expiration_date {
        output.push(format!("  {}: {}", self.label("Expires"), self.value(&d.format("%Y-%m-%d").to_string())));
    }
    if let Some(d) = info.updated_date {
        output.push(format!("  {}: {}", self.label("Updated"), self.value(&d.format("%Y-%m-%d").to_string())));
    }

    // DNS
    if !info.nameservers.is_empty() {
        output.push(format!("  {}: {}", self.label("Nameservers"), self.value(&info.nameservers.join(", "))));
    }
    if !info.status.is_empty() {
        output.push(format!("  {}: {}", self.label("Status"), self.value(&info.status.join(", "))));
    }
    if let Some(ref v) = info.dnssec {
        output.push(format!("  {}: {}", self.label("DNSSEC"), self.value(&sanitize_display(v))));
    }

    // Registrant contact
    let has_registrant_contact = info.registrant_email.is_some()
        || info.registrant_phone.is_some()
        || info.registrant_address.is_some()
        || info.registrant_country.is_some();
    if has_registrant_contact {
        output.push(format!("\n  {}:", self.label("Registrant Contact")));
        if let Some(ref v) = info.registrant_email {
            output.push(format!("    {}: {}", self.label("Email"), self.value(&sanitize_display(v))));
        }
        if let Some(ref v) = info.registrant_phone {
            output.push(format!("    {}: {}", self.label("Phone"), self.value(&sanitize_display(v))));
        }
        if let Some(ref v) = info.registrant_address {
            output.push(format!("    {}: {}", self.label("Address"), self.value(&sanitize_display(v))));
        }
        if let Some(ref v) = info.registrant_country {
            output.push(format!("    {}: {}", self.label("Country"), self.value(&sanitize_display(v))));
        }
    }

    // Admin contact
    let has_admin = info.admin_name.is_some() || info.admin_email.is_some()
        || info.admin_organization.is_some() || info.admin_phone.is_some();
    if has_admin {
        output.push(format!("\n  {}:", self.label("Admin Contact")));
        if let Some(ref v) = info.admin_name {
            output.push(format!("    {}: {}", self.label("Name"), self.value(&sanitize_display(v))));
        }
        if let Some(ref v) = info.admin_organization {
            output.push(format!("    {}: {}", self.label("Organization"), self.value(&sanitize_display(v))));
        }
        if let Some(ref v) = info.admin_email {
            output.push(format!("    {}: {}", self.label("Email"), self.value(&sanitize_display(v))));
        }
        if let Some(ref v) = info.admin_phone {
            output.push(format!("    {}: {}", self.label("Phone"), self.value(&sanitize_display(v))));
        }
    }

    // Tech contact
    let has_tech = info.tech_name.is_some() || info.tech_email.is_some()
        || info.tech_organization.is_some() || info.tech_phone.is_some();
    if has_tech {
        output.push(format!("\n  {}:", self.label("Tech Contact")));
        if let Some(ref v) = info.tech_name {
            output.push(format!("    {}: {}", self.label("Name"), self.value(&sanitize_display(v))));
        }
        if let Some(ref v) = info.tech_organization {
            output.push(format!("    {}: {}", self.label("Organization"), self.value(&sanitize_display(v))));
        }
        if let Some(ref v) = info.tech_email {
            output.push(format!("    {}: {}", self.label("Email"), self.value(&sanitize_display(v))));
        }
        if let Some(ref v) = info.tech_phone {
            output.push(format!("    {}: {}", self.label("Phone"), self.value(&sanitize_display(v))));
        }
    }

    // Metadata
    if info.whois_server.is_some() || info.rdap_url.is_some() {
        output.push(format!("\n  {}:", self.label("Protocol Metadata")));
        if let Some(ref v) = info.whois_server {
            output.push(format!("    {}: {}", self.label("WHOIS Server"), self.value(&sanitize_display(v))));
        }
        if let Some(ref v) = info.rdap_url {
            output.push(format!("    {}: {}", self.label("RDAP URL"), self.value(&sanitize_display(v))));
        }
    }

    output.join("\n")
}
```

- [ ] **Step 4: Implement for MarkdownFormatter**

In `seer-core/src/output/markdown.rs`, add the method. Follow the existing markdown patterns (using `##` headers, `| Key | Value |` tables):

```rust
fn format_domain_info(&self, info: &crate::domain_info::DomainInfo) -> String {
    let mut output = Vec::new();

    output.push(format!("## Domain Info: {}\n", sanitize_display(&info.domain)));
    output.push(format!("**Source:** {:?}\n", info.source));

    output.push("### Registration\n".to_string());
    output.push("| Field | Value |".to_string());
    output.push("|-------|-------|".to_string());
    output.push(format!("| Registrar | {} |", info.registrar.as_deref().unwrap_or("-")));
    output.push(format!("| Registrant | {} |", info.registrant.as_deref().unwrap_or("-")));
    output.push(format!("| Organization | {} |", info.organization.as_deref().unwrap_or("-")));
    output.push(format!("| Created | {} |", info.creation_date.map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or("-".into())));
    output.push(format!("| Expires | {} |", info.expiration_date.map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or("-".into())));
    output.push(format!("| Updated | {} |", info.updated_date.map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or("-".into())));
    output.push(format!("| Nameservers | {} |", if info.nameservers.is_empty() { "-".to_string() } else { info.nameservers.join(", ") }));
    output.push(format!("| Status | {} |", if info.status.is_empty() { "-".to_string() } else { info.status.join(", ") }));
    output.push(format!("| DNSSEC | {} |", info.dnssec.as_deref().unwrap_or("-")));

    output.push("\n### Contacts\n".to_string());
    output.push("| Role | Name | Organization | Email | Phone |".to_string());
    output.push("|------|------|--------------|-------|-------|".to_string());
    output.push(format!("| Registrant | {} | {} | {} | {} |",
        info.registrant.as_deref().unwrap_or("-"),
        info.organization.as_deref().unwrap_or("-"),
        info.registrant_email.as_deref().unwrap_or("-"),
        info.registrant_phone.as_deref().unwrap_or("-"),
    ));
    output.push(format!("| Admin | {} | {} | {} | {} |",
        info.admin_name.as_deref().unwrap_or("-"),
        info.admin_organization.as_deref().unwrap_or("-"),
        info.admin_email.as_deref().unwrap_or("-"),
        info.admin_phone.as_deref().unwrap_or("-"),
    ));
    output.push(format!("| Tech | {} | {} | {} | {} |",
        info.tech_name.as_deref().unwrap_or("-"),
        info.tech_organization.as_deref().unwrap_or("-"),
        info.tech_email.as_deref().unwrap_or("-"),
        info.tech_phone.as_deref().unwrap_or("-"),
    ));

    output.join("\n")
}
```

- [ ] **Step 5: Build to verify everything compiles**

Run: `cargo build -p seer-core`
Expected: Success.

- [ ] **Step 6: Commit**

```bash
git add seer-core/src/output/mod.rs seer-core/src/output/human.rs seer-core/src/output/json.rs seer-core/src/output/markdown.rs
git commit -m "feat(output): add format_domain_info to all output formatters"
```

---

### Task 5: Add Python bindings for `info` and `bulk_info`

**Files:**
- Modify: `seer-py/src/lib.rs`
- Modify: `seer-py/python/seer/__init__.py`

- [ ] **Step 1: Add `info` function to Python bindings**

In `seer-py/src/lib.rs`, add after the `diff` function (around line 574):

```rust
#[pyfunction]
fn info(py: Python<'_>, domain: String) -> PyResult<PyObject> {
    let rt = get_runtime();
    let smart_lookup = get_smart_lookup();

    let result = py.allow_threads(|| rt.block_on(async { smart_lookup.lookup(&domain).await }));

    match result {
        Ok(lookup_result) => {
            let domain_info = seer_core::domain_info::DomainInfo::from_lookup_result(&lookup_result);
            let json = serde_json::to_value(&domain_info)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            json_to_python(py, &json)
        }
        Err(e) => Err(PyRuntimeError::new_err(e.to_string())),
    }
}
```

- [ ] **Step 2: Add `bulk_info` function**

In `seer-py/src/lib.rs`, add after the `info` function:

```rust
#[pyfunction]
#[pyo3(signature = (domains, concurrency = 10))]
fn bulk_info(py: Python<'_>, domains: Vec<String>, concurrency: usize) -> PyResult<PyObject> {
    let rt = get_runtime();
    let executor = BulkExecutor::new().with_concurrency(validate_concurrency(concurrency)?);

    let operations: Vec<BulkOperation> = domains
        .into_iter()
        .map(|domain| BulkOperation::Info { domain })
        .collect();

    let result =
        py.allow_threads(|| rt.block_on(async { executor.execute(operations, None).await }));

    let json = serde_json::to_value(&result).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    json_to_python(py, &json)
}
```

- [ ] **Step 3: Register functions in the module**

In `seer-py/src/lib.rs`, add to the `_seer` module function (around line 641, after `diff`):

```rust
m.add_function(wrap_pyfunction!(info, m)?)?;
m.add_function(wrap_pyfunction!(bulk_info, m)?)?;
```

- [ ] **Step 4: Export from Python `__init__.py`**

In `seer-py/python/seer/__init__.py`, add `info` and `bulk_info` to the import (line 27):

```python
from seer._seer import (
    lookup,
    whois,
    rdap_domain,
    rdap_ip,
    rdap_asn,
    dig,
    propagation,
    status,
    bulk_lookup,
    bulk_whois,
    bulk_dig,
    bulk_propagation,
    bulk_status,
    bulk_availability,
    availability,
    subdomains,
    ssl,
    dnssec,
    dns_compare,
    dns_follow,
    diff,
    info,
    bulk_info,
)
```

And add to `__all__` (around line 61):

```python
__all__ = [
    # ... existing entries ...
    "diff",
    "info",
    "bulk_info",
]
```

- [ ] **Step 5: Build Python bindings**

Run: `cd seer-py && maturin develop --release`
Expected: Build succeeds.

- [ ] **Step 6: Quick smoke test**

Run: `python -c "import seer; print(seer.info('example.com').keys())"`
Expected: Prints dict keys matching DomainInfo fields (domain, source, registrar, registrant, etc.).

- [ ] **Step 7: Commit**

```bash
git add seer-py/src/lib.rs seer-py/python/seer/__init__.py
git commit -m "feat(py): add info() and bulk_info() Python bindings"
```

---

### Task 6: Add MCP server tools

**Files:**
- Modify: `seer-api/seer_api/mcp/server.py`

- [ ] **Step 1: Add `seer_info` tool definition**

In `seer-api/seer_api/mcp/server.py`, add to the `list_tools()` return list (after the last Tool, around line 307):

```python
Tool(
    name="seer_info",
    description="Get comprehensive domain registration info with all available fields merged from RDAP and WHOIS. Returns a flat structure with every field as a top-level key.",
    inputSchema={
        "type": "object",
        "properties": {
            "domain": {
                "type": "string",
                "description": "Domain name to look up (e.g., 'example.com')",
            },
        },
        "required": ["domain"],
    },
),
Tool(
    name="seer_bulk_info",
    description="Get comprehensive domain registration info for multiple domains. Merges RDAP and WHOIS data into flat, column-per-field results for each domain.",
    inputSchema={
        "type": "object",
        "properties": {
            "domains": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of domain names to look up",
                "maxItems": MAX_BULK_DOMAINS,
            },
            "concurrency": {
                "type": "integer",
                "description": f"Number of concurrent requests (default: 10, max: {MAX_CONCURRENCY})",
                "default": 10,
                "minimum": 1,
                "maximum": MAX_CONCURRENCY,
            },
        },
        "required": ["domains"],
    },
),
```

- [ ] **Step 2: Add tool execution cases**

In the `execute_tool` function's match statement (before the `case _:` default, around line 416):

```python
case "seer_info":
    domain = _require_str(arguments, "domain")
    return await loop.run_in_executor(None, seer.info, domain)

case "seer_bulk_info":
    domains = _require_domains(arguments)
    concurrency = _get_concurrency(arguments, default=10)
    return await loop.run_in_executor(
        None, seer.bulk_info, domains, concurrency
    )
```

- [ ] **Step 3: Commit**

```bash
git add seer-api/seer_api/mcp/server.py
git commit -m "feat(mcp): add seer_info and seer_bulk_info tools"
```

---

### Task 7: Add CLI `info` subcommand and bulk `info` operation

**Files:**
- Modify: `seer-cli/src/main.rs`
- Modify: `seer-cli/src/utils.rs`
- Modify: `seer-cli/src/repl/mod.rs`

- [ ] **Step 1: Add `Info` subcommand to the CLI enum**

In `seer-cli/src/main.rs`, add to the `Commands` enum (after `Lookup`, around line 83):

```rust
/// Comprehensive domain info (merges RDAP + WHOIS into flat fields)
Info {
    /// Domain name to look up
    domain: String,
},
```

- [ ] **Step 2: Add `Info` command handler in `execute_command`**

In `seer-cli/src/main.rs`, add a new arm in the `match command` block (after the `Commands::Lookup` arm, around line 351):

```rust
Commands::Info { domain } => {
    let spinner = std::sync::Arc::new(display::Spinner::new(&format!(
        "Getting comprehensive info for {}",
        domain
    )));

    let lookup = seer_core::SmartLookup::new();
    match lookup.lookup(&domain).await {
        Ok(result) => {
            spinner.finish();
            let info = seer_core::DomainInfo::from_lookup_result(&result);
            if quiet {
                handle_quiet_output(&info, &fields);
            } else {
                println!("{}", formatter.format_domain_info(&info));
            }
        }
        Err(e) => {
            spinner.finish();
            eprintln!("{} {}", "Error:".ctp_red(), e);
            std::process::exit(1);
        }
    }
}
```

- [ ] **Step 3: Add `info` to bulk operations**

In `seer-cli/src/main.rs`, in the `Commands::Bulk` match arm where operations are built (around line 493), add a new arm:

```rust
"info" => domains
    .iter()
    .map(|d: &String| seer_core::bulk::BulkOperation::Info { domain: d.clone() })
    .collect(),
```

Update the error message (around line 529) to include `info`:

```rust
"{} Unknown operation: {}. Use: lookup, whois, rdap, dig/dns, prop, status, avail, info",
```

- [ ] **Step 4: Add `info` CSV format to utils**

In `seer-cli/src/utils.rs`, add a header and row format for the `info` operation.

Add to the header match (around line 17):

```rust
"info" => {
    csv.push_str("domain,success,source,registrar,registrant,organization,created,expires,updated,nameservers,status,dnssec,registrant_email,registrant_phone,registrant_address,registrant_country,admin_name,admin_organization,admin_email,admin_phone,tech_name,tech_organization,tech_email,tech_phone,whois_server,rdap_url,duration_ms,error\n");
}
```

Add to the data row match (around line 47):

```rust
"info" => {
    if let Some(BulkResultData::Info(ref info)) = result.data {
        csv.push_str(&format!(
            "{},{},{:?},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
            domain,
            success,
            info.source,
            escape_csv_field(info.registrar.as_deref().unwrap_or("")),
            escape_csv_field(info.registrant.as_deref().unwrap_or("")),
            escape_csv_field(info.organization.as_deref().unwrap_or("")),
            info.creation_date.map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_default(),
            info.expiration_date.map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_default(),
            info.updated_date.map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_default(),
            escape_csv_field(&info.nameservers.join(";")),
            escape_csv_field(&info.status.join(";")),
            escape_csv_field(info.dnssec.as_deref().unwrap_or("")),
            escape_csv_field(info.registrant_email.as_deref().unwrap_or("")),
            escape_csv_field(info.registrant_phone.as_deref().unwrap_or("")),
            escape_csv_field(info.registrant_address.as_deref().unwrap_or("")),
            escape_csv_field(info.registrant_country.as_deref().unwrap_or("")),
            escape_csv_field(info.admin_name.as_deref().unwrap_or("")),
            escape_csv_field(info.admin_organization.as_deref().unwrap_or("")),
            escape_csv_field(info.admin_email.as_deref().unwrap_or("")),
            escape_csv_field(info.admin_phone.as_deref().unwrap_or("")),
            escape_csv_field(info.tech_name.as_deref().unwrap_or("")),
            escape_csv_field(info.tech_organization.as_deref().unwrap_or("")),
            escape_csv_field(info.tech_email.as_deref().unwrap_or("")),
            escape_csv_field(info.tech_phone.as_deref().unwrap_or("")),
            escape_csv_field(info.whois_server.as_deref().unwrap_or("")),
            escape_csv_field(info.rdap_url.as_deref().unwrap_or("")),
            duration_ms,
            error
        ));
    } else {
        csv.push_str(&format!(
            "{},{},,,,,,,,,,,,,,,,,,,,,,,,,{},{}\n",
            domain, success, duration_ms, error
        ));
    }
}
```

- [ ] **Step 5: Add `info` to REPL**

In `seer-cli/src/repl/mod.rs`, add an `info` match arm in the command dispatcher (around line 181, near the other command matches):

```rust
"info" => self.execute_info(args).await,
```

Add the `execute_info` method to the `Repl` impl (follow the same pattern as `execute_lookup`):

```rust
async fn execute_info(&mut self, args: &str) -> CommandResult {
    let domain = args.trim();
    if domain.is_empty() {
        return CommandResult::Error("Usage: info <domain>".to_string());
    }

    let lookup = seer_core::SmartLookup::new();
    match lookup.lookup(domain).await {
        Ok(result) => {
            let info = seer_core::DomainInfo::from_lookup_result(&result);
            let formatter = seer_core::output::get_formatter(self.context.output_format);
            println!("{}", formatter.format_domain_info(&info));
            CommandResult::Continue
        }
        Err(e) => CommandResult::Error(format!("Info failed: {}", e)),
    }
}
```

Add `info` to the REPL bulk operations match (around line 722, where bulk operation strings are matched):

```rust
"info" => domains
    .iter()
    .map(|d: &String| seer_core::bulk::BulkOperation::Info { domain: d.clone() })
    .collect(),
```

Update the REPL help text to mention `info` (near line 328):

```rust
println!(
    "  {}        Comprehensive domain info (RDAP + WHOIS merged)",
    "info".bright_green()
);
```

- [ ] **Step 6: Add `info` to REPL tab completer**

In `seer-cli/src/repl/completer.rs`, add `"info"` to the list of command completions (find the array/vec of command strings and add it).

- [ ] **Step 7: Build and test**

Run: `cargo build -p seer-cli`
Expected: Success.

Run: `cargo test -p seer-cli`
Expected: All tests pass.

- [ ] **Step 8: Commit**

```bash
git add seer-cli/src/main.rs seer-cli/src/utils.rs seer-cli/src/repl/mod.rs seer-cli/src/repl/completer.rs
git commit -m "feat(cli): add info subcommand, bulk info operation, and REPL support"
```

---

### Task 8: Update BULK_EXAMPLES and help text

**Files:**
- Modify: `seer-cli/src/main.rs`

- [ ] **Step 1: Add info examples to BULK_EXAMPLES**

In `seer-cli/src/main.rs`, add to the `BULK_EXAMPLES` const string. Add to the "Example Usage" section (around line 28):

```
  seer bulk info domains.txt               # Output: domains_results.csv
```

Add a new "Example Output" section (around line 52):

```
Example Output (info operation):
  domain,success,source,registrar,registrant,organization,created,expires,updated,nameservers,status,dnssec,registrant_email,registrant_phone,registrant_address,registrant_country,admin_name,admin_organization,admin_email,admin_phone,tech_name,tech_organization,tech_email,tech_phone,whois_server,rdap_url,duration_ms,error
  example.com,true,Both,RESERVED-Internet Assigned Numbers Authority,,Internet Assigned Numbers Authority,1995-08-14,2025-08-13,2024-08-14,a.iana-servers.net;b.iana-servers.net,client delete prohibited,signed,,,,,,,,,,,,,whois.iana.org,https://rdap.iana.org/domain/example.com,1523,
```

Update the `Bulk` operation description (line 117) to include `info`:

```rust
/// Operation type: lookup, whois, rdap, dig, prop, status, avail, info
```

- [ ] **Step 2: Commit**

```bash
git add seer-cli/src/main.rs
git commit -m "docs(cli): add info operation to bulk examples and help text"
```

---

### Task 9: Full integration test

**Files:** None (manual verification)

- [ ] **Step 1: Run full Rust test suite**

Run: `cargo test`
Expected: All tests pass across all crates.

- [ ] **Step 2: Run clippy**

Run: `cargo clippy -- -D warnings`
Expected: No warnings.

- [ ] **Step 3: Run formatter**

Run: `cargo fmt`
Expected: No changes (or apply formatting if needed).

- [ ] **Step 4: Build Python bindings and smoke test**

Run: `cd seer-py && maturin develop --release && cd ..`
Run: `python -c "import seer; r = seer.info('google.com'); print(r['source'], r['registrar'], r['expiration_date'])"`
Expected: Prints source (likely "both"), registrar name, and expiration date.

- [ ] **Step 5: Test bulk via CLI**

Create a test file:
```bash
echo -e "google.com\ngithub.com\nexample.com" > /tmp/test_domains.txt
```

Run: `cargo run -p seer-cli -- bulk info /tmp/test_domains.txt -o /tmp/info_results.csv`
Expected: CSV file with 28 columns, 3 data rows, all with `success=true`.

Run: `head -2 /tmp/info_results.csv`
Expected: Header row with all DomainInfo fields, first data row with populated fields.

- [ ] **Step 6: Test single domain via CLI**

Run: `cargo run -p seer-cli -- info example.com`
Expected: Human-formatted output with Domain Info header, registration, contacts, metadata sections.

Run: `cargo run -p seer-cli -- info example.com --format json`
Expected: Pretty-printed JSON with all DomainInfo fields.

- [ ] **Step 7: Commit any final fixes**

If any fixes were needed, commit them:
```bash
git add -A
git commit -m "fix: address integration test findings"
```
