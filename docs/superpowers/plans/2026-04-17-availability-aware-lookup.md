# Availability-Aware Lookup Display Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Route thin WHOIS responses + RDAP 404s (and explicit WHOIS "not registered") to `LookupResult::Available` with confidence-based verdicts, then surface those verdicts through every rendering surface (human, markdown, JSON, CSV, info, bulk, API/MCP pass-through).

**Architecture:** Extend `LookupResult::Available` to carry an optional `WhoisResponse`. Add two routing branches in `SmartLookup::lookup_concurrent` that synthesize `AvailabilityResult`s inline (no new network calls). Update formatters to render verdict/confidence language and a new `availability_verdict` column in bulk CSV.

**Tech Stack:** Rust (seer-core, seer-cli).

**Reference spec:** `docs/superpowers/specs/2026-04-17-availability-aware-lookup-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `seer-core/src/lookup.rs` | Modify | Add `whois_data` field to `Available`; add `rdap_error_is_404` + `whois_response_is_thin` helpers; add routing branches in `lookup_concurrent`; tests |
| `seer-core/src/output/human.rs` | Modify | Rewrite `LookupResult::Available` arm to render verdict language; handle `whois_data: Some` block |
| `seer-core/src/output/markdown.rs` | Modify | Mirror verdict/confidence/method/details in markdown |
| `seer-core/src/domain_info.rs` | Modify | Add `availability_verdict` field to `DomainInfo`; populate from `LookupResult::Available` |
| `seer-cli/src/utils.rs` | Modify | Add `availability_verdict` column to `lookup` and `info` bulk CSV |
| `seer-cli/src/main.rs` | Modify | `BULK_EXAMPLES` text updates to document new column |

---

## Implementation notes the engineer needs

**Existing `LookupResult::Available` variant (`seer-core/src/lookup.rs:157-162`):**
```rust
Available {
    data: Box<AvailabilityResult>,
    rdap_error: String,
    whois_error: String,
},
```
Serde tag is `#[serde(tag = "source", rename_all = "lowercase")]` at the enum level — so the JSON has `"source": "available"`.

**`AvailabilityResult` (`seer-core/src/availability.rs:15-26`):**
```rust
pub struct AvailabilityResult {
    pub domain: String,
    pub available: bool,
    pub confidence: String,   // "high" | "medium" | "none"
    pub method: String,
    pub details: Option<String>,
}
```

**`WhoisResponse::is_available()` (`seer-core/src/whois/parser.rs:286`)** scans the raw WHOIS response for "no match" / "not found" / etc. Already tested; reuse as-is.

**RDAP 404 error shape:** `SeerError::RdapError(String)` where the string is built at `seer-core/src/rdap/client.rs:603` as `format!("query failed with status {}", response.status())`. A 404 produces `"query failed with status 404 Not Found"`. Detection: check if the error string matches this pattern with status code 404.

**Confidence → verdict mapping used throughout:**
- `"high"` → `"available"` → header `(available)` → Verdict `AVAILABLE`
- `"medium"` → `"likely_available"` → header `(likely available)` → Verdict `MAY BE AVAILABLE`
- anything else (incl. `"none"`) → `"unknown"` → header `(status unknown)` → Verdict `UNKNOWN`

---

### Task 1: Extend `LookupResult::Available` with `whois_data`

**Files:**
- Modify: `seer-core/src/lookup.rs`

**Why:** Data-model foundation for every later task. Adds the optional field, updates the `trim_for_cache` pattern, and leaves every existing call site compilable.

- [ ] **Step 1: Add the `whois_data` field**

In `seer-core/src/lookup.rs` at the `LookupResult` enum (around line 157), replace the `Available { ... }` arm with:

```rust
    Available {
        data: Box<AvailabilityResult>,
        rdap_error: String,
        whois_error: String,
        /// Raw WHOIS response, when one was available at routing time
        /// (Cases A and B in the design spec). `None` preserves the
        /// pre-existing "both protocols errored" semantics.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        whois_data: Option<WhoisResponse>,
    },
```

- [ ] **Step 2: Update `trim_for_cache` to trim `whois_data` when present**

In `seer-core/src/lookup.rs`, find `fn trim_for_cache` (around line 250). The `Available { .. }` arm currently does nothing. Replace it with:

```rust
        LookupResult::Available {
            ref mut whois_data,
            ..
        } => {
            if let Some(ref mut w) = whois_data {
                if w.raw_response.len() > MAX_RAW {
                    w.raw_response.truncate(MAX_RAW);
                    w.raw_response.push_str("\n... [truncated for cache]");
                }
            }
        }
```

- [ ] **Step 3: Update the existing `availability_fallback` call site**

In `seer-core/src/lookup.rs`, find `async fn availability_fallback` (around line 550). The function returns `Ok(LookupResult::Available { data, rdap_error, whois_error })`. Add the new field as `None`:

```rust
        match self.availability_checker.check(domain).await {
            Ok(avail) => Ok(LookupResult::Available {
                data: Box::new(avail),
                rdap_error: sanitize_error_for_public(&rdap_error),
                whois_error: sanitize_error_for_public(&whois_error),
                whois_data: None,
            }),
```

- [ ] **Step 4: Fix any other `LookupResult::Available { ... }` construction sites**

Search for `LookupResult::Available {` in the workspace:

```bash
grep -rn "LookupResult::Available {" /home/zac/Projects/arcanum_suite/seer
```

Every construction site must include `whois_data: None` (or `whois_data: Some(...)` later). Add the field to each one. Most sites will be in tests under `seer-core/src/lookup.rs`.

- [ ] **Step 5: Build and test**

Run: `cargo build --workspace`
Expected: Success.

Run: `cargo test --workspace`
Expected: all PASS.

Run: `cargo clippy --workspace -- -D warnings`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add seer-core/src/lookup.rs
git commit -m "feat(lookup): add whois_data field to LookupResult::Available

Prepares the data model to carry a WHOIS response alongside the
AvailabilityResult when routing reclassifies a thin WHOIS as
'available' (Cases A and B in the design spec). None preserves
existing serialization and semantics."
```

---

### Task 2: Add `rdap_error_is_404` helper with tests

**Files:**
- Modify: `seer-core/src/lookup.rs`

**Why:** Case B's gate requires detecting an RDAP error that originated from a 404 response. Keep the detection as a small pure function that's independently testable.

- [ ] **Step 1: Write failing tests**

At the bottom of `seer-core/src/lookup.rs`, inside the existing `#[cfg(test)] mod tests` block (find `mod tests {`), add:

```rust
    #[test]
    fn rdap_error_is_404_matches_standard_404() {
        let e = SeerError::RdapError("query failed with status 404 Not Found".to_string());
        assert!(rdap_error_is_404(&e));
    }

    #[test]
    fn rdap_error_is_404_matches_without_reason_phrase() {
        let e = SeerError::RdapError("query failed with status 404".to_string());
        assert!(rdap_error_is_404(&e));
    }

    #[test]
    fn rdap_error_is_404_rejects_other_statuses() {
        let e = SeerError::RdapError("query failed with status 500 Server Error".to_string());
        assert!(!rdap_error_is_404(&e));
        let e = SeerError::RdapError("query failed with status 400 Bad Request".to_string());
        assert!(!rdap_error_is_404(&e));
    }

    #[test]
    fn rdap_error_is_404_rejects_non_http_errors() {
        let e = SeerError::RdapError("connection timeout".to_string());
        assert!(!rdap_error_is_404(&e));
        let e = SeerError::Timeout("rdap".to_string());
        assert!(!rdap_error_is_404(&e));
    }

    #[test]
    fn rdap_error_is_404_rejects_incidental_404_in_message() {
        // A 404 substring inside a non-status context must not match.
        let e = SeerError::RdapError("error 40404: database corruption".to_string());
        assert!(!rdap_error_is_404(&e));
    }
```

- [ ] **Step 2: Run tests — expect compile failure**

Run: `cargo test -p seer-core lookup::tests::rdap_error_is_404`
Expected: compile error — `rdap_error_is_404` is not defined.

- [ ] **Step 3: Implement the helper**

In `seer-core/src/lookup.rs`, add the helper at module scope (near `sanitize_error_for_public`, around line 79):

```rust
/// Returns true if the error is an RDAP HTTP 404 response, indicating the
/// registry's RDAP server has no entry for this domain. Other RDAP errors
/// (timeouts, 5xx, connection failures, etc.) do NOT match — they mean "we
/// don't know", not "not registered".
///
/// Matches the format produced by `seer-core/src/rdap/client.rs:603`:
/// `"query failed with status 404 ..."`.
fn rdap_error_is_404(err: &SeerError) -> bool {
    if let SeerError::RdapError(msg) = err {
        msg.contains("query failed with status 404")
    } else {
        false
    }
}
```

- [ ] **Step 4: Run tests — expect pass**

Run: `cargo test -p seer-core lookup::tests::rdap_error_is_404`
Expected: 5 PASS.

- [ ] **Step 5: Commit**

```bash
git add seer-core/src/lookup.rs
git commit -m "feat(lookup): add rdap_error_is_404 detection helper

Pure function that recognizes the specific 'status 404' signature
produced by our RDAP client. Gates the upcoming availability-routing
branch for thin WHOIS + RDAP 404."
```

---

### Task 3: Add `whois_response_is_thin` helper with tests

**Files:**
- Modify: `seer-core/src/lookup.rs`

**Why:** Case B's second gate — the parsed WHOIS has no identifying registration data. Keep the definition of "thin" in one pure function so it's testable and reusable.

- [ ] **Step 1: Write failing tests**

Inside the same `#[cfg(test)] mod tests` block, add:

```rust
    fn empty_whois(domain: &str) -> WhoisResponse {
        WhoisResponse {
            domain: domain.to_string(),
            registrar: None,
            registrant: None,
            organization: None,
            registrant_email: None,
            registrant_phone: None,
            registrant_address: None,
            registrant_country: None,
            admin_name: None,
            admin_organization: None,
            admin_email: None,
            admin_phone: None,
            tech_name: None,
            tech_organization: None,
            tech_email: None,
            tech_phone: None,
            creation_date: None,
            expiration_date: None,
            updated_date: None,
            nameservers: vec![],
            status: vec![],
            dnssec: None,
            whois_server: None,
            raw_response: String::new(),
        }
    }

    #[test]
    fn whois_response_is_thin_when_all_key_fields_missing() {
        let w = empty_whois("example.com");
        assert!(whois_response_is_thin(&w));
    }

    #[test]
    fn whois_response_is_not_thin_when_registrar_present() {
        let mut w = empty_whois("example.com");
        w.registrar = Some("Test Registrar".to_string());
        assert!(!whois_response_is_thin(&w));
    }

    #[test]
    fn whois_response_is_not_thin_when_creation_date_present() {
        let mut w = empty_whois("example.com");
        w.creation_date = Some(chrono::Utc::now());
        assert!(!whois_response_is_thin(&w));
    }

    #[test]
    fn whois_response_is_not_thin_when_expiration_date_present() {
        let mut w = empty_whois("example.com");
        w.expiration_date = Some(chrono::Utc::now());
        assert!(!whois_response_is_thin(&w));
    }

    #[test]
    fn whois_response_is_thin_even_with_nameservers_alone() {
        // Nameservers alone don't prove registration — some registries list
        // orphan nameservers or return generic placeholders.
        let mut w = empty_whois("example.com");
        w.nameservers = vec!["ns1.example.net".to_string()];
        assert!(whois_response_is_thin(&w));
    }
```

- [ ] **Step 2: Run tests — expect compile failure**

Run: `cargo test -p seer-core lookup::tests::whois_response_is_thin`
Expected: compile error — `whois_response_is_thin` not defined.

- [ ] **Step 3: Implement the helper**

In `seer-core/src/lookup.rs`, at module scope near `rdap_error_is_404`:

```rust
/// Returns true if the parsed WHOIS response lacks all key registration
/// signals: no registrar, no creation date, and no expiration date.
///
/// This is a necessary-but-not-sufficient signal for domain availability;
/// `lookup_concurrent` combines it with an RDAP 404 before routing to the
/// availability path. Nameservers alone don't disqualify thinness — some
/// registries return placeholder nameservers for unregistered domains.
fn whois_response_is_thin(w: &WhoisResponse) -> bool {
    w.registrar.is_none() && w.creation_date.is_none() && w.expiration_date.is_none()
}
```

- [ ] **Step 4: Run tests — expect pass**

Run: `cargo test -p seer-core lookup::tests::whois_response_is_thin`
Expected: 5 PASS.

- [ ] **Step 5: Commit**

```bash
git add seer-core/src/lookup.rs
git commit -m "feat(lookup): add whois_response_is_thin detection helper

Returns true when the parsed WHOIS lacks registrar + both registration
dates. Nameservers alone don't disqualify thinness since some registries
return orphan/placeholder NS for unregistered domains."
```

---

### Task 4: Wire routing Cases A and B in `lookup_concurrent`

**Files:**
- Modify: `seer-core/src/lookup.rs`

**Why:** This is the behavior change. When WHOIS succeeds but `is_available()` is true (Case A) or the response is thin + RDAP 404 (Case B), synthesize an `AvailabilityResult` and route to `LookupResult::Available` instead of `LookupResult::Whois`.

- [ ] **Step 1: Write failing integration-style tests**

Inside the `#[cfg(test)] mod tests` block, add. These assert on `SmartLookup` by constructing a `WhoisResponse` directly and passing it through a helper. To avoid spinning up real network calls, we unit-test a small pure classifier function that mirrors the routing decision.

First, add the classifier tests:

```rust
    use crate::rdap::RdapResponse;

    fn make_empty_rdap_response() -> RdapResponse {
        serde_json::from_value(serde_json::json!({
            "objectClassName": "domain",
        }))
        .expect("valid minimal RDAP response")
    }

    #[test]
    fn classify_whois_leg_case_a_high_confidence() {
        // Case A: WHOIS explicitly indicates no registration.
        let mut w = empty_whois("zaccodes.com");
        w.raw_response = "No match for \"ZACCODES.COM\".".to_string();
        assert!(w.is_available());
        let rdap_err = SeerError::RdapError("query failed with status 404 Not Found".to_string());
        let (verdict, method) = classify_whois_leg(&w, &rdap_err)
            .expect("expected a routing decision");
        assert_eq!(verdict, "high");
        assert_eq!(method, "whois");
    }

    #[test]
    fn classify_whois_leg_case_b_medium_confidence() {
        // Case B: thin WHOIS + RDAP 404.
        let w = empty_whois("example.xyz");
        assert!(!w.is_available(), "this WHOIS body has no 'no match' text");
        let rdap_err = SeerError::RdapError("query failed with status 404 Not Found".to_string());
        let (verdict, method) = classify_whois_leg(&w, &rdap_err)
            .expect("expected a routing decision");
        assert_eq!(verdict, "medium");
        assert_eq!(method, "whois_thin_response");
    }

    #[test]
    fn classify_whois_leg_rejects_thin_whois_without_404() {
        // Thin WHOIS but RDAP errored for non-404 reasons → no availability routing.
        let w = empty_whois("example.xyz");
        let rdap_err = SeerError::RdapError("connection timeout".to_string());
        assert!(classify_whois_leg(&w, &rdap_err).is_none());
    }

    #[test]
    fn classify_whois_leg_rejects_whois_with_real_data() {
        // Real registration data + RDAP 404 (legacy TLD) → stay on Whois.
        let mut w = empty_whois("legacy.tld");
        w.registrar = Some("Legacy Registry".to_string());
        w.creation_date = Some(chrono::Utc::now());
        let rdap_err = SeerError::RdapError("query failed with status 404 Not Found".to_string());
        assert!(classify_whois_leg(&w, &rdap_err).is_none());
    }

    #[test]
    fn classify_whois_leg_case_a_wins_over_case_b() {
        // Explicit "no match" + thin response → Case A (high), not Case B (medium).
        let mut w = empty_whois("example.com");
        w.raw_response = "No match for \"EXAMPLE.COM\".".to_string();
        let rdap_err = SeerError::RdapError("query failed with status 404 Not Found".to_string());
        let (verdict, _) = classify_whois_leg(&w, &rdap_err).unwrap();
        assert_eq!(verdict, "high");
    }
```

- [ ] **Step 2: Run tests — expect compile failure**

Run: `cargo test -p seer-core lookup::tests::classify_whois_leg`
Expected: compile error — `classify_whois_leg` not defined.

- [ ] **Step 3: Implement the classifier**

In `seer-core/src/lookup.rs` at module scope near `whois_response_is_thin`:

```rust
/// Decides whether a WHOIS response + RDAP error combination should route
/// to the availability path. Returns `(confidence, method)` when routing is
/// warranted, `None` to keep the existing `LookupResult::Whois` behavior.
///
/// The caller is responsible for constructing the final `AvailabilityResult`
/// from the returned `(confidence, method)`; this function is pure and has
/// no I/O so it can be unit-tested directly.
fn classify_whois_leg(w: &WhoisResponse, rdap_err: &SeerError) -> Option<(&'static str, &'static str)> {
    // Case A: WHOIS explicitly says "no match" (takes precedence).
    if w.is_available() {
        return Some(("high", "whois"));
    }
    // Case B: thin WHOIS AND RDAP returned a 404 from the registry.
    if whois_response_is_thin(w) && rdap_error_is_404(rdap_err) {
        return Some(("medium", "whois_thin_response"));
    }
    None
}
```

- [ ] **Step 4: Run classifier tests — expect pass**

Run: `cargo test -p seer-core lookup::tests::classify_whois_leg`
Expected: 5 PASS.

- [ ] **Step 5: Rewire `lookup_concurrent` to consult the classifier**

In `seer-core/src/lookup.rs`, find the WHOIS-leg handler in `lookup_concurrent` (around line 518):

```rust
        if let LegOutcome::Completed(Ok(whois_data)) = whois_leg {
            debug!("Using WHOIS result (RDAP not useful)");
            if let Some(ref cb) = progress {
                cb("RDAP not available (using WHOIS)");
            }
            return Ok(LookupResult::Whois {
                data: whois_data,
                rdap_error: Some(rdap_error_str),
                rdap_fallback: rdap_fallback_data,
            });
        }
```

Replace with a version that first consults the classifier. Note: we need access to the original `SeerError` to pass to `rdap_error_is_404`. Currently `rdap_outcome` has already been consumed. We need to preserve the `SeerError` when we destructure `RdapOutcome::Error` earlier in the function. Look for the match block starting `let (rdap_error_str, rdap_fallback_data) = match rdap_outcome` (around line 498). Replace with:

```rust
        let (rdap_error_str, rdap_fallback_data, rdap_seer_error) = match rdap_outcome {
            RdapOutcome::Useful(_) => {
                // Unreachable in this branch (we returned above), but handle
                // defensively rather than panicking across the FFI boundary.
                debug!("Unexpected RdapOutcome::Useful in fallback branch");
                (String::from("RDAP ok"), None, None)
            }
            RdapOutcome::NoData(data) => (
                "RDAP response incomplete".to_string(),
                Some(Box::new(data)),
                None,
            ),
            RdapOutcome::Error(e) => (e.to_string(), None, Some(e)),
            RdapOutcome::GraceTimeout => (
                format!(
                    "RDAP did not return within {}s grace period after WHOIS won",
                    PROTOCOL_GRACE_PERIOD.as_secs()
                ),
                None,
                None,
            ),
        };
```

Then find the WHOIS-leg handler immediately below and replace:

```rust
        if let LegOutcome::Completed(Ok(whois_data)) = whois_leg {
            debug!("Using WHOIS result (RDAP not useful)");
            if let Some(ref cb) = progress {
                cb("RDAP not available (using WHOIS)");
            }
            return Ok(LookupResult::Whois {
                data: whois_data,
                rdap_error: Some(rdap_error_str),
                rdap_fallback: rdap_fallback_data,
            });
        }
```

with:

```rust
        if let LegOutcome::Completed(Ok(whois_data)) = whois_leg {
            // Check Cases A and B: should we reclassify as Available?
            let availability_match = rdap_seer_error
                .as_ref()
                .and_then(|e| classify_whois_leg(&whois_data, e))
                .or_else(|| {
                    // Case A can still fire even when RDAP errored for a
                    // non-404 reason — the WHOIS signal alone is sufficient.
                    if whois_data.is_available() {
                        Some(("high", "whois"))
                    } else {
                        None
                    }
                });

            if let Some((confidence, method)) = availability_match {
                debug!(domain = %domain, confidence = %confidence, "Reclassifying WHOIS as availability signal");
                if let Some(ref cb) = progress {
                    cb("Domain appears unregistered");
                }
                let details = match confidence {
                    "high" => Some("WHOIS indicates domain is not registered".to_string()),
                    "medium" => Some(
                        "WHOIS returned no registrar or registration dates; RDAP returned 404"
                            .to_string(),
                    ),
                    _ => None,
                };
                let avail = AvailabilityResult {
                    domain: domain.to_string(),
                    available: true,
                    confidence: confidence.to_string(),
                    method: method.to_string(),
                    details,
                };
                return Ok(LookupResult::Available {
                    data: Box::new(avail),
                    rdap_error: sanitize_error_for_public(&rdap_error_str),
                    whois_error: String::new(),
                    whois_data: Some(whois_data),
                });
            }

            debug!("Using WHOIS result (RDAP not useful)");
            if let Some(ref cb) = progress {
                cb("RDAP not available (using WHOIS)");
            }
            return Ok(LookupResult::Whois {
                data: whois_data,
                rdap_error: Some(rdap_error_str),
                rdap_fallback: rdap_fallback_data,
            });
        }
```

- [ ] **Step 6: Run workspace tests**

Run: `cargo test --workspace`
Expected: all PASS.

Run: `cargo clippy --workspace -- -D warnings`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add seer-core/src/lookup.rs
git commit -m "feat(lookup): route thin/unregistered WHOIS to Available verdict

SmartLookup::lookup_concurrent now reclassifies a 'completed WHOIS
but no registration data' outcome as LookupResult::Available with
synthesized confidence. Case A (explicit 'no match') → high; Case B
(thin WHOIS + RDAP 404) → medium. Existing legacy-TLD cases (real
WHOIS data + RDAP 404) still return Whois. No new network calls."
```

---

### Task 5: Human formatter renders verdict language

**Files:**
- Modify: `seer-core/src/output/human.rs`

**Why:** Surface the new `Available` variant semantics to interactive CLI users per the spec's display section.

- [ ] **Step 1: Update the header `source` selector**

In `seer-core/src/output/human.rs`, find the `format_lookup` method's `source` match (around line 819). Replace:

```rust
        let source = match result {
            LookupResult::Rdap { .. } => "RDAP",
            LookupResult::Whois { .. } => "WHOIS",
            LookupResult::Available { .. } => "availability",
        };

        output.push(self.header(&format!(
            "Lookup: {} (via {})",
            sanitize_display(&domain),
            source
        )));
```

with:

```rust
        let header_suffix = match result {
            LookupResult::Rdap { .. } => "via RDAP".to_string(),
            LookupResult::Whois { .. } => "via WHOIS".to_string(),
            LookupResult::Available { data, .. } => match data.confidence.as_str() {
                "high" => "available".to_string(),
                "medium" => "likely available".to_string(),
                _ => "status unknown".to_string(),
            },
        };

        output.push(self.header(&format!(
            "Lookup: {} ({})",
            sanitize_display(&domain),
            header_suffix
        )));
```

- [ ] **Step 2: Rewrite the `LookupResult::Available` body arm**

In the same function's match on `result`, find the existing `LookupResult::Available { data, rdap_error, whois_error, }` arm (around line 1386). Replace the entire arm with:

```rust
            LookupResult::Available {
                data,
                rdap_error,
                whois_error,
                whois_data,
            } => {
                // Source line reflects how we got here.
                let source_note = if !whois_error.is_empty() {
                    "availability check (RDAP and WHOIS failed)"
                } else {
                    "WHOIS (RDAP unavailable)"
                };
                output.push(format!(
                    "  {}: {}",
                    self.label("Source"),
                    self.warning(source_note)
                ));

                // Verdict headline.
                let verdict_colored = match data.confidence.as_str() {
                    "high" => self.success("AVAILABLE"),
                    "medium" => self.warning("MAY BE AVAILABLE"),
                    _ => self.error("UNKNOWN"),
                };
                output.push(format!(
                    "  {}: {}",
                    self.label("Verdict"),
                    verdict_colored
                ));

                let confidence_colored = match data.confidence.as_str() {
                    "high" => self.success(&data.confidence),
                    "medium" => self.warning(&data.confidence),
                    _ => self.error(&data.confidence),
                };
                output.push(format!(
                    "  {}: {}",
                    self.label("Confidence"),
                    confidence_colored
                ));

                output.push(format!(
                    "  {}: {}",
                    self.label("Method"),
                    self.value(&sanitize_display(&data.method))
                ));

                if let Some(details) = &data.details {
                    output.push(format!(
                        "  {}: {}",
                        self.label("Details"),
                        self.value(&sanitize_display(details))
                    ));
                }

                // RDAP error line stays on when we routed here because of 404 or similar.
                if !rdap_error.is_empty() {
                    output.push(format!(
                        "  {}: {}",
                        self.label("RDAP Error"),
                        self.error(rdap_error)
                    ));
                }
                if !whois_error.is_empty() {
                    output.push(format!(
                        "  {}: {}",
                        self.label("WHOIS Error"),
                        self.error(whois_error)
                    ));
                }

                // If the WHOIS response carried any partial data, show it.
                if let Some(w) = whois_data {
                    let mut extra = Vec::new();
                    if !w.nameservers.is_empty() {
                        extra.push(format!(
                            "    {}: {}",
                            self.label("Nameservers"),
                            self.value(&sanitize_display(&w.nameservers.join(", ")))
                        ));
                    }
                    if !w.status.is_empty() {
                        extra.push(format!(
                            "    {}: {}",
                            self.label("Status"),
                            self.value(&sanitize_display(&w.status.join(", ")))
                        ));
                    }
                    if let Some(ref dnssec) = w.dnssec {
                        extra.push(format!(
                            "    {}: {}",
                            self.label("DNSSEC"),
                            self.value(&sanitize_display(dnssec))
                        ));
                    }
                    if let Some(ref ws) = w.whois_server {
                        extra.push(format!(
                            "    {}: {}",
                            self.label("WHOIS Server"),
                            self.value(&sanitize_display(ws))
                        ));
                    }
                    if !extra.is_empty() {
                        output.push(format!("  {}", self.label("Additional WHOIS data:")));
                        output.extend(extra);
                    }
                }
            }
```

- [ ] **Step 3: Build and test**

Run: `cargo build -p seer-core`
Expected: Success.

Run: `cargo test -p seer-core`
Expected: all PASS (existing tests that exercise `format_lookup` on `Available` should still pass — the variant display has changed but the structure is similar).

- [ ] **Step 4: Commit**

```bash
git add seer-core/src/output/human.rs
git commit -m "feat(output): render availability verdict in human lookup output

Header line now reads '(available)' / '(likely available)' /
'(status unknown)' per confidence. Body adds a bold Verdict line
and, when whois_data is Some, an 'Additional WHOIS data' block
with whatever partial fields the thin response did carry."
```

---

### Task 6: Markdown formatter mirrors the verdict language

**Files:**
- Modify: `seer-core/src/output/markdown.rs`

**Why:** Keep markdown output consistent with human output.

- [ ] **Step 1: Find the current Available arm**

Open `seer-core/src/output/markdown.rs` and locate the `format_lookup` method. Find the `LookupResult::Available` match arm (search for `LookupResult::Available`).

- [ ] **Step 2: Replace the arm**

Replace the whole `LookupResult::Available { .. }` arm with:

```rust
            LookupResult::Available {
                data,
                rdap_error,
                whois_error,
                whois_data,
            } => {
                let header_suffix = match data.confidence.as_str() {
                    "high" => "available",
                    "medium" => "likely available",
                    _ => "status unknown",
                };
                output.push(format!("## Lookup: {} ({})", data.domain, header_suffix));
                output.push(String::new());

                let verdict = match data.confidence.as_str() {
                    "high" => "AVAILABLE",
                    "medium" => "MAY BE AVAILABLE",
                    _ => "UNKNOWN",
                };
                output.push(format!("- **Verdict**: {}", verdict));
                output.push(format!("- **Confidence**: {}", data.confidence));
                output.push(format!("- **Method**: {}", data.method));
                if let Some(details) = &data.details {
                    output.push(format!("- **Details**: {}", details));
                }
                if !rdap_error.is_empty() {
                    output.push(format!("- **RDAP Error**: {}", rdap_error));
                }
                if !whois_error.is_empty() {
                    output.push(format!("- **WHOIS Error**: {}", whois_error));
                }
                if let Some(w) = whois_data {
                    let mut rendered_any = false;
                    if !w.nameservers.is_empty() {
                        if !rendered_any {
                            output.push(String::new());
                            output.push("### Additional WHOIS data".to_string());
                            rendered_any = true;
                        }
                        output.push(format!("- **Nameservers**: {}", w.nameservers.join(", ")));
                    }
                    if !w.status.is_empty() {
                        if !rendered_any {
                            output.push(String::new());
                            output.push("### Additional WHOIS data".to_string());
                            rendered_any = true;
                        }
                        output.push(format!("- **Status**: {}", w.status.join(", ")));
                    }
                    if let Some(ref dnssec) = w.dnssec {
                        if !rendered_any {
                            output.push(String::new());
                            output.push("### Additional WHOIS data".to_string());
                            rendered_any = true;
                        }
                        output.push(format!("- **DNSSEC**: {}", dnssec));
                    }
                    if let Some(ref ws) = w.whois_server {
                        if !rendered_any {
                            output.push(String::new());
                            output.push("### Additional WHOIS data".to_string());
                            rendered_any = true;
                        }
                        output.push(format!("- **WHOIS Server**: {}", ws));
                    }
                    let _ = rendered_any;
                }
            }
```

If the surrounding function's return type uses `Vec<String>` that's later joined with `\n`, the spacing works. If it concatenates differently, mirror the existing arm's idiom.

- [ ] **Step 3: Build**

Run: `cargo build -p seer-core`
Expected: Success. Fix any name-resolution errors (e.g., if the existing arm didn't destructure `whois_data`, and a nested helper closure needed adjustment).

- [ ] **Step 4: Run workspace tests**

Run: `cargo test --workspace`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add seer-core/src/output/markdown.rs
git commit -m "feat(output): mirror availability verdict in markdown output"
```

---

### Task 7: `DomainInfo` gains `availability_verdict`

**Files:**
- Modify: `seer-core/src/domain_info.rs`

**Why:** `seer info` consumers should see the verdict, both in JSON and the info-specific human formatter.

- [ ] **Step 1: Add the field**

In `seer-core/src/domain_info.rs`, add to the `DomainInfo` struct (alongside `rdap_url`):

```rust
    /// Availability verdict: `"available"` / `"likely_available"` / `"unknown"`
    /// when derived from a `LookupResult::Available`. `None` otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub availability_verdict: Option<String>,
```

- [ ] **Step 2: Update `from_sources` to default the field**

Find `impl DomainInfo { pub fn from_sources(...) -> Self` (around line 73). The returned struct literal needs the new field. Add `availability_verdict: None,` to the literal.

- [ ] **Step 3: Populate in `from_lookup_result`**

Find `pub fn from_lookup_result` (around line 239). Replace the `LookupResult::Available { data, .. }` arm with:

```rust
            LookupResult::Available { data, .. } => {
                let mut info = Self::from_sources(&data.domain, None, None);
                info.source = DomainInfoSource::Available;
                info.availability_verdict = Some(
                    match data.confidence.as_str() {
                        "high" => "available",
                        "medium" => "likely_available",
                        _ => "unknown",
                    }
                    .to_string(),
                );
                info
            }
```

- [ ] **Step 4: Build + test**

Run: `cargo build --workspace`
Expected: Success.

Run: `cargo test --workspace`
Expected: all PASS. If an existing test constructs `DomainInfo { .. }` literally with a field list, add `availability_verdict: None` to match.

- [ ] **Step 5: Commit**

```bash
git add seer-core/src/domain_info.rs
git commit -m "feat(info): populate availability_verdict on DomainInfo

Adds an optional availability_verdict field. When the underlying
LookupResult is Available, the verdict string (available /
likely_available / unknown) mirrors the displayed confidence. Json
output gains the field only when set; existing callers unaffected."
```

---

### Task 8: Add `availability_verdict` column to bulk CSV

**Files:**
- Modify: `seer-cli/src/utils.rs`

**Why:** `seer bulk lookup` and `seer bulk info` CSV outputs should carry the new verdict.

- [ ] **Step 1: Update the `lookup` / `whois` / `rdap` CSV header**

In `seer-cli/src/utils.rs`, find `bulk_results_to_csv` (around line 49). The `lookup | whois | rdap` header currently reads:

```rust
        "lookup" | "whois" | "rdap" => {
            csv.push_str("domain,success,registrar,created,expires,updated,duration_ms,error\n");
        }
```

Change to (append `availability_verdict` at the end, before `error`? No — keep `error` last per existing convention; add between `duration_ms` and `error`):

```rust
        "lookup" | "whois" | "rdap" => {
            csv.push_str("domain,success,registrar,created,expires,updated,duration_ms,availability_verdict,error\n");
        }
```

- [ ] **Step 2: Update the `info` CSV header**

Change the existing `info` header from:

```rust
        "info" => {
            csv.push_str("domain,success,source,registrar,registrant,organization,created,expires,updated,nameservers,status,dnssec,registrant_email,registrant_phone,registrant_address,registrant_country,admin_name,admin_organization,admin_email,admin_phone,tech_name,tech_organization,tech_email,tech_phone,whois_server,rdap_url,duration_ms,error\n");
        }
```

to (insert `availability_verdict` just before `duration_ms`):

```rust
        "info" => {
            csv.push_str("domain,success,source,registrar,registrant,organization,created,expires,updated,nameservers,status,dnssec,registrant_email,registrant_phone,registrant_address,registrant_country,admin_name,admin_organization,admin_email,admin_phone,tech_name,tech_organization,tech_email,tech_phone,whois_server,rdap_url,availability_verdict,duration_ms,error\n");
        }
```

- [ ] **Step 3: Update the `lookup | whois | rdap` data row writer**

Find the part of `bulk_results_to_csv` that handles `"lookup" | "whois" | "rdap"` data rows. Locate the code that writes the row fields (it should consume `BulkResultData::Whois | BulkResultData::Rdap | BulkResultData::Lookup`). Add logic that derives a verdict from the result data:

For the `BulkResultData::Lookup(lookup_result)` case, compute:

```rust
                        let availability_verdict = match &lookup_result {
                            seer_core::lookup::LookupResult::Available { data, .. } => {
                                match data.confidence.as_str() {
                                    "high" => "available",
                                    "medium" => "likely_available",
                                    _ => "unknown",
                                }
                                .to_string()
                            }
                            _ => String::new(),
                        };
```

For the `BulkResultData::Whois(_) | BulkResultData::Rdap(_)` cases, `availability_verdict = String::new()`.

Then append the value in the written row. Find the `write!(csv, "{},...", domain, success, ...)` or `csv.push_str(&format!(...))` line for this op and add `,availability_verdict` at the correct position (between `duration_ms` and `error`).

Since the exact row-writing implementation may vary, read the existing handler first:

```bash
grep -n '"lookup" | "whois" | "rdap"' /home/zac/Projects/arcanum_suite/seer/seer-cli/src/utils.rs
```

Then adjust the writer to match the new header column order. The key constraint: `availability_verdict` lives between `duration_ms` and `error` in the row so positions line up with the header.

- [ ] **Step 4: Update the `info` data row writer**

Same approach: in the `"info"` block, derive `availability_verdict` from `DomainInfo.availability_verdict.clone().unwrap_or_default()` and insert it between `rdap_url` and `duration_ms` in the written row.

- [ ] **Step 5: Update `BULK_EXAMPLES` documentation in `seer-cli/src/main.rs`**

In `seer-cli/src/main.rs`, find `const BULK_EXAMPLES: &str = r#"` (starts around line 13). Update the two example header lines:

Before:
```
domain,success,registrar,created,expires,updated,duration_ms,error
```

After:
```
domain,success,registrar,created,expires,updated,duration_ms,availability_verdict,error
```

And for the info example:

Before:
```
domain,success,source,registrar,registrant,organization,created,expires,updated,nameservers,status,dnssec,...,whois_server,rdap_url,duration_ms,error
```

After:
```
domain,success,source,registrar,registrant,organization,created,expires,updated,nameservers,status,dnssec,...,whois_server,rdap_url,availability_verdict,duration_ms,error
```

(Preserve the `,...,` truncation the original had.)

- [ ] **Step 6: Build and test**

Run: `cargo build --workspace`
Expected: Success.

Run: `cargo test --workspace`
Expected: all PASS. If a CSV snapshot test exists in `seer-cli`, update its expected header/rows.

Run: `cargo clippy --workspace -- -D warnings`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add seer-cli/src/utils.rs seer-cli/src/main.rs
git commit -m "feat(bulk): add availability_verdict column to lookup/info CSV

New column lives between duration_ms and error. Values: available,
likely_available, unknown, or empty string when not applicable.
Updates BULK_EXAMPLES documentation to match."
```

---

### Task 9: `seer info` human formatter shows Status line

**Files:**
- Modify: `seer-core/src/output/human.rs`

**Why:** `info` formatter doesn't currently render `availability_verdict`. Add a single `Status: available (high confidence)` line when the verdict is set.

- [ ] **Step 1: Locate the info formatter**

In `seer-core/src/output/human.rs`, find `fn format_info` or the equivalent method that renders a `DomainInfo`. Search:

```bash
grep -n "fn format_info\|format_domain_info" /home/zac/Projects/arcanum_suite/seer/seer-core/src/output/human.rs
```

- [ ] **Step 2: Render the verdict line when set**

Near the top of the formatter's body (after the header and source lines), add:

```rust
        if let Some(verdict) = &info.availability_verdict {
            let colored = match verdict.as_str() {
                "available" => self.success("AVAILABLE"),
                "likely_available" => self.warning("MAY BE AVAILABLE"),
                _ => self.error("UNKNOWN"),
            };
            output.push(format!("  {}: {}", self.label("Status"), colored));
        }
```

Place it where the source/summary fields are rendered, above the registrar block. If the existing formatter uses a different template style, mirror it.

- [ ] **Step 3: Build and test**

Run: `cargo build --workspace`
Expected: Success.

Run: `cargo test --workspace`
Expected: all PASS.

- [ ] **Step 4: Commit**

```bash
git add seer-core/src/output/human.rs
git commit -m "feat(info): render Status line when availability_verdict is set"
```

---

### Task 10: Final workspace verification

**Files:**
- None modified

**Why:** End-to-end confidence: formatting, clippy, tests, and a manual CLI smoke test.

- [ ] **Step 1: Rust fmt check**

Run: `cargo fmt --all -- --check`
Expected: PASS. If anything changed, run `cargo fmt --all` and commit with `style: cargo fmt after availability-aware lookup changes`.

- [ ] **Step 2: Clippy**

Run: `cargo clippy --workspace -- -D warnings`
Expected: PASS.

- [ ] **Step 3: Tests**

Run: `cargo test --workspace`
Expected: all PASS.

- [ ] **Step 4: Manual smoke — available domain (high confidence)**

Find a domain that produces an explicit "No match" WHOIS — `zaccodes.com` is the reference case from the spec:

Run: `./target/debug/seer lookup zaccodes.com`

Expected (approximate):
```
Lookup: zaccodes.com (likely available)
...
  Verdict: MAY BE AVAILABLE
  Confidence: medium
  Method: whois_thin_response
  Details: WHOIS returned no registrar or registration dates; RDAP returned 404
```

(It may be `high` confidence if the WHOIS response includes an explicit "not found" message.)

- [ ] **Step 5: Manual smoke — registered domain (unchanged)**

Run: `./target/debug/seer lookup google.com`

Expected: unchanged "(via RDAP)" output with registrar, dates, etc. No verdict lines.

- [ ] **Step 6: Manual smoke — bulk CSV**

Create input:
```bash
cat > /tmp/seer-avail-test.txt <<'EOF'
google.com
zaccodes.com
EOF
```

Run: `./target/debug/seer bulk lookup /tmp/seer-avail-test.txt -o /tmp/seer-avail-results.csv && cat /tmp/seer-avail-results.csv`

Expected: CSV header contains `availability_verdict`; the `google.com` row leaves it empty; the `zaccodes.com` row has `available` or `likely_available`.

- [ ] **Step 7: Manual smoke — info command**

Run: `./target/debug/seer info zaccodes.com`

Expected: human output includes a `Status:` line with the verdict.

Run: `./target/debug/seer --format json info zaccodes.com | python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('availability_verdict'))"`

Expected: prints `available` or `likely_available`.

- [ ] **Step 8: Done**

No commit.

---

## Summary

After all 10 tasks:

- `LookupResult::Available` variant carries optional `whois_data`
- Two new routing cases in `SmartLookup::lookup_concurrent` classify unregistered domains without extra network calls
- Human and markdown formatters render verdict (`AVAILABLE` / `MAY BE AVAILABLE` / `UNKNOWN`) with confidence and method
- `DomainInfo` gains `availability_verdict`; JSON + CSV + human `info` output all reflect it
- Bulk CSV gains an `availability_verdict` column for `lookup` / `whois` / `rdap` / `info` operations
- No API / MCP code changes (JSON pass-through)
- No `seer-core` public API breaking changes (new field is optional; old constructors need the new field but serde defaults keep deserialization compatible)
