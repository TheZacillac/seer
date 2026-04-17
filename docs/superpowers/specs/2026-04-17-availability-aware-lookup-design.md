# Availability-Aware Lookup Display

**Status:** Draft
**Date:** 2026-04-17
**Scope:** `seer-core`, `seer-cli`, `seer-api`, `seer-py`

## Goal

When `seer lookup` or `seer info` detects that a domain is probably available for registration, surface a clear verdict instead of a bare `(via WHOIS)` header. Three verdicts based on existing `AvailabilityChecker` confidence:

- `AVAILABLE` (confidence `high`)
- `MAY BE AVAILABLE` (confidence `medium`)
- `UNKNOWN` (confidence `none`)

Already-taken domains are unaffected. The change flows through every surface that renders a `LookupResult`: human, markdown, JSON, bulk CSV, REST/MCP responses, Python bindings.

## Motivation

Current behavior on an unregistered domain like `zaccodes.com`:

```
Lookup: zaccodes.com (via WHOIS)
────────────────────────────────
  Source: WHOIS (RDAP unavailable)
  RDAP Error: RDAP lookup failed: query failed with status 404 Not Found
```

RDAP returned 404; WHOIS returned a response with no registrar, no dates, and text a parser recognizes as "not registered" — but `SmartLookup::lookup_concurrent` only routes to the availability path when **both** protocols error out. A WHOIS success with empty content is classified as a successful lookup, producing the thin display above. Users reading this can't tell whether the domain is unregistered or whether our query went wrong.

## Non-Goals

- Changes to the Rust core's `ProgressCallback` or `AvailabilityChecker` API.
- New network calls for availability determination (synthesis only — see §3).
- Changes to `seer bulk avail` semantics.
- Renaming CLI commands or tools.

## Detection Rule

Today, `SmartLookup::lookup_concurrent` routes to `LookupResult::Available` only when both RDAP and WHOIS error out. This spec adds two new routing cases while preserving existing behavior everywhere else.

**Case A — WHOIS explicitly indicates no registration.**
`WhoisResponse::is_available()` returns `true` (looks for "no match", "not found", etc. in the response). Synthesize:

```rust
AvailabilityResult {
    domain,
    available: true,
    confidence: "high",
    method: "whois",
    details: Some("WHOIS indicates domain is not registered"),
}
```

**Case B — WHOIS returned thin data AND RDAP specifically 404'd.**
"Thin" = the parsed `WhoisResponse` has no registrar AND no creation date AND no expiration date. Combined with an RDAP error whose origin is a 404 response, synthesize:

```rust
AvailabilityResult {
    domain,
    available: true,
    confidence: "medium",
    method: "whois_thin_response",
    details: Some("WHOIS returned no registrar or registration dates; RDAP returned 404"),
}
```

**Non-404 RDAP errors do NOT trigger availability routing.** Timeouts, 500s, connection failures, SSRF rejections, etc. all mean "we don't know" — we keep today's behavior (use WHOIS as-is, display `RDAP Error` line). A 404 from the registry-delegated RDAP server is the semantically correct "no entry in registry" signal; other failures are not.

**Synthesis, not re-lookup.** The routing decision uses signals already in hand. We do NOT fire a second `AvailabilityChecker::check()` network call — the `AvailabilityResult` is built from the in-flight RDAP error and WHOIS response.

## Data Model

Extend the existing `LookupResult::Available` variant to optionally carry the raw WHOIS response:

```rust
pub enum LookupResult {
    Rdap { data: Box<RdapResponse>, whois_fallback: Option<WhoisResponse> },
    Whois { data: WhoisResponse, rdap_error: Option<String>, rdap_fallback: Option<Box<RdapResponse>> },
    Available {
        data: Box<AvailabilityResult>,
        rdap_error: String,
        whois_error: String,
        // NEW: Some when WHOIS returned a parsed response (Cases A and B).
        // None preserves existing behavior (both protocols errored).
        #[serde(skip_serializing_if = "Option::is_none", default)]
        whois_data: Option<WhoisResponse>,
    },
}
```

Helpers `is_available()` and `domain_name()` already match on the variant and need no changes beyond adding the new field to the destructuring.

## Display Changes

### Human formatter (`seer-core/src/output/human.rs`)

Rewrite the `LookupResult::Available` arm. Header line chooses wording by confidence:

- `Lookup: example.com (available)` — confidence `high`
- `Lookup: example.com (likely available)` — confidence `medium`
- `Lookup: example.com (status unknown)` — confidence `none`

Body:

```
  Source: WHOIS (RDAP unavailable)           ← reflects how we got here
  Verdict: MAY BE AVAILABLE                  ← green/yellow/red per confidence
  Confidence: medium
  Method: whois_thin_response
  Details: WHOIS returned no registrar or registration dates; RDAP returned 404
  RDAP Error: RDAP lookup failed: query failed with status 404 Not Found
```

When `whois_data: Some(_)` contains any non-empty fields (nameservers, status, etc. — data the thin response did carry), render them under an `Additional WHOIS data:` block matching the existing `Whois` arm.

Color: verdict line colored by confidence — `high`/green, `medium`/yellow, `none`/red (or muted).

### Markdown formatter (`output/markdown.rs`)

Same verdict / confidence / method / details structure, markdown-styled. No new columns.

### JSON formatter (`output/json.rs`)

No structural change. `LookupResult::Available` serializes as today plus the optional `whois_data` field (omitted when `None`).

### Bulk CSV (`seer-cli/src/utils.rs::bulk_results_to_csv`)

For the `lookup` and `info` operations, append a new `availability_verdict` column. Values: `available`, `likely_available`, `unknown`, or an empty string when the result is `Rdap` or `Whois`. Registrar and date columns stay blank for `Available` rows.

Naming note: `status` would collide with `info`'s existing `status` column (domain status codes like `clientTransferProhibited`). `availability_verdict` is unambiguous and mirrors the in-memory field name. Added at the end of the CSV so scripts reading by column name are unaffected; positional parsers that expect a fixed trailing layout will need to adjust.

## `seer info`

`DomainInfo::from_lookup_result` currently leaves most fields blank when the result is `LookupResult::Available`. Extend it:

- Populate `source` as `"availability"` when the result is `Available`.
- Add a new `availability_verdict: Option<String>` field populated with `"available"` / `"likely_available"` / `"unknown"` based on confidence, or `None` for `Rdap` / `Whois`.

JSON output gains one optional field. Human `info` output adds a `Status: available (high confidence)` line when the verdict is set.

## Other Surfaces

### REST API (`seer-api/seer_api/routers/lookup.py`)

No code change. The new `whois_data` field appears transparently in serialized responses; consumers that don't care still ignore it.

### MCP server (`seer-api/seer_api/mcp/server.py`)

Same — tool results are JSON passthrough. `UNTRUSTED_PREAMBLE` still applies. No code change.

### Python bindings (`seer-py`)

`seer.lookup()` / `seer.info()` already return `dict` from the serialized `LookupResult` via `json_to_python`. New fields flow through transparently.

### MCP tool name

Unchanged (`seer_lookup`). No new tool.

## Testing

### Rust core (`seer-core`)

- **Routing: Case A (high).** `lookup_concurrent` returns `Available` with `confidence: "high"` when WHOIS `is_available()` fires. Stubbed clients.
- **Routing: Case B (medium).** Returns `Available` with `confidence: "medium"` when WHOIS is thin (no registrar, no dates) AND RDAP error is a 404.
- **No routing on non-404 RDAP error.** Thin WHOIS + RDAP timeout / 500 / connection error must stay on `LookupResult::Whois`.
- **No routing when WHOIS has real data.** A parsed WHOIS with registrar or dates must stay on `Whois` even with RDAP 404 (legacy TLD case).
- **Pure function: `rdap_error_is_404`.** Test that the helper recognizes the 404 error and rejects other error variants.

### Display (`seer-core/src/output/human.rs`)

- Snapshot-style tests for the three verdicts (`high`/`medium`/`none`) rendering the expected header + body.
- Snapshot for the `whois_data: Some(_)` path with partial fields — `Additional WHOIS data:` block appears.

### `info` formatter (`seer-core/src/domain_info.rs`)

- `DomainInfo::from_lookup_result(Available{..})` populates `availability_verdict` and `source = "availability"`.

### Bulk CSV (`seer-cli/src/utils.rs`)

- Extend existing tests to cover a `LookupResult::Available` row in `bulk lookup` output — `status` column populates `available` / `likely_available` / `unknown`; registrar/date columns are blank.

### Manual verification

- `seer lookup zaccodes.com` → shows `MAY BE AVAILABLE` with `medium` confidence.
- `seer lookup <domain with explicit "no match" WHOIS>` → shows `AVAILABLE` with `high` confidence.
- `seer lookup google.com` → unchanged (still RDAP primary).
- `seer info zaccodes.com` → new `availability_verdict` field present in JSON; human output shows `Status` line.
- `seer bulk lookup domains.csv` mixed available/taken → CSV `status` column populates correctly.

### Explicitly not tested

- REST API / MCP / Python pass-through (pure serialization).

## Files Touched

| File | Change |
|------|--------|
| `seer-core/src/lookup.rs` | Extend `LookupResult::Available` with `whois_data`; add routing for Cases A and B; add `rdap_error_is_404` helper; synthesize `AvailabilityResult` inline |
| `seer-core/src/output/human.rs` | Rewrite `LookupResult::Available` arm — header wording by confidence, Verdict line, Additional WHOIS data block |
| `seer-core/src/output/markdown.rs` | Mirror human-formatter verdict/confidence/method/details structure |
| `seer-core/src/domain_info.rs` | `from_lookup_result` populates `availability_verdict` + `source = "availability"` |
| `seer-cli/src/utils.rs` | Add `status` column to bulk CSV for `lookup` / `info` operations |
| Existing tests in `seer-core` and `seer-cli` | Extended per §Testing |
