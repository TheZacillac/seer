# Seer Optimization Audit — Three-Batch Remediation

**Status:** Draft
**Date:** 2026-04-21
**Scope:** `seer-core`, `seer-cli`, `seer-py`, `seer-api`

## Goal

Execute the optimization findings from the 2026-04-21 broad audit in three independent commits/PRs, ordered by risk and review ergonomics. No behavioral changes outside of documented feature defaults; all existing tests continue to pass.

## Non-Goals

- `panic = "abort"` in the release profile — keeps the PyO3 FFI `catch_unwind` bridge working.
- Migrating `ssl.rs` off `native-tls` to `rustls` (audit item #8) — real design work; deferred.
- Splitting `seer-cli/src/main.rs` and `repl/mod.rs` (audit items #16) — deferred.
- Cow-ifying `HumanFormatter` helpers (item #14) — waits on item #6.
- Removing the `#[deprecated]` `SmartLookup` fields (item #17) — waits on next minor bump.
- Moving `dirs` out of `seer-core` (item #18) — separate investigation.

## Batch 1 — Mechanical, low-risk wins

One commit per item; bundled into a single PR.

### 1A. Release profile tuning

**File:** `Cargo.toml`

Add:
```toml
[profile.release]
lto = "thin"
codegen-units = 1
strip = "symbols"
```

Omit `panic = "abort"` — the PyO3 bridge uses `std::panic::catch_unwind` at `seer-py/src/lib.rs:127,157` which requires unwinding.

Expected: binary `~20MB → ~14–16MB`, +5–15% runtime on release builds.

### 1B. Static DNS server list

**File:** `seer-core/src/dns/propagation.rs`

- Change `DnsServer` fields `name/ip/location/provider` from `String` → `&'static str`.
- Delete `DnsServer::new`; replace with struct-literal construction.
- Change `default_dns_servers()` to return `&'static [DnsServer]`, backed by `const DEFAULT_DNS_SERVERS: &[DnsServer] = &[…]`.
- Adjust downstream call sites that own the `Vec<DnsServer>` (the checker can either borrow the slice or `.to_vec()` if a mutable config is needed).

Expected: eliminates ~116 string allocations per propagation run.

### 1C. `ORJSONResponse` as FastAPI default

**Files:** `seer-api/pyproject.toml`, `seer-api/seer_api/main.py`

- Add `orjson` to `pyproject.toml` dependencies.
- In `main.py`, `from fastapi.responses import ORJSONResponse` and pass `default_response_class=ORJSONResponse` to `FastAPI(...)`.
- Audit existing handlers for any that explicitly construct `JSONResponse` with non-serializable types (dates, bytes) — `orjson` handles these differently.

Expected: 2–5x JSON serialization speedup on bulk endpoints.

### 1D. Factor SSRF-guard + executor helper

**File:** `seer-api/seer_api/ssrf.py` (extend) and all routers

Add to `ssrf.py`:
```python
async def guard_hosts_async(hosts: Iterable[tuple[str, int]]) -> None:
    for host, port in hosts:
        await guard_async(host, port)
```

Add `seer_api/executor.py`:
```python
async def run_seer(fn, *args) -> Any:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, fn, *args)
```

Refactor `routers/{lookup,whois,rdap,dns,propagation,status}.py` to use these. Do **not** refactor the MCP server in this batch (item #13 for MCP is deferred until batch 1 lands and proves the pattern).

Expected: no runtime impact; ~30–40% line reduction in routers; single place to change the guard behavior.

### Batch 1 testing

- `cargo test --workspace` must pass.
- `cd seer-api && pytest` must pass (hermetic) and with `SEER_LIVE_TESTS=1` (live).
- Confirm binary size reduction with `ls -la target/release/seer`.
- One manual smoke: `seer-api` boot + `curl /lookup/example.com` still returns JSON.

---

## Batch 2 — Feature-flag audit

Single commit; separate PR.

### 2A. Gate OpenTelemetry behind a `otel` feature

**Files:** `Cargo.toml` (workspace), `seer-core/Cargo.toml`, `seer-core/src/logging.rs`

- Move `opentelemetry`, `opentelemetry_sdk`, `opentelemetry-otlp`, `tracing-opentelemetry` from required to optional in `seer-core/Cargo.toml`.
- Add `[features]` block: `default = []`, `otel = ["dep:opentelemetry", "dep:opentelemetry_sdk", "dep:opentelemetry-otlp", "dep:tracing-opentelemetry"]`.
- Put `#[cfg(feature = "otel")]` on the OTEL layer builder at `logging.rs:158-194` (roughly). The call site that consumes the `Option<OpenTelemetryLayer>` must compile both with and without the feature — simplest is to shadow the function to return `None` when the feature is off.
- `seer-cli/Cargo.toml` and `seer-py/Cargo.toml`: decide whether to enable `seer-core/otel` by default. **Decision:** leave OFF by default for both; the API/MCP entry points that deploy with OTEL can enable via `--features seer-core/otel`. Document in README.

Expected: ~1.5–3MB binary reduction on the default build; substantial cold-build time win (tonic/prost/protobuf-parse drop out).

### 2B. Gate DNSSEC behind a `dnssec` feature

**Files:** `seer-core/Cargo.toml`, `seer-core/src/dns/dnssec.rs`, `seer-core/src/dns/mod.rs`, `seer-core/src/lib.rs`

- Move `hickory-resolver = { ..., features = ["dnssec-ring"] }` behind a `dnssec` feature: `dnssec = ["hickory-resolver/dnssec-ring"]`.
- Add `default = ["dnssec"]` — DNSSEC stays on by default, but can be stripped.
- `#[cfg(feature = "dnssec")]` on `dns/dnssec.rs`, `DnssecChecker`/`DnssecReport` re-exports in `dns/mod.rs` and `lib.rs`.
- Handle any non-dnssec-gated callers (e.g. `rdap/types.rs::is_dnssec_signed` looks unrelated — string comparison, no dep on hickory's dnssec types — so it stays).

Expected: ~500KB–1MB binary reduction when disabled; doesn't affect default-feature builds.

### 2C. Trim tokio features

**File:** `Cargo.toml` workspace

Change:
```toml
tokio = { version = "1", features = ["full"] }
```
to:
```toml
tokio = { version = "1", features = [
    "rt-multi-thread", "macros", "net", "time", "sync", "io-util", "signal"
] }
```

Validate `cargo build` succeeds; the `fs` and `process` features should not be needed. If it breaks, narrow further or restore `full`.

Expected: modest binary + compile time win.

### Batch 2 testing

- `cargo build` both with and without default features: `cargo build --release`, `cargo build --release --no-default-features`, `cargo build --release --features otel`.
- `cargo test --workspace` default features.
- Smoke-test `seer lookup example.com` + `seer dig example.com DNSKEY` still work.
- Size check before/after.

---

## Batch 3 — File splits (pure refactor)

Single commit; separate PR. No behavioral change.

### 3A. Split `seer-core/src/output/human.rs`

Current: 3500 lines, one `HumanFormatter` struct with methods for every entity type.

New layout:
```
seer-core/src/output/human/
├── mod.rs        # HumanFormatter struct, shared helpers (label, value, success,
│                 # warning, error, dim, sanitize_display, format_duration),
│                 # OutputFormatter trait impl that dispatches to per-entity mods
├── whois.rs      # format_whois(&self, ..., f: &mut String)
├── rdap.rs       # format_rdap
├── dns.rs        # format_dns_records
├── status.rs     # format_status
├── lookup.rs     # format_lookup
├── propagation.rs # format_propagation
├── follow.rs     # format_follow_result + FollowIteration
└── diff.rs       # format_diff
```

Approach: move functions verbatim; keep `&self` signatures; have `mod.rs` `pub use` nothing public except the `HumanFormatter` struct. The `impl HumanFormatter { … }` block splits across files using multiple `impl HumanFormatter` blocks (Rust allows this).

### 3B. Split `seer-core/src/output/markdown.rs`

Parallel treatment: `output/markdown/{mod,whois,rdap,dns,status,lookup,propagation,follow,diff}.rs`. Likely fewer per-entity functions than human.rs — structure from the existing file.

### 3C. Split `seer-core/src/lookup.rs`

Current: 1341 lines — SmartLookup + cache + in-flight dedup + concurrent race + classification + tests.

New layout:
```
seer-core/src/lookup/
├── mod.rs       # Public API: SmartLookup, LookupResult, re-exports
├── cache.rs     # LOOKUP_CACHE, trim_for_cache
├── inflight.rs  # LOOKUP_INFLIGHT, InflightGuard
├── race.rs      # lookup_concurrent, LegOutcome, PROTOCOL_GRACE_PERIOD
└── classify.rs  # is_rdap_response_useful, RdapOutcome
```

Tests move with their subject (each new file gets its own `#[cfg(test)] mod tests`).

### 3D. Split `seer-core/src/rdap/client.rs`

Current: 1385 lines — bootstrap + per-query + URL selection.

New layout:
```
seer-core/src/rdap/
├── mod.rs         # re-exports (unchanged public API)
├── bootstrap.rs   # IANA bootstrap fetch, cache, waiter coordination
├── client.rs      # RdapClient, per-query logic, URL selection
└── types.rs       # (unchanged)
```

### Batch 3 testing

- `cargo test --workspace` must pass with zero changes to test logic — this is a pure move.
- `cargo clippy -- -D warnings` must pass.
- `cargo fmt --check` must pass.
- `grep -rn "pub use" seer-core/src/lookup* seer-core/src/rdap* seer-core/src/output*` to verify no public API surface changed.

---

## Risk & rollout

- Batches are **independent and ordered** but can be reviewed/merged in any order after batch 1 lands. Batch 3 is pure refactor and easiest to review when the other two aren't interleaved.
- Each batch is a separate PR to main.
- No schema changes, no API changes (beyond orjson's slightly different date/bytes handling which we'll test).
- Version bump to **v0.24.0** after all three batches land (breaking only in the sense of feature defaults for OTEL consumers).

## Out-of-scope follow-ups

Deferred to later work, tracked as audit items:
- #3 shared client trees (bulk executor)
- #8 rustls migration for ssl.rs
- #10 sized PyO3 tokio runtime
- #13 (MCP half) — MCP server SSRF+executor refactor (router half lands in batch 1)
- #14 Cow-ify HumanFormatter helpers
- #15 crossterm dedup
- #16 split CLI main/repl
- #17 drop deprecated SmartLookup fields (v0.24)
- #18 move `dirs` out of seer-core
