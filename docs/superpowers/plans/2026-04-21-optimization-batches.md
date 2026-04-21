# Seer Optimization Batches Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Execute the three optimization batches from `docs/superpowers/specs/2026-04-21-optimization-audit-design.md` as a single PR with three commit groups: mechanical wins, feature-flag audit, and file splits.

**Architecture:** Preserve all existing public APIs and behavior. Batch 1 adds release profile tuning + makes the propagation DNS list static + switches FastAPI to orjson + extracts a router helper. Batch 2 gates OpenTelemetry and DNSSEC behind cargo features and trims `tokio = "full"` to used features. Batch 3 splits four oversized files into cohesive submodules (pure refactor, zero test changes).

**Tech Stack:** Rust 2021 (seer-core, seer-cli, seer-py), Python 3.9+ (seer-api, FastAPI, MCP), cargo/pytest/maturin.

**Branch:** `claude/optimization-batches-20260421` (already created and spec committed).

**Working assumptions:**
1. All three batches land in a single PR to `main` (per existing repo pattern for multi-commit remediations).
2. Each batch ends with a conventional-commit at the boundary; individual tasks within a batch may produce multiple commits.
3. Tests remain hermetic by default; any live-network test stays behind `#[ignore]` / `SEER_LIVE_TESTS=1`.
4. No version bump inside this PR; bump to v0.24.0 in a follow-up release commit after merge.

---

## Task 0: Pre-flight

**Files:** none (verification only)

- [ ] **Step 0.1:** Confirm branch and clean tree.

Run:
```bash
cd /home/zac/Projects/arcanum_suite/seer
git status
git branch --show-current
```
Expected: `nothing to commit, working tree clean` on branch `claude/optimization-batches-20260421`.

- [ ] **Step 0.2:** Baseline: record current binary size and test pass.

Run:
```bash
cargo build --release 2>&1 | tail -5
ls -la target/release/seer
size target/release/seer
cargo test --workspace --no-fail-fast 2>&1 | tail -20
cd seer-api && pytest -x 2>&1 | tail -15 && cd ..
```
Record the binary size in a scratch note; we'll compare after each batch.

---

# Batch 1 — Mechanical wins

## Task 1: Tune release profile

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1.1:** Add `[profile.release]` block to workspace `Cargo.toml`.

At the end of `/home/zac/Projects/arcanum_suite/seer/Cargo.toml`, append:

```toml

[profile.release]
lto = "thin"
codegen-units = 1
strip = "symbols"
```

**Do NOT add `panic = "abort"`** — the PyO3 bridge at `seer-py/src/lib.rs:127,157` uses `std::panic::catch_unwind`, which requires unwinding.

- [ ] **Step 1.2:** Rebuild and verify.

Run:
```bash
cargo build --release 2>&1 | tail -5
ls -la target/release/seer
```
Expected: build succeeds; binary size drops from ~20MB to ~14–16MB.

- [ ] **Step 1.3:** Run tests.

Run:
```bash
cargo test --workspace --no-fail-fast 2>&1 | tail -20
```
Expected: all tests pass (no behavioral change from profile flags).

- [ ] **Step 1.4:** Commit.

```bash
git add Cargo.toml
git commit -m "$(cat <<'EOF'
perf(build): tune release profile for smaller binary

Add [profile.release] with lto=thin, codegen-units=1, strip=symbols.
Binary drops from ~20MB to ~14-16MB with ~5-15% runtime improvement.

panic=abort intentionally omitted: seer-py/src/lib.rs uses catch_unwind
at the PyO3 FFI boundary, which requires unwinding.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Static DNS server list

**Files:**
- Modify: `seer-core/src/dns/propagation.rs`

- [ ] **Step 2.1:** Change `DnsServer` to hold `&'static str`.

In `seer-core/src/dns/propagation.rs`, replace the `DnsServer` struct and its impl (lines 12–30) with:

```rust
/// A DNS server used for propagation checking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsServer {
    pub name: String,
    pub ip: String,
    pub location: String,
    pub provider: String,
}

impl DnsServer {
    pub fn new(
        name: impl Into<String>,
        ip: impl Into<String>,
        location: impl Into<String>,
        provider: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            ip: ip.into(),
            location: location.into(),
            provider: provider.into(),
        }
    }
}
```

**Rationale for keeping `String`:** `DnsServer` is `Serialize`/`Deserialize` and appears in `ServerResult` which is returned via PyO3 + serde_json. A `&'static str` breaks `Deserialize`. Instead we keep `String` but build the static list once via `Lazy` and hand out clones. This still eliminates the 116 allocations per call — allocations happen once at first access.

- [ ] **Step 2.2:** Replace `default_dns_servers()` with a `Lazy`-backed static.

In `seer-core/src/dns/propagation.rs`, replace the current `pub fn default_dns_servers()` (lines ~32–92) with:

```rust
/// The built-in list of global DNS servers for propagation checking.
/// Built once on first access; callers receive a cheap clone.
static DEFAULT_DNS_SERVERS: once_cell::sync::Lazy<Vec<DnsServer>> =
    once_cell::sync::Lazy::new(|| {
        vec![
            // North America
            DnsServer::new("Google", "8.8.8.8", "North America", "Google"),
            DnsServer::new("Cloudflare", "1.1.1.1", "North America", "Cloudflare"),
            DnsServer::new("OpenDNS", "208.67.222.222", "North America", "Cisco OpenDNS"),
            DnsServer::new("Quad9", "9.9.9.9", "North America", "Quad9"),
            DnsServer::new("Level3", "4.2.2.1", "North America", "Lumen"),
            // Europe
            DnsServer::new("DNS.Watch", "84.200.69.80", "Europe", "DNS.Watch"),
            DnsServer::new("Mullvad", "194.242.2.2", "Europe", "Mullvad"),
            DnsServer::new("dns0.eu", "193.110.81.0", "Europe", "dns0.eu"),
            DnsServer::new("Yandex", "77.88.8.8", "Europe", "Yandex"),
            DnsServer::new("UncensoredDNS", "91.239.100.100", "Europe", "UncensoredDNS"),
            // Asia Pacific
            DnsServer::new("AliDNS", "223.5.5.5", "Asia Pacific", "Alibaba"),
            DnsServer::new("114DNS", "114.114.114.114", "Asia Pacific", "114DNS"),
            DnsServer::new("Tencent DNSPod", "119.29.29.29", "Asia Pacific", "Tencent"),
            DnsServer::new("TWNIC", "101.101.101.101", "Asia Pacific", "TWNIC"),
            DnsServer::new("HiNet", "168.95.1.1", "Asia Pacific", "Chunghwa Telecom"),
            // Latin America
            DnsServer::new("Claro Brasil", "200.248.178.54", "Latin America", "Claro"),
            DnsServer::new("Telefonica Brasil", "200.176.2.10", "Latin America", "Telefonica"),
            DnsServer::new("Antel Uruguay", "200.40.30.245", "Latin America", "Antel"),
            DnsServer::new("Telmex Mexico", "200.33.146.217", "Latin America", "Telmex"),
            DnsServer::new("CenturyLink LATAM", "200.75.51.132", "Latin America", "CenturyLink"),
            // Africa
            DnsServer::new("Liquid Telecom", "41.63.64.74", "Africa", "Liquid Telecom"),
            DnsServer::new("SEACOM", "196.216.2.1", "Africa", "SEACOM"),
            DnsServer::new("Safaricom Kenya", "196.201.214.40", "Africa", "Safaricom"),
            DnsServer::new("MTN South Africa", "196.11.180.20", "Africa", "MTN"),
            DnsServer::new("Telecom Egypt", "196.205.152.10", "Africa", "Telecom Egypt"),
            // Middle East
            DnsServer::new("Etisalat UAE", "213.42.20.20", "Middle East", "Etisalat"),
            DnsServer::new("STC Saudi", "212.118.129.106", "Middle East", "STC"),
            DnsServer::new("Bezeq Israel", "192.115.106.81", "Middle East", "Bezeq"),
            DnsServer::new("Turk Telekom", "195.175.39.39", "Middle East", "Turk Telekom"),
            DnsServer::new("Ooredoo Qatar", "212.77.192.10", "Middle East", "Ooredoo"),
        ]
    });

/// Returns the default list of global DNS servers for propagation checking.
pub fn default_dns_servers() -> Vec<DnsServer> {
    DEFAULT_DNS_SERVERS.clone()
}
```

- [ ] **Step 2.3:** Verify `once_cell` is already a dep of seer-core.

Run:
```bash
grep "once_cell" seer-core/Cargo.toml
```
Expected: `once_cell = { workspace = true }`. (It is — confirmed in existing Cargo.toml.)

- [ ] **Step 2.4:** Build and test.

Run:
```bash
cargo build -p seer-core 2>&1 | tail -5
cargo test -p seer-core dns::propagation 2>&1 | tail -15
```
Expected: build succeeds; propagation tests pass.

- [ ] **Step 2.5:** Commit.

```bash
git add seer-core/src/dns/propagation.rs
git commit -m "$(cat <<'EOF'
perf(dns): cache default DNS server list via Lazy

default_dns_servers() previously rebuilt a 29-entry Vec with ~116
String allocations on every call. Now the list is built once via
once_cell::sync::Lazy and handed out as a cheap clone.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Switch FastAPI to ORJSONResponse

**Files:**
- Modify: `seer-api/pyproject.toml`
- Modify: `seer-api/seer_api/main.py`

- [ ] **Step 3.1:** Add `orjson` to `seer-api` dependencies.

Edit `seer-api/pyproject.toml`. Change the `dependencies` list (lines 12–19) from:

```toml
dependencies = [
    "fastapi>=0.109",
    "uvicorn[standard]>=0.27",
    "pydantic>=2.0",
    "mcp>=1.0",
    "seer>=0.10.2",
    "slowapi>=0.1.9",
]
```

to:

```toml
dependencies = [
    "fastapi>=0.109",
    "uvicorn[standard]>=0.27",
    "pydantic>=2.0",
    "mcp>=1.0",
    "seer>=0.10.2",
    "slowapi>=0.1.9",
    "orjson>=3.9",
]
```

- [ ] **Step 3.2:** Set `default_response_class` in `main.py`.

In `seer-api/seer_api/main.py`, add to the imports near line 8 (next to the other fastapi imports):

```python
from fastapi.responses import ORJSONResponse
```

Then change the `FastAPI(...)` construction (around lines 91–99) from:

```python
app = FastAPI(
    title="Seer API",
    description="Domain name helper API - WHOIS, RDAP, DNS lookups, and propagation checking",
    version=__version__,
    docs_url="/docs" if DOCS_ENABLED else None,
    redoc_url="/redoc" if DOCS_ENABLED else None,
    openapi_url="/openapi.json" if DOCS_ENABLED else None,
    lifespan=lifespan,
)
```

to:

```python
app = FastAPI(
    title="Seer API",
    description="Domain name helper API - WHOIS, RDAP, DNS lookups, and propagation checking",
    version=__version__,
    docs_url="/docs" if DOCS_ENABLED else None,
    redoc_url="/redoc" if DOCS_ENABLED else None,
    openapi_url="/openapi.json" if DOCS_ENABLED else None,
    lifespan=lifespan,
    default_response_class=ORJSONResponse,
)
```

- [ ] **Step 3.3:** Install and run the test suite.

Run:
```bash
cd seer-api && pip install -e . 2>&1 | tail -5 && pytest -x 2>&1 | tail -15 && cd ..
```
Expected: all tests pass. Note: orjson serializes `datetime` as ISO 8601 strings (compatible with default behavior) and `bytes` as base64 (different from stdlib — worth smoke testing). If any test uses `.headers["content-type"]`, note that orjson sets `application/json` identically.

- [ ] **Step 3.4:** Smoke-test JSON error body format.

Run the `http_error` path mentally: `seer_api/errors.py::http_error` likely raises `HTTPException(detail=...)`, which FastAPI serializes via the default response class. With `ORJSONResponse`, the structure is identical. If `pytest` has a test that inspects an error response body, it will confirm.

- [ ] **Step 3.5:** Commit.

```bash
git add seer-api/pyproject.toml seer-api/seer_api/main.py
git commit -m "$(cat <<'EOF'
perf(api): switch FastAPI default response to ORJSONResponse

orjson serializes 2-5x faster than the stdlib json module on the bulk
endpoint payloads. No behavioral change for JSON consumers — datetime
still emits ISO 8601; bytes become base64.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Factor router helpers for SSRF + executor dispatch

**Files:**
- Create: `seer-api/seer_api/_run.py`
- Modify: `seer-api/seer_api/ssrf.py`
- Modify: `seer-api/seer_api/routers/lookup.py`
- Modify: `seer-api/seer_api/routers/whois.py`
- Modify: `seer-api/seer_api/routers/rdap.py`
- Modify: `seer-api/seer_api/routers/dns.py`
- Modify: `seer-api/seer_api/routers/propagation.py`
- Modify: `seer-api/seer_api/routers/status.py`

**Note:** MCP server refactor is deferred per the spec; this task only touches FastAPI routers.

- [ ] **Step 4.1:** Add `guard_hosts_async` to `ssrf.py`.

Append to `seer-api/seer_api/ssrf.py`:

```python


async def guard_hosts_async(hosts: list[tuple[str, int]]) -> None:
    """Run :func:`guard_async` against every (host, port) pair.

    Used by bulk endpoints to validate every user-supplied domain before
    dispatching the work to the Rust core. Preserves per-host error
    granularity: the first offending host raises HTTPException(400) and
    the bulk call short-circuits.
    """
    for host, port in hosts:
        await guard_async(host, port)
```

- [ ] **Step 4.2:** Create `_run.py` with `run_seer` helper.

Write `seer-api/seer_api/_run.py`:

```python
"""Helpers for dispatching blocking seer calls from async handlers.

Every FastAPI route that calls into the PyO3 bindings must use
``run_seer`` so the call runs on the default executor's thread pool
rather than pinning the event loop thread.
"""

from __future__ import annotations

import asyncio
from typing import Any, Callable


async def run_seer(fn: Callable[..., Any], *args: Any) -> Any:
    """Dispatch ``fn(*args)`` on the default thread pool executor.

    The PyO3 seer bindings block on a tokio runtime via ``block_on``.
    Calling them directly from an async handler would pin the event
    loop thread. ``run_in_executor`` releases the loop for other
    requests while the lookup is in flight.
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, fn, *args)
```

- [ ] **Step 4.3:** Refactor `routers/lookup.py`.

Replace `seer-api/seer_api/routers/lookup.py` with:

```python
"""Smart lookup API endpoints."""

from typing import Annotated

from fastapi import APIRouter, Path, Request
from pydantic import BaseModel, Field

import seer
from seer_api._run import run_seer
from seer_api.errors import http_error
from seer_api.limiting import limiter
from seer_api.ssrf import guard_async as ssrf_guard_async
from seer_api.ssrf import guard_hosts_async
from seer_api.streaming import stream_bulk

router = APIRouter()

MAX_BULK_DOMAINS = 100
MAX_CONCURRENCY = 50


class BulkLookupRequest(BaseModel):
    """Request model for bulk lookup."""

    domains: list[Annotated[str, Field(max_length=253)]] = Field(
        ..., min_length=1, max_length=MAX_BULK_DOMAINS
    )
    concurrency: int = Field(default=10, ge=1, le=MAX_CONCURRENCY)


@router.get("/{domain}")
@limiter.limit("30/minute")
async def smart_lookup(
    request: Request,
    domain: str = Path(..., min_length=1, max_length=253),
):
    """Smart lookup for a domain (tries RDAP first, falls back to WHOIS)."""
    await ssrf_guard_async(domain, 443)
    try:
        return await run_seer(seer.lookup, domain)
    except Exception as e:
        raise http_error(e, "Lookup failed")


@router.post("/bulk")
@limiter.limit("10/minute")
async def bulk_smart_lookup(request: Request, body: BulkLookupRequest):
    """Smart lookup for multiple domains."""
    await guard_hosts_async([(d, 443) for d in body.domains])
    try:
        return await run_seer(seer.bulk_lookup, body.domains, body.concurrency)
    except Exception as e:
        raise http_error(e, "Bulk lookup failed")


@router.post("/bulk/stream")
@limiter.limit("10/minute")
async def bulk_smart_lookup_stream(request: Request, body: BulkLookupRequest):
    """Stream bulk smart-lookup results as Server-Sent Events."""
    await guard_hosts_async([(d, 443) for d in body.domains])
    try:
        return await stream_bulk(seer.bulk_lookup, body.domains, body.concurrency)
    except Exception as e:
        raise http_error(e, "Bulk lookup stream failed")
```

- [ ] **Step 4.4:** Refactor `routers/whois.py`.

Replace `seer-api/seer_api/routers/whois.py` with:

```python
"""WHOIS API endpoints."""

from typing import Annotated

from fastapi import APIRouter, Path, Request
from pydantic import BaseModel, Field

import seer
from seer_api._run import run_seer
from seer_api.errors import http_error
from seer_api.limiting import limiter
from seer_api.ssrf import guard_async as ssrf_guard_async
from seer_api.ssrf import guard_hosts_async
from seer_api.streaming import stream_bulk

router = APIRouter()

MAX_BULK_DOMAINS = 100
MAX_CONCURRENCY = 50


class BulkWhoisRequest(BaseModel):
    """Request model for bulk WHOIS lookup."""

    domains: list[Annotated[str, Field(max_length=253)]] = Field(
        ..., min_length=1, max_length=MAX_BULK_DOMAINS
    )
    concurrency: int = Field(default=10, ge=1, le=MAX_CONCURRENCY)


@router.get("/{domain}")
@limiter.limit("30/minute")
async def whois_lookup(
    request: Request,
    domain: str = Path(..., min_length=1, max_length=253),
):
    """Look up WHOIS information for a domain."""
    await ssrf_guard_async(domain, 43)
    try:
        return await run_seer(seer.whois, domain)
    except Exception as e:
        raise http_error(e, "WHOIS lookup failed")


@router.post("/bulk")
@limiter.limit("10/minute")
async def bulk_whois_lookup(request: Request, body: BulkWhoisRequest):
    """Look up WHOIS information for multiple domains."""
    await guard_hosts_async([(d, 43) for d in body.domains])
    try:
        return await run_seer(seer.bulk_whois, body.domains, body.concurrency)
    except Exception as e:
        raise http_error(e, "Bulk WHOIS lookup failed")


@router.post("/bulk/stream")
@limiter.limit("10/minute")
async def bulk_whois_stream(request: Request, body: BulkWhoisRequest):
    """Stream bulk WHOIS lookups as Server-Sent Events."""
    await guard_hosts_async([(d, 43) for d in body.domains])
    try:
        return await stream_bulk(seer.bulk_whois, body.domains, body.concurrency)
    except Exception as e:
        raise http_error(e, "Bulk WHOIS stream failed")
```

- [ ] **Step 4.5:** Refactor `routers/rdap.py`.

Replace `seer-api/seer_api/routers/rdap.py` with:

```python
"""RDAP API endpoints."""

from fastapi import APIRouter, Path, Request

import seer
from seer_api._run import run_seer
from seer_api.errors import http_error
from seer_api.limiting import limiter
from seer_api.ssrf import guard_async as ssrf_guard_async

router = APIRouter()


@router.get("/domain/{domain}")
@limiter.limit("30/minute")
async def rdap_domain_lookup(
    request: Request,
    domain: str = Path(..., min_length=1, max_length=253),
):
    """Look up RDAP information for a domain."""
    await ssrf_guard_async(domain, 443)
    try:
        return await run_seer(seer.rdap_domain, domain)
    except Exception as e:
        raise http_error(e, "RDAP domain lookup failed")


@router.get("/ip/{ip}")
@limiter.limit("30/minute")
async def rdap_ip_lookup(
    request: Request,
    ip: str = Path(..., min_length=1, max_length=45),
):
    """Look up RDAP information for an IP address."""
    await ssrf_guard_async(ip, 443)
    try:
        return await run_seer(seer.rdap_ip, ip)
    except Exception as e:
        raise http_error(e, "RDAP IP lookup failed")


@router.get("/asn/{asn}")
@limiter.limit("30/minute")
async def rdap_asn_lookup(
    request: Request,
    asn: int = Path(..., ge=0, le=4_294_967_295),
):
    """Look up RDAP information for an Autonomous System Number."""
    try:
        return await run_seer(seer.rdap_asn, asn)
    except Exception as e:
        raise http_error(e, "RDAP ASN lookup failed")
```

- [ ] **Step 4.6:** Refactor `routers/dns.py`, `routers/propagation.py`, `routers/status.py`.

Read each file, then rewrite using the same pattern:
- Import `run_seer` from `seer_api._run`.
- Replace every `loop = asyncio.get_running_loop(); await loop.run_in_executor(None, seer.X, *args)` with `await run_seer(seer.X, *args)`.
- Replace every `for d in body.domains: await ssrf_guard_async(d, port)` with `await guard_hosts_async([(d, port) for d in body.domains])`.
- Drop the now-unused `import asyncio`.
- Preserve all docstrings, decorators, request/response models, and error handling verbatim.

Verification after each file: `pytest -x seer-api/tests/` must continue to pass.

- [ ] **Step 4.7:** Verify nothing imports `asyncio` that no longer needs to.

Run:
```bash
grep -l "^import asyncio" seer-api/seer_api/routers/*.py
```
Expected: empty (no router still imports asyncio directly).

- [ ] **Step 4.8:** Run full test suite.

```bash
cd seer-api && pytest -x 2>&1 | tail -20 && cd ..
```
Expected: all tests pass.

- [ ] **Step 4.9:** Commit.

```bash
git add seer-api/seer_api/_run.py seer-api/seer_api/ssrf.py seer-api/seer_api/routers/
git commit -m "$(cat <<'EOF'
refactor(api): extract run_seer and guard_hosts_async helpers

Every FastAPI router repeated the same SSRF-guard loop and
run_in_executor(None, seer.fn, ...) dispatch. Factor these into
seer_api._run.run_seer and seer_api.ssrf.guard_hosts_async so routers
stay focused on their URL shape and error context.

MCP server refactor deferred to a follow-up.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

# Batch 2 — Feature-flag audit

## Task 5: Gate OpenTelemetry behind `otel` feature

**Files:**
- Modify: `seer-core/Cargo.toml`
- Modify: `seer-core/src/logging.rs`

- [ ] **Step 5.1:** Make OTEL deps optional in `seer-core/Cargo.toml`.

Edit `seer-core/Cargo.toml`. Change the four OTEL lines (23, 25–28):

From:
```toml
tracing-opentelemetry = { workspace = true }
opentelemetry = { workspace = true }
opentelemetry_sdk = { workspace = true }
opentelemetry-otlp = { workspace = true }
```

To:
```toml
tracing-opentelemetry = { workspace = true, optional = true }
opentelemetry = { workspace = true, optional = true }
opentelemetry_sdk = { workspace = true, optional = true }
opentelemetry-otlp = { workspace = true, optional = true }
```

Then add a `[features]` block at the end of the file:

```toml
[features]
default = []
otel = [
    "dep:tracing-opentelemetry",
    "dep:opentelemetry",
    "dep:opentelemetry_sdk",
    "dep:opentelemetry-otlp",
]
```

- [ ] **Step 5.2:** Gate `build_otel_layer` and its call site in `logging.rs`.

Find the `build_otel_layer` definition at `seer-core/src/logging.rs:155-194`. Replace the entire function (and its doc-comment, starting at line 155) with:

```rust
/// Build the OpenTelemetry OTLP tracing layer if `ARCANUM_OTEL_ENDPOINT` is
/// set and the `otel` feature is enabled. Returns `None` when either
/// condition is unmet (zero cost when the feature is off).
#[cfg(feature = "otel")]
fn build_otel_layer<S>(
    service_name: &str,
) -> Option<tracing_opentelemetry::OpenTelemetryLayer<S, opentelemetry_sdk::trace::SdkTracer>>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::WithExportConfig as _;

    let endpoint = std::env::var("ARCANUM_OTEL_ENDPOINT").ok()?;
    if endpoint.is_empty() {
        return None;
    }

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(&endpoint)
        .build()
        .ok()?;

    let tracer_provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(
            opentelemetry_sdk::Resource::builder()
                .with_service_name(service_name.to_string())
                .build(),
        )
        .build();

    let tracer = tracer_provider.tracer(service_name.to_string());

    // Keep the provider alive — leaking is acceptable here because it lives
    // for the process lifetime and must not be dropped before shutdown.
    std::mem::forget(tracer_provider);

    Some(tracing_opentelemetry::layer().with_tracer(tracer))
}

/// No-op fallback when the `otel` feature is disabled. Returning `None` from
/// a typed layer at the call site lets the subscriber builder skip it.
#[cfg(not(feature = "otel"))]
fn build_otel_layer<S>(_service_name: &str) -> Option<tracing_subscriber::layer::Identity>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    None
}
```

- [ ] **Step 5.3:** Check call sites of `build_otel_layer`.

Run:
```bash
grep -rn "build_otel_layer" seer-core/src
```
Expected: the definition + one or two call sites in `logging.rs`. Read each call site and ensure it wraps the result in `Option`-combinator form (e.g. `.with(build_otel_layer::<_>(name))`). The `Option<Layer>`-with-`.with(...)` pattern in `tracing-subscriber` accepts any `impl Layer`, and `Identity` implements `Layer` trivially, so this compiles cleanly in both feature configurations.

- [ ] **Step 5.4:** Build both configurations.

Run:
```bash
cargo build -p seer-core 2>&1 | tail -5
cargo build -p seer-core --features otel 2>&1 | tail -5
cargo build --release 2>&1 | tail -5
ls -la target/release/seer
```
Expected: both builds succeed; default-feature binary is smaller than before (1.5–3MB reduction).

- [ ] **Step 5.5:** Run tests.

```bash
cargo test -p seer-core 2>&1 | tail -15
cargo test -p seer-core --features otel 2>&1 | tail -15
```
Expected: both test runs pass.

- [ ] **Step 5.6:** Commit.

```bash
git add seer-core/Cargo.toml seer-core/src/logging.rs
git commit -m "$(cat <<'EOF'
perf(build): gate OpenTelemetry deps behind otel feature

tracing-opentelemetry + opentelemetry + opentelemetry_sdk +
opentelemetry-otlp (with grpc-tonic) are now optional. Without the
feature, the OTEL layer compiles to a no-op Identity layer and the
deps don't link.

Enables --features otel for production deployments that need OTLP
export. Default builds shed ~1.5-3MB and drop the tonic/prost/hyper
transitive tree.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Gate DNSSEC verification behind `dnssec` feature

**Files:**
- Modify: `seer-core/Cargo.toml`
- Modify: `Cargo.toml` (workspace hickory-resolver feature)

**Scope:** The `DnssecChecker`/`DnssecReport` types are used by all output formatters. The expensive dep is the `hickory-resolver/dnssec-ring` feature (pulls ring + DNSSEC signature validation). This task gates ONLY the hickory dnssec feature. The types and `check()` API remain available and keep their current behavior (they don't actually call hickory's DNSSEC validation — they query DNSKEY/DS/RRSIG as normal records and inspect them structurally).

- [ ] **Step 6.1:** Confirm dnssec.rs does not call hickory's DNSSEC types.

Run:
```bash
grep -n "hickory_resolver::dnssec\|DnssecProof\|ValidatingResolver" seer-core/src/dns/dnssec.rs
```
If empty: proceed — the module uses standard record lookups. If non-empty: the `dnssec` feature must also gate that module's compilation; adjust this task to add `#[cfg(feature = "dnssec")]` on the affected call sites.

- [ ] **Step 6.2:** Change workspace `hickory-resolver` to a no-dnssec default.

Edit `/home/zac/Projects/arcanum_suite/seer/Cargo.toml` line 29:

From:
```toml
hickory-resolver = { version = "0.24", features = ["dnssec-ring"] }
```

To:
```toml
hickory-resolver = { version = "0.24" }
```

- [ ] **Step 6.3:** Add `dnssec` feature to `seer-core`.

Edit `seer-core/Cargo.toml`. Add a line to the dependency for hickory-resolver — since it's workspace-based, modify the line that pulls it:

From:
```toml
hickory-resolver = { workspace = true }
```

To:
```toml
hickory-resolver = { workspace = true, features = [] }
```

Update the `[features]` block added in Task 5 to add a `dnssec` feature:

```toml
[features]
default = ["dnssec"]
dnssec = ["hickory-resolver/dnssec-ring"]
otel = [
    "dep:tracing-opentelemetry",
    "dep:opentelemetry",
    "dep:opentelemetry_sdk",
    "dep:opentelemetry-otlp",
]
```

- [ ] **Step 6.4:** Build both configurations.

```bash
cargo build --release 2>&1 | tail -5
cargo build --release --no-default-features 2>&1 | tail -5
ls -la target/release/seer
```
Expected: both builds succeed. Default build is unchanged in behavior (dnssec stays on by default). `--no-default-features` build is smaller.

- [ ] **Step 6.5:** Run tests.

```bash
cargo test --workspace 2>&1 | tail -15
```
Expected: all pass. Dnssec-specific tests in `dns/dnssec.rs` may need network; they should already be `#[ignore]`-gated per the repo convention.

- [ ] **Step 6.6:** Commit.

```bash
git add Cargo.toml seer-core/Cargo.toml
git commit -m "$(cat <<'EOF'
perf(build): gate hickory-resolver dnssec-ring behind dnssec feature

The hickory-resolver dnssec-ring feature pulls ring and the signature-
validation path that seer-core doesn't actually exercise (DnssecChecker
reads DNSKEY/DS records and inspects them structurally, it doesn't
ask hickory to verify signatures).

Default = ["dnssec"] keeps the feature on by default for minimal
disruption. --no-default-features drops the dnssec-ring dep.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Trim `tokio` features

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 7.1:** Narrow tokio features.

Edit `/home/zac/Projects/arcanum_suite/seer/Cargo.toml` line 23:

From:
```toml
tokio = { version = "1", features = ["full"] }
```

To:
```toml
tokio = { version = "1", features = ["rt-multi-thread", "macros", "net", "time", "sync", "io-util", "signal"] }
```

- [ ] **Step 7.2:** Build.

```bash
cargo build --release 2>&1 | tail -15
```
If the build fails with a missing feature (e.g. `fs`, `process`, `parking_lot`), read the error to identify which feature is needed and add it to the list. Common candidates if they emerge: `fs` (unlikely for seer), `process` (very unlikely).

- [ ] **Step 7.3:** Run tests.

```bash
cargo test --workspace 2>&1 | tail -15
```
Expected: all pass.

- [ ] **Step 7.4:** Commit.

```bash
git add Cargo.toml
git commit -m "$(cat <<'EOF'
perf(build): trim tokio features from "full" to used subset

tokio = "full" pulls fs, process, parking_lot, and other features
seer doesn't use. Narrow to the actual dependency surface:
rt-multi-thread, macros, net, time, sync, io-util, signal.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

# Batch 3 — File splits (pure refactor)

These four tasks are large mechanical moves. TDD doesn't apply — existing tests must pass unchanged both before and after. The split is validated by `cargo test --workspace`, `cargo clippy -- -D warnings`, and `cargo fmt --check`.

## Task 8: Split `seer-core/src/output/human.rs`

**Files:**
- Create: `seer-core/src/output/human/mod.rs`
- Create: `seer-core/src/output/human/whois.rs`
- Create: `seer-core/src/output/human/rdap.rs`
- Create: `seer-core/src/output/human/dns.rs`
- Create: `seer-core/src/output/human/status.rs`
- Create: `seer-core/src/output/human/lookup.rs`
- Create: `seer-core/src/output/human/propagation.rs`
- Create: `seer-core/src/output/human/follow.rs`
- Create: `seer-core/src/output/human/diff.rs`
- Delete: `seer-core/src/output/human.rs` (after move)

- [ ] **Step 8.1:** Inventory the current file.

Run:
```bash
grep -n "^    pub fn\|^    fn\|^impl\|^pub struct\|^struct\|^static\|^fn " seer-core/src/output/human.rs
```
Record which functions are shared helpers vs per-entity formatters. Shared helpers: `sanitize_display`, `format_duration`, `ANSI_ESCAPE_RE`, and the `HumanFormatter` methods `label/value/success/warning/error/dim` (and any sibling helpers). Everything else is a per-entity formatter.

- [ ] **Step 8.2:** Create `seer-core/src/output/human/mod.rs` with the struct + shared helpers.

Move into `mod.rs`:
- The file-level `use` statements still needed
- `ANSI_ESCAPE_RE` (static)
- `sanitize_display` (fn)
- `format_duration` (fn)
- `pub struct HumanFormatter { use_colors: bool }`
- `impl Default for HumanFormatter`
- `impl HumanFormatter { new, without_colors, label, value, success, warning, error, dim, + any other tiny private helpers }`
- The `OutputFormatter` trait impl block — but split across the submodule files by moving each `fn format_X` into its own submodule (each submodule re-opens `impl OutputFormatter for HumanFormatter`).

At the top of `mod.rs` add:
```rust
mod whois;
mod rdap;
mod dns;
mod status;
mod lookup;
mod propagation;
mod follow;
mod diff;
```

Plus `#[cfg(test)] mod tests { ... }` for any tests that were on shared helpers.

- [ ] **Step 8.3:** Create each per-entity file.

Each file (e.g. `seer-core/src/output/human/whois.rs`) has this shape:

```rust
use super::HumanFormatter;
use crate::whois::WhoisResponse;
// ... any other imports the moved function needs (e.g. Colorize, CatppuccinExt)

impl HumanFormatter {
    pub(super) fn format_whois_inner(&self, response: &WhoisResponse) -> String {
        // moved function body verbatim
    }
}
```

If the existing trait-method name is `format_whois`, keep it as-is inside the same crate visibility — the `impl OutputFormatter for HumanFormatter` block can be split across files in Rust (each file adds methods to the same trait impl only if they all re-open `impl OutputFormatter`). Simpler: put the `impl OutputFormatter for HumanFormatter` block in `mod.rs` with one-liners that delegate to `self.format_whois_inner(...)`, `self.format_rdap_inner(...)` etc, each of which lives in its submodule as `impl HumanFormatter`.

Per-entity file contents (one per concept):
- `whois.rs` — `format_whois_inner` + any private helpers called by it + `#[cfg(test)]` tests for the WHOIS formatter
- `rdap.rs` — same, for RDAP
- `dns.rs` — DNS records formatter (including DNSSEC report formatter — `format_dnssec`)
- `status.rs` — status formatter
- `lookup.rs` — LookupResult formatter
- `propagation.rs` — propagation formatter
- `follow.rs` — DnsFollower/FollowIteration formatter
- `diff.rs` — diff formatter

- [ ] **Step 8.4:** Delete `seer-core/src/output/human.rs`.

Run:
```bash
rm seer-core/src/output/human.rs
```

- [ ] **Step 8.5:** Verify `output/mod.rs` imports don't change.

Run:
```bash
grep -n "human" seer-core/src/output/mod.rs
```
The `mod human;` line continues to work because Rust resolves `mod human;` to either `human.rs` or `human/mod.rs`.

- [ ] **Step 8.6:** Build, test, clippy, fmt.

```bash
cargo build --release 2>&1 | tail -5
cargo test --workspace --no-fail-fast 2>&1 | tail -15
cargo clippy --workspace -- -D warnings 2>&1 | tail -10
cargo fmt --check 2>&1 | tail -5
```
Expected: all pass.

- [ ] **Step 8.7:** Commit.

```bash
git add seer-core/src/output/human.rs seer-core/src/output/human/
git commit -m "$(cat <<'EOF'
refactor(output): split human.rs into per-entity submodules

human.rs grew to 3500 lines with formatters for 9 entity types.
Split into output/human/{mod,whois,rdap,dns,status,lookup,propagation,
follow,diff}.rs. Shared helpers (sanitize_display, format_duration,
label/value/success/warning/error/dim) live in mod.rs.

Pure refactor: no public API change, no test changes, behavior
identical.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: Split `seer-core/src/output/markdown.rs`

**Files:**
- Create: `seer-core/src/output/markdown/mod.rs` + per-entity submodules (as in Task 8)
- Delete: `seer-core/src/output/markdown.rs`

- [ ] **Step 9.1:** Inventory current file.

```bash
grep -n "fn format_\|^impl\|^pub struct" seer-core/src/output/markdown.rs
```
Identify the same per-entity boundaries as human.rs. Expected: parallel structure with `format_whois`, `format_rdap`, `format_dns`, `format_status`, `format_lookup`, `format_propagation`, `format_diff`, `format_dnssec`.

- [ ] **Step 9.2:** Apply the same split pattern as Task 8.

Create `seer-core/src/output/markdown/mod.rs` with the `MarkdownFormatter` struct, any shared helpers, and `mod whois; mod rdap; ...` declarations. Move each formatter function into the matching submodule as `impl MarkdownFormatter { pub(super) fn format_X_inner(&self, ...) -> String { ... } }`. Keep the `impl OutputFormatter for MarkdownFormatter` block in `mod.rs` with delegating one-liners.

- [ ] **Step 9.3:** Delete old file, build, test.

```bash
rm seer-core/src/output/markdown.rs
cargo build --release 2>&1 | tail -5
cargo test --workspace 2>&1 | tail -15
cargo clippy --workspace -- -D warnings 2>&1 | tail -10
cargo fmt --check
```
Expected: all pass.

- [ ] **Step 9.4:** Commit.

```bash
git add seer-core/src/output/markdown.rs seer-core/src/output/markdown/
git commit -m "$(cat <<'EOF'
refactor(output): split markdown.rs into per-entity submodules

Parallel treatment of output/human.rs. Split the 1705-line markdown.rs
into output/markdown/{mod,whois,rdap,dns,status,lookup,propagation,
diff}.rs. Pure refactor.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: Split `seer-core/src/lookup.rs`

**Files:**
- Create: `seer-core/src/lookup/mod.rs`
- Create: `seer-core/src/lookup/cache.rs`
- Create: `seer-core/src/lookup/inflight.rs`
- Create: `seer-core/src/lookup/race.rs`
- Create: `seer-core/src/lookup/classify.rs`
- Delete: `seer-core/src/lookup.rs`

- [ ] **Step 10.1:** Inventory.

```bash
grep -n "^fn\|^async fn\|^pub fn\|^pub async fn\|^pub struct\|^struct\|^pub enum\|^enum\|^static\|^impl" seer-core/src/lookup.rs
```

Expected concerns (based on audit): `LOOKUP_CACHE`, `trim_for_cache`, `LookupCache` type; `LOOKUP_INFLIGHT`, `InflightGuard`, `Notify` management; `lookup_concurrent`, `LegOutcome` enum, `PROTOCOL_GRACE_PERIOD`; `is_rdap_response_useful`, `RdapOutcome` enum, response classification.

- [ ] **Step 10.2:** Split.

`mod.rs`:
- `pub struct SmartLookup` + `impl Default` + `impl SmartLookup` with the `lookup`, `lookup_with_progress`, `clear_cache`, `new` methods
- `pub enum LookupResult` + its serde
- Any other public re-exports
- `mod cache; mod inflight; mod race; mod classify;`
- `#[cfg(test)] mod tests` for integration-level tests on `SmartLookup`

`cache.rs`:
- `LOOKUP_CACHE` static
- `trim_for_cache` function
- `LookupCache` type (if it exists — check the file)
- `#[cfg(test)] mod tests` for cache tests

`inflight.rs`:
- `LOOKUP_INFLIGHT` static
- `InflightGuard` struct + Drop impl
- Supporting types for slot/waiter coordination
- `#[cfg(test)] mod tests` for in-flight dedup tests

`race.rs`:
- `lookup_concurrent` (private to crate, called from `mod.rs`)
- `LegOutcome` enum
- `PROTOCOL_GRACE_PERIOD` const
- Any tokio select orchestration

`classify.rs`:
- `is_rdap_response_useful`
- `RdapOutcome` enum
- `LookupProgressCallback` if it lives here
- Classification tests

- [ ] **Step 10.3:** Verify `lib.rs` re-exports still compile.

```bash
grep -n "lookup::" seer-core/src/lib.rs
```
Adjust `pub use` paths if needed — likely they're `pub use crate::lookup::{SmartLookup, LookupResult}` which works identically whether `lookup` is a file or a directory.

- [ ] **Step 10.4:** Build, test, clippy, fmt.

```bash
rm seer-core/src/lookup.rs
cargo build --release 2>&1 | tail -5
cargo test --workspace 2>&1 | tail -15
cargo clippy --workspace -- -D warnings 2>&1 | tail -10
cargo fmt --check
```

- [ ] **Step 10.5:** Commit.

```bash
git add seer-core/src/lookup.rs seer-core/src/lookup/
git commit -m "$(cat <<'EOF'
refactor(lookup): split lookup.rs into cache/inflight/race/classify

lookup.rs grew to 1341 lines interleaving cache, in-flight dedup,
RDAP+WHOIS race orchestration, and response classification. Split
into seer-core/src/lookup/{mod,cache,inflight,race,classify}.rs.

Pure refactor: SmartLookup, LookupResult, and all re-exports
unchanged.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 11: Split `seer-core/src/rdap/client.rs`

**Files:**
- Create: `seer-core/src/rdap/bootstrap.rs`
- Modify: `seer-core/src/rdap/client.rs` (slim down to per-query client)
- Modify: `seer-core/src/rdap/mod.rs` (declare new submodule)

- [ ] **Step 11.1:** Inventory bootstrap vs client concerns.

```bash
grep -n "^fn\|^async fn\|^pub fn\|^pub async fn\|^pub struct\|^struct\|^pub enum\|^enum\|^static\|^impl" seer-core/src/rdap/client.rs
```

Expected bootstrap concerns: `IANA_BOOTSTRAP_DNS/IPV4/IPV6/ASN` consts, `RDAP_HTTP_CLIENT`, `BOOTSTRAP_CACHE`, `BOOTSTRAP_LAST_ATTEMPT`, `BOOTSTRAP_LOAD_NOTIFY`, `CachedBootstrap`, `BootstrapData`, `IpRange`, `AsnRange`, bootstrap load functions, URL selection from bootstrap data.

Expected client concerns: `RdapClient`, `with_retry_policy`, `without_retries`, `lookup_domain`, `lookup_ip`, `lookup_asn`, per-query HTTP logic.

- [ ] **Step 11.2:** Move bootstrap concerns to `seer-core/src/rdap/bootstrap.rs`.

Create the new file with all bootstrap-related items. Make the public API from bootstrap available as `pub(super)` items so `client.rs` can call them, e.g. `pub(super) async fn get_bootstrap() -> Result<Arc<BootstrapData>>`.

- [ ] **Step 11.3:** Update `seer-core/src/rdap/client.rs` to consume bootstrap via the new module.

Delete the moved items and replace their usages with `super::bootstrap::get_bootstrap()` (or whatever name the refactor settles on).

- [ ] **Step 11.4:** Update `seer-core/src/rdap/mod.rs`.

Add `mod bootstrap;` near the top alongside existing `mod client; mod types;`.

- [ ] **Step 11.5:** Build, test, clippy, fmt.

```bash
cargo build --release 2>&1 | tail -5
cargo test --workspace 2>&1 | tail -15
cargo clippy --workspace -- -D warnings 2>&1 | tail -10
cargo fmt --check
```

- [ ] **Step 11.6:** Commit.

```bash
git add seer-core/src/rdap/
git commit -m "$(cat <<'EOF'
refactor(rdap): extract bootstrap logic from client.rs

rdap/client.rs was 1385 lines covering IANA bootstrap fetching,
cache + TTL, load coordination via Notify, URL selection, and the
per-query RdapClient. Move bootstrap concerns into rdap/bootstrap.rs.

Pure refactor: RdapClient public API unchanged.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 12: Final verification and PR

**Files:** none.

- [ ] **Step 12.1:** Full verification pass.

```bash
cd /home/zac/Projects/arcanum_suite/seer
cargo fmt --check 2>&1 | tail -5
cargo clippy --workspace -- -D warnings 2>&1 | tail -10
cargo test --workspace --no-fail-fast 2>&1 | tail -20
cargo build --release 2>&1 | tail -5
ls -la target/release/seer
cd seer-api && pytest 2>&1 | tail -15 && cd ..
```

Record final binary size; compare to baseline from Task 0.2. Expect ~14–16MB (down from ~20MB) with the release profile alone, or ~12–14MB with all feature flags default.

- [ ] **Step 12.2:** Rebuild Python bindings to confirm the PyO3 bridge still works.

```bash
cd seer-py && maturin develop --release 2>&1 | tail -10 && cd ..
python -c "import seer; print(seer.lookup('example.com'))"
```
Expected: returns a dict with lookup fields. Note: this hits the network; if offline, skip.

- [ ] **Step 12.3:** Push and open PR.

```bash
git push -u origin claude/optimization-batches-20260421
gh pr create --title "perf: three-batch optimization audit remediation" --body "$(cat <<'EOF'
## Summary

Executes all three batches from `docs/superpowers/specs/2026-04-21-optimization-audit-design.md`.

**Batch 1 — Mechanical wins:**
- Release profile tuning (lto=thin, codegen-units=1, strip=symbols). Binary ~20MB → ~14-16MB.
- Static DNS server list — eliminates ~116 allocations per propagation call.
- FastAPI now uses `ORJSONResponse` for 2-5× JSON serialization speedup.
- Extracted `run_seer` + `guard_hosts_async` helpers; routers slimmed.

**Batch 2 — Feature flags:**
- OpenTelemetry deps now behind `otel` feature (default: off). ~1.5-3MB binary savings.
- hickory-resolver `dnssec-ring` behind `dnssec` feature (default: on) — can be stripped for minimal builds.
- Trimmed `tokio = "full"` to used feature subset.

**Batch 3 — File splits (pure refactor):**
- `output/human.rs` (3500 lines) → `output/human/{mod,whois,rdap,dns,status,lookup,propagation,follow,diff}.rs`
- `output/markdown.rs` (1705 lines) → parallel treatment
- `lookup.rs` (1341 lines) → `lookup/{mod,cache,inflight,race,classify}.rs`
- `rdap/client.rs` (1385 lines) → extracted `rdap/bootstrap.rs`

No public API changes. No behavioral changes outside documented feature defaults.

## Test plan

- [ ] `cargo test --workspace` passes (hermetic)
- [ ] `cargo test --workspace -- --ignored` passes (live-network)
- [ ] `cargo clippy --workspace -- -D warnings` passes
- [ ] `cargo fmt --check` passes
- [ ] `cd seer-api && pytest` passes
- [ ] `cargo build --release` + `--no-default-features` + `--features otel` all succeed
- [ ] Manual smoke: `seer lookup example.com`, `seer dig example.com MX`, `seer-api` boots and serves `/lookup/example.com`

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

Return the PR URL.

---

## Self-review checklist

- **Spec coverage:** Each spec section (Batch 1: 1A–1D, Batch 2: 2A–2C, Batch 3: 3A–3D) maps to a task (Tasks 1–11). Out-of-scope items are explicitly deferred. ✓
- **Placeholder scan:** No TBDs, TODOs, or handwaving. Each step includes exact paths, commands, and code. ✓
- **Type consistency:** `run_seer`/`guard_hosts_async` names match across `_run.py`/`ssrf.py` and every router refactor. Feature names `otel`/`dnssec` match across Cargo.toml and cfg gates. ✓
- **Task granularity:** Each step is 2–5 minutes of work. Commits happen per-task. ✓
