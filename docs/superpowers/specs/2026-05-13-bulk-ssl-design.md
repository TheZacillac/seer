# Bulk SSL Chain Inspection

Date: 2026-05-13
Status: Approved

## Goal

Add a new `Ssl` bulk operation that runs deep SSL certificate chain inspection
(`SslChecker::check()`) concurrently across a list of domains. Behaviorally
parallel to the existing `bulk status` operation, but using the full SSL report
(chain, SANs, key details, signature algorithm, TLS version).

## Motivation

Today, `bulk status` returns only an SSL *summary* (issuer, valid_until,
days_remaining) embedded in the per-domain status response. The deeper
`seer ssl <domain>` command (`SslChecker`) — which produces a full chain plus
SAN list, key type/bits, signature algorithm, and TLS version — is single-domain
only. This proposal exposes the deep inspection through every bulk surface
(CLI, Python binding, REST API, MCP) so it can be run across hundreds of
domains in one batch.

## Architecture

All business logic stays in `seer-core`. CLI, Python, API, and MCP layers are
thin wrappers — same pattern as the existing bulk operations.

### 1. `seer-core/src/bulk/executor.rs`

Additive changes only.

- New variant `BulkOperation::Ssl { domain }`.
- New variant `BulkResultData::Ssl(SslReport)`.
- New field `ssl_checker: SslChecker` on `BulkExecutor`, initialized in `new()`.
- `Clients<'a>` gains `ssl: &'a SslChecker`.
- `execute_operation` gains an `Ssl` arm that calls `clients.ssl.check(domain)`.
- The progress-description match in `execute()` adds the `Ssl { domain }` arm.
- New convenience method `execute_ssl(domains: Vec<String>) -> Vec<BulkResult>`
  matching the existing `execute_status` pattern.

### 2. `seer-cli/src/main.rs`

Extend the existing `bulk` subcommand:

- Add `"ssl"` arm to the `match operation.as_str()` block, mapping each domain
  to `BulkOperation::Ssl { domain }`.
- Add `ssl` to the help text and the unknown-operation error message.
- Add the `Ssl { domain }` arm to each `match &r.operation` block (three sites
  that destructure the operation back to its domain string for progress/output).

### 3. `seer-cli/src/utils.rs` — CSV output

Add a `BulkResultData::Ssl(report)` arm emitting a **leaf-only summary row**:

Columns (in order):

```
domain, success, subject, issuer, valid_from, valid_until, days_remaining,
signature_algorithm, key_type, key_bits, chain_length, san_count, sans,
protocol_version, is_valid, duration_ms, error
```

- `subject`, `issuer`, `valid_from`, `valid_until`, `signature_algorithm`,
  `key_type`, `key_bits` are taken from the leaf cert (`chain[0]`).
- `days_remaining` mirrors `SslReport::days_until_expiry`.
- `chain_length` = `report.chain.len()`.
- `san_count` = `report.san_names.len()`.
- `sans` = SAN list joined by `;`, capped at the first 10 entries; when the
  list is longer, append `;…+N more` where N is the excess count. This
  prevents wildcard certs with 100+ SANs from blowing out a CSV row while
  keeping the column truthful.
- `protocol_version` = `report.protocol_version.unwrap_or_default()`.
- `is_valid` = `report.is_valid`.
- On failure: all SSL columns are empty strings; `error` is populated.
- The CSV header is emitted only when the bulk operation is `ssl`,
  paralleling the existing per-op header dispatch in this file.

### 4. `seer-py/src/lib.rs` — `bulk_ssl` function

Mirror `bulk_status` exactly:

```rust
#[pyfunction]
#[pyo3(signature = (domains, concurrency = 10, *, progress = None))]
fn bulk_ssl(
    py: Python<'_>,
    domains: Vec<String>,
    concurrency: usize,
    progress: Option<Py<PyAny>>,
) -> PyResult<PyObject>
```

Same body shape: `BulkExecutor::new().with_concurrency(...)`, map domains to
`BulkOperation::Ssl`, run via `run_async_infallible`, serialize, convert to
Python. Register with `wrap_pyfunction!(bulk_ssl, m)?`.

### 5. `seer-py/python/seer/__init__.py`

Add `bulk_ssl` to the imports from the compiled module and to `__all__`,
alongside `bulk_status`.

### 6. `seer-api/seer_api/routers/ssl.py` — new router

New file. Structure mirrors `status.py`:

- `POST /ssl/bulk` — buffered bulk response.
- `POST /ssl/bulk/stream` — Server-Sent Events streaming variant.
- Request body uses the same shape as `BulkStatusRequest` (rename to
  `BulkSslRequest` to keep types domain-specific); reuses
  `MAX_BULK_DOMAINS = 100` and `MAX_CONCURRENCY = 50`.
- Same rate limit (`5/minute`).
- Same `guard_hosts_async([(d, 443) for d in body.domains])` SSRF guard.
- Calls `seer.bulk_ssl` via `run_seer` / `stream_bulk`.

The single-domain `GET /ssl/{domain}` is intentionally out of scope (see
"Out of scope" below).

### 7. `seer-api/seer_api/main.py`

Register the router:

```python
from .routers import ssl
app.include_router(ssl.router, prefix="/ssl", tags=["ssl"])
```

### 8. `seer-api/seer_api/mcp/server.py`

Add one MCP tool:

- Tool name: `seer_bulk_ssl`.
- Schema: `domains: list[str]`, `concurrency: int = 10` (mirrors
  `seer_bulk_status`).
- Handler: `case "seer_bulk_ssl":` calling `seer.bulk_ssl(domains, concurrency)`
  via the same `run_in_executor` pattern used by `seer_bulk_status`.

## Testing

Hermetic tests (run on every `cargo test` / `pytest`):

- `seer-core/src/bulk/executor.rs`: a test asserting that running
  `execute_ssl` against an unresolvable hostname (e.g.
  `nonexistent.invalid.example`) yields `success: false` with `error`
  populated — no live network required because resolution fails locally.
- `seer-cli/src/utils.rs`: a unit test for the SSL CSV row formatter,
  covering both the success path (using a constructed `SslReport`) and the
  failure path (empty SSL columns, populated `error`).
- `seer-cli/src/utils.rs`: a unit test for the SAN truncation rule (≤10
  SANs joined as-is; >10 SANs joined as first 10 followed by `;…+N more`).

Live-network tests (opt-in, `#[ignore]` or `SEER_LIVE_TESTS=1`):

- Rust: integration test running `execute_ssl(vec!["cloudflare.com".into()])`
  and asserting a non-empty chain.
- Python: a `pytest` test under `SEER_LIVE_TESTS=1` calling
  `seer.bulk_ssl(["cloudflare.com"])` and asserting `success is True` and
  `data["chain"]` is non-empty.

## Out of scope (YAGNI)

- No JSONL/streaming variant for the CLI — only CSV, matching every other
  bulk operation today.
- No new `GET /ssl/{domain}` route. The user asked for bulk, and deep
  single-domain inspection is already available via the CLI (`seer ssl`)
  and MCP tools. Adding a single-domain endpoint can be a separate proposal
  if needed.
- No JSON-flattening of the SSL chain into the CLI human formatter — the
  existing `output/human.rs` `format_ssl` is reused as-is for human/JSON
  rendering of individual results within the bulk run.

## Risk / compatibility notes

- The change is purely additive across all surfaces; no existing field
  names, route paths, CSV column orderings, or Python signatures change.
- The SSL operation will be slower per-domain than `status` because the
  TLS handshake plus full chain parsing is the bulk of the cost. The
  default concurrency of 10 and the existing 100-domain cap remain
  appropriate.
- SSRF protection on port 443 is already enforced inside `SslChecker::check`
  (reserved-IP check after `lookup_host`). The API layer additionally
  applies `guard_hosts_async` before dispatch, matching `status`.
