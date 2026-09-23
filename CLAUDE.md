# CLAUDE.md - AI Assistant Guide for Seer

Guidance for AI assistants working on the Seer codebase: architecture, layout,
workflows, and the rules the code follows.

---

## Project Overview

**Seer** is a multi-interface domain name utility tool written in Rust with Python bindings. It provides WHOIS, RDAP, DNS, SSL, domain status and security checks through multiple interfaces:

- **CLI** (seer-cli): Command-line tool with interactive REPL and full-screen TUI
- **Python Library** (seer-py): PyO3-based Python bindings
- **REST API** (seer-api): FastAPI-based web service
- **MCP Server** (seer-api): Model Context Protocol server for AI assistants

### Technology Stack

**Rust Core:**
- Tokio (async runtime)
- Reqwest (HTTP client)
- Hickory-resolver (DNS resolution)
- Serde (serialization)
- Thiserror (error handling)

**CLI:**
- Clap (command parsing)
- Rustyline (REPL)
- Ratatui + Crossterm (TUI)
- Indicatif (progress indicators)
- Colored (terminal colors)

**Python:**
- PyO3 (Rust/Python bindings)
- FastAPI (REST API)
- Pydantic (validation)
- MCP (Model Context Protocol)

### Versions

- **Rust**: edition 2021; MSRV 1.89 (enforced by the `msrv` CI job; floor set by
  rustyline 18's use of `std::fs::File::lock`, stabilized in 1.89. Previous
  floor was 1.88 via `x509-parser → time → time-macros`.)
- **Python**: 3.10+ (abi3 wheels)
- **License**: MIT

---

## Architecture

### Workspace Organization

Seer uses a Cargo workspace with 3 Rust crates and 1 Python package:

```
seer/
├── Cargo.toml              # Workspace root with shared dependencies
├── seer-core/              # Core Rust library (all business logic)
├── seer-cli/               # CLI application (commands + REPL + TUI)
├── seer-py/                # Python bindings (PyO3 wrapper)
└── seer-api/               # FastAPI REST + MCP server (Python)
```

### Dependency Flow

```
seer-cli ──┐
           ├──> seer-core (Rust core library)
seer-py ───┘

seer-api (Python) ──> seer-py (Python package) ──> seer-core (Rust)
```

**Key Principle:** All business logic lives in `seer-core`. Other crates/packages are thin presentation layers.

---

## Codebase Structure

### seer-core/ (Core Library)

All business logic and domain operations live here:

```
seer-core/src/
├── lib.rs              # Module exports and re-exports
├── error.rs            # Centralized error types (SeerError enum)
├── colors.rs           # Catppuccin color palette for terminal output
├── config.rs           # User config file (~/.seer/config.toml), clamped ranges; [watch]/[tui] tables
├── doctor.rs           # `seer doctor` self-diagnosis: 4 concurrent probes (config/DNS/WHOIS-43/RDAP-bootstrap)
├── lookup.rs           # Smart lookup (RDAP-first with WHOIS fallback, in-flight coalescing)
├── availability.rs     # Domain availability detection (RDAP 404 + DNS + patterns)
├── domain_info.rs      # Merged RDAP + WHOIS flat structure
├── retry.rs            # RetryPolicy/RetryExecutor: exponential backoff + jitter
├── cache.rs            # Generic TtlCache (stale-while-revalidate, capacity-bounded)
├── net.rs              # SSRF guards: resolve/validate public hosts (refuses loopback/private)
├── validation.rs       # Domain normalization, reserved-IP checks, SEER_DOMAIN_ALLOWLIST
├── psl.rs              # (private) Public Suffix List: registrable-domain boundary (example.co.uk)
├── dates.rs            # (private) shared "days until expiry" arithmetic
├── fsutil.rs           # (private) atomic owner-only saves for the ~/.seer stores
├── ssl.rs              # SSL chain inspection (single-attempt by design)
├── caa.rs              # CAA policy lookup + issuer comparison
├── posture.rs          # Email/DNS security posture: SPF/DMARC/MTA-STS/BIMI/DANE verdicts
├── headers.rs          # HTTP security-header + cookie audit, weighted 0-100 score -> A+-F grade
├── takeover.rs         # Subdomain takeover: provider CNAME match + HTTP body fingerprint confirmation
├── http.rs             # (private) SSRF-guarded HTTP GET: manual per-hop redirect validation, pinned addrs, capped body
├── confusables.rs      # Typosquat/homoglyph look-alike generation + registration scoring
├── subdomains/         # Subdomain enumeration via CT logs: ordered source chain (crt.sh→certspotter) + per-source retry treating crt.sh 404/429/HTML-body as transient
├── diff.rs             # Side-by-side domain comparison
├── drift.rs            # Registration drift detection vs stored history snapshot
├── watchlist.rs        # Cert/registration expiry watchlist
├── webhook.rs          # SSRF-guarded JSON webhook POST (watch --webhook): pinned addrs, no redirects
├── history.rs          # Lookup history
├── logging.rs          # tracing setup (+ optional OTel via `otel` feature)
│
├── whois/              # WHOIS: TCP client w/ referral following, parsers/ registry, TLD map
├── rdap/               # RDAP: HTTP client, IANA bootstrap (+bootstrap.rs), types
├── dns/                # DNS: resolver, records, propagation/, compare, follow, DNSSEC, delegation
├── status/             # Domain health: HTTP/SSL/expiration/DNS (single-attempt by design)
├── tld/                # TLD info (WHOIS server, RDAP endpoint, registry URL)
├── bulk/               # Concurrent bulk executor + domain-list parsing
└── output/             # OutputFormat enum + human/ (colored), markdown/, json, yaml
```

Each directory module's `mod.rs` opens with a `//!` overview (rendered on
docs.rs); there are no per-module README files.

#### Module Responsibilities

- **error.rs**: All error types in one place, uses thiserror
- **config.rs**: Loads `~/.seer/config.toml` (timeouts, concurrency, output format, nameserver, `[watch] webhook_url`, `[tui] theme`); values clamped to safe ranges; `seer config --init` scaffolds it
- **whois/**: WHOIS protocol, parsing (per-registry `parsers/` registry), referral following (max depth: 3), IANA discovery fallback for unmapped TLDs (24h TTL cache)
- **rdap/**: RDAP protocol, IANA bootstrap caching (24h TTL, stale-while-revalidate), domain/IP/ASN lookups, multi-candidate base-URL fallback, 429 Retry-After honoring
- **dns/**: DNS resolution (16 record types), propagation checking (30 servers), compare, follow (live monitor), DNSSEC validation, NS delegation health (delegation.rs: parent NS set vs zone NS RRset + per-server RD=0 lameness probes, SSRF-vetted)
- **status/**: HTTP status, SSL certificates, domain expiration checking — deliberately single-attempt (see module docs: health probes must not retry-mask flakiness)
- **lookup.rs**: Smart lookup orchestration (RDAP → WHOIS fallback)
- **doctor.rs**: `seer doctor` diagnosis — 4 concurrent probes (config parse, DNS resolve, WHOIS port-43, RDAP bootstrap HTTPS), each stage-bounded (exchange legs 5s; the WHOIS probe's resolution stage runs through `net::resolve_public_host`, separately capped there, for parity with how production WHOIS connects); `overall` = worst check (malformed config = Warn since defaults still work; unreachable network = Fail); probe endpoints injectable via `#[cfg(test)]`-only seams
- **webhook.rs**: SSRF-guarded JSON webhook delivery for `seer watch --webhook` — resolved addresses vetted then pinned on the client (rebinding defense), redirects disabled, single-attempt, 10s timeout, non-2xx surfaces status only (never the body)
- **headers.rs**: `seer headers` — one non-intrusive GET graded across the security headers (HSTS, CSP, XFO, nosniff, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP), every `Set-Cookie`'s Secure/HttpOnly/SameSite flags, and version-disclosing banners. Weighted 0–100 score (weights sum to 100, asserted by a test) minus bounded cookie/disclosure penalties → A+–F. Verdicts reuse posture's Absent/Weak/Moderate/Strict/Present scale; CSP `frame-ancestors` counts as superseding `X-Frame-Options`. All grading is pure and unit-tested; only the fetch is async
- **takeover.rs**: `seer takeover` — the HTTP half of subdomain-takeover detection. `subdomains/classify.rs` already flags a dangling CNAME whose name stops resolving; this catches the commoner case where the provider still answers for a deprovisioned resource and only the response *body* says otherwise. 27 provider fingerprints; `Vulnerable` requires a matched body marker and always records it as evidence, `Potential` is an unconfirmable dangling CNAME — never promote one to the other without evidence. Hosts whose CNAME matches no provider are never fetched, bounding the HTTP fan-out
- **http.rs** (private): SSRF-guarded HTTP GET shared by headers/takeover. Redirects are followed **manually** with `net::validate_http_url` re-run at every hop — reqwest's own redirect policy would skip the guard (redirect-SSRF bypass) — validated addresses are pinned per hop against rebinding, and the body streams under an incremental cap. Single-attempt, like status/ssl
- **bulk/**: `BulkExecutor` — bounded concurrent fan-out (`buffer_unordered`) paced by a slot-based rate limiter; per-row results never abort the batch; plain-text/CSV domain-list parsing
- **retry.rs**: Shared retry framework — used by WHOIS/RDAP clients; dns/status/ssl intentionally don't (documented at their module level)
- **net.rs / validation.rs**: SSRF protection — all outbound hosts resolved and checked against reserved/private ranges before connect. `net::validate_http_url` is the single URL-shaped entry point (scheme, no credentials, ports 80/443 only, reserved-range check) shared by every HTTP fetch path — status, headers, takeover — so the policy cannot drift between them
- **output/**: Human (colored), JSON, YAML, and Markdown formatters behind `get_formatter(OutputFormat)`
- **colors.rs**: Catppuccin Frappe color palette

### seer-cli/ (CLI Application)

```
seer-cli/src/
├── main.rs             # Entry point, clap commands, subcommand dispatch
├── ops.rs              # Shared CLI/REPL pipelines (bulk op mapping, domain-list validation, drift/history snapshots)
├── payload.rs          # Payload enum over formatter-backed results (TUI raw view + `y` copy, REPL `copy`)
├── utils.rs            # Shared helpers: bulk CSV export, raw-mode guard, follow key loop, bulk input readers
├── clipboard.rs        # OSC52 terminal clipboard copy
├── repl/               # Interactive REPL
│   ├── mod.rs          # REPL main loop, session state
│   ├── commands.rs     # Command parsing and context
│   └── completer.rs    # Tab completion
├── display/            # Terminal progress UI
│   ├── spinner.rs      # Loading spinner for async operations
│   └── progress.rs     # Bulk progress bar that keeps tracing output from tearing it
└── tui/                # Full-screen ratatui TUI (`seer tui`)
    ├── mod.rs          # run(): terminal lifecycle + async select! loop
    ├── app.rs          # pure App state + update() (no ratatui imports)
    ├── action.rs       # FetchReq / Action / Msg / LensData / InputMode types
    ├── command.rs      # `:` command-line parser
    ├── event.rs        # normal-mode key → action mapping
    ├── data.rs         # async seer-core dispatch (the only core-coupled module)
    ├── filter.rs       # in-lens row filtering for the table lenses
    ├── line_editor.rs  # cursor-aware single-line editor for every input field
    ├── theme.rs        # Catppuccin Frappé + Latte palettes → ratatui Color (Theme::from_name)
    ├── render.rs       # frame rendering (shell + lens dispatch)
    ├── widgets/        # panel, kv, gauge, dot, chips
    ├── panes/          # interactive lens components (tld/dns/compare/diff/follow/bulk): state + handle_key
    └── lenses/         # registry + all 18 lens renderers
```

**Key Points:**
- Uses Clap v4 with derive macros
- Defaults to REPL when no command provided
- Supports global `--format` flag (human/json/yaml/markdown) — must be placed before the subcommand
- `seer generate-key` mints a random API key (OsRng, 256-bit, URL-safe base64) for `SEER_API_KEY`
- `seer doctor` runs `seer_core::doctor` and exits 1 only when `overall` is
  FAIL (WARN exits 0 — documented in its help). Rendering lives in the shared
  `pub(crate) render_doctor_report` (main.rs), used by both the CLI and the
  REPL `doctor` command since no `OutputFormatter` method exists for doctor
  reports.
- `seer dnssec <domain>` is check-style: exits 1 unless `report.status ==
  "signed"` (core's vocabulary is `signed | unsigned | partial |
  misconfigured` — it never says "secure").
- `seer delegation <domain>` is check-style: exits 1 when `!report.in_sync ||
  !report.lame.is_empty()`, 0 when healthy. Output goes through
  `get_formatter(format).format_delegation()`.
- `seer headers <domain>` audits HTTP security headers via
  `seer_core::audit_headers(&domain, config.http_timeout())`. Not check-style —
  it reports a grade and always exits 0, matching `posture`. Output goes
  through `get_formatter(format).format_headers()`.
- `seer takeover <domain>` is check-style: exits 1 when
  `report.has_findings()` (any vulnerable OR potential host), 0 when clean.
  Enumerates via `SubdomainEnumerator` then calls `seer_core::scan_takeover`
  with `config.bulk.concurrency`; `--host <HOST>` (repeatable) skips CT
  enumeration entirely and scans the given hosts. Output goes through
  `get_formatter(format).format_takeover()`.
- `seer watch --webhook <URL>` POSTs the check-all `WatchReport` as JSON via
  `seer_core::webhook::WebhookClient`; the flag overrides the config file's
  `watch.webhook_url`. Delivery is best-effort: failure prints a stderr
  warning and never changes the exit code.
- `seer mangen <DIR>` (hidden via `#[command(hide = true)]`) writes `seer.1`
  plus one page per visible subcommand with `clap_mangen::generate_to` —
  hidden commands (mangen itself) get no page.
- REPL history saved to `~/.seer_history`
- `seer tui [domain]` launches a full-screen ratatui TUI (additive — the REPL
  and all subcommands are unchanged). Architecture: async `tokio::select!` loop,
  pure `App` state (no I/O — file I/O runs in `mod.rs` via `spawn_blocking`),
  parameterized `FetchReq` lookups dispatched to `seer-core` over a channel, and
  interactive lenses as `panes/` components (`handle_key -> PaneOutcome`). All 18
  lenses are wired with live data + full in-pane inputs, including the streaming
  Follow (live monitor) and Bulk (concurrent + CSV export) lenses. A per-lens /
  per-stream generation guard drops stale async results (on domain/tab change or
  run restart). Two themes: Catppuccin Frappé (default) and Latte (light) —
  startup theme from `[tui] theme` in the config (`SeerConfig::tui_theme()`
  clamps unknown names to "frappe"), switchable live with `:theme <name>`
  through `App::set_theme_by_name`.

### seer-py/ (Python Bindings)

```
seer-py/
├── Cargo.toml          # Library config with crate-type = ["cdylib"]
├── pyproject.toml      # Maturin build config, ABI3 (Python 3.10+); version from the Cargo workspace
├── src/lib.rs          # PyO3 bindings, async→sync conversion
└── python/seer/        # Python wrapper package
    └── __init__.py     # Re-exports and convenience functions
```

**Key Points:**
- Single Tokio runtime via `OnceLock` (thread-safe singleton)
- All async Rust functions exposed synchronously to Python
- Custom `json_to_python()` converter for serde_json → Python objects
- `SeerError` maps to `ValueError` (invalid input), `TimeoutError`,
  `ConnectionError` (WHOIS connect failures) or `RuntimeError`, always with the
  sanitized message

### seer-api/ (FastAPI + MCP)

```
seer-api/
├── pyproject.toml          # Entry points: seer-api, seer-mcp
└── seer_api/
    ├── main.py             # FastAPI app: bearer-token auth, middleware stack, lifespan startup checks
    ├── _env.py             # strict integer env-var parsing
    ├── _run.py             # run_seer: bounded dispatch pool + SEER_REQUEST_TIMEOUT deadline
    ├── errors.py           # http_error: exception → sanitized HTTP status mapping
    ├── limiting.py         # rate limiter + proxy-aware client-IP keying
    ├── middleware.py       # body-size cap, request logging + /metrics counters
    ├── ssrf.py             # SSRF guard for user-supplied connect targets (status hosts, nameservers)
    ├── streaming.py        # SSE bulk-stream plumbing
    ├── routers/            # API endpoints by feature
    │   ├── lookup.py       # Smart lookup (single + bulk)
    │   ├── whois.py        # WHOIS lookups
    │   ├── rdap.py         # RDAP lookups
    │   ├── dns.py          # DNS queries
    │   ├── propagation.py  # DNS propagation
    │   ├── status.py       # Domain status
    │   ├── ssl.py          # SSL chain inspection
    │   ├── intel.py        # availability/info/subdomains/dnssec/delegation/diff/caa/posture/headers/takeover/confusables routers
    │   └── tld.py          # TLD info (/tld/{tld}) + full catalog (/tld/)
    └── mcp/
        └── server.py       # MCP server (30 tools)
```

**Key Points:**
- Secure by default: binds `127.0.0.1`; startup hard-fails on a non-loopback
  `SEER_HOST` without `SEER_API_KEY`, and on more than one worker with the
  `memory://` rate-limit store (per-worker limiters would be bypassable)
- OpenAPI docs at `/docs` and `/redoc` (off unless `SEER_DOCS_ENABLED`)
- CORS configured via `SEER_CORS_ORIGINS` env var
- Every REST route declares its own rate limit; `SEER_RATE_LIMIT` governs only `POST /mcp`
- Bulk endpoints have limits (max 100 domains, max 50 concurrency)
- MCP server exposes all operations as tools for AI assistants over TWO
  transports: stdio (`seer-mcp`) and Streamable HTTP at `POST /mcp` on the
  FastAPI app (same tool registry; session manager rebuilt per lifespan;
  DNS-rebinding protection opt-in via `SEER_MCP_ALLOWED_HOSTS`/`_ORIGINS`).
  `/mcp` is covered by the same `SEER_API_KEY` auth middleware as the REST API.

---

## Development Workflows

### Setting Up Development Environment

```bash
# 1. Clone repository
git clone https://github.com/TheZacillac/seer.git
cd seer

# 2. Install CLI to PATH (installs to ~/.cargo/bin/)
cargo install --path seer-cli

# 3. Build Python bindings
cd seer-py
maturin develop --release
cd ..

# 4. Install API package
cd seer-api
pip install -e .
cd ..
```

### Building

```bash
# Build all Rust packages (CLI + core + Python bindings)
cargo build --release

# Build only CLI
cargo build --release -p seer-cli

# Build only core library
cargo build --release -p seer-core

# Build Python bindings (development mode)
cd seer-py && maturin develop --release

# Build Python wheel
cd seer-py && maturin build --release
```

### Running Tests

```bash
# Run all Rust tests (hermetic only; live-network tests are skipped)
cargo test

# Run tests for specific package
cargo test -p seer-core
cargo test -p seer-cli

# Run Python tests
cd seer-api && pytest
cd seer-py && pytest

# Run with logging
RUST_LOG=debug cargo test
```

Unit tests live next to the code in `#[cfg(test)] mod tests`; bug fixes come
with a hermetic regression test.

#### Running live-network tests

Tests that hit real DNS/HTTP/WHOIS servers (cloudflare.com, wikipedia.org,
example.com, iana.org, etc.) are marked `#[ignore]` in Rust and
`@pytest.mark.skipif` in Python. They are opt-in so `cargo test` and
`pytest` stay hermetic by default:

```bash
# Run only the live-network Rust tests
cargo test --workspace -- --ignored

# Run Python live-network tests
SEER_LIVE_TESTS=1 pytest
```

These tests require network connectivity and can fail transiently if the
external services change behavior. They are not run in CI by default.

#### Deterministic protocol tests (mock servers)

The protocol clients also have hermetic mock-server tests that DO run in CI:

- **WHOIS** (`whois/client.rs` tests): a local `tokio::net::TcpListener`
  fixture serves canned responses through the full client path (referrals,
  cycles, timeouts).
- **RDAP** (`rdap/client.rs` tests): `wiremock` scripts 404/429/malformed
  responses against `query_rdap_with_retry` directly — no IANA bootstrap, so
  the global bootstrap cache stays untouched.
- **Formatters** (`seer-core/tests/format_snapshots.rs`): `insta` snapshots of
  human + markdown output. After an intentional formatting change, run the
  test, inspect the generated `.snap.new` files, and rename them over the
  `.snap` baselines (or use `cargo insta review`).

The SSRF guards deliberately refuse loopback, so the clients expose
`#[cfg(test)]`-only seams (`allowing_private_hosts`/`with_port` on
`WhoisClient`, `allowing_reserved_for_tests` on `RdapClient`). These do not
exist in release builds — never weaken the production validation path to make
a test reachable; thread the test flag instead.

### Running the Applications

```bash
./target/release/seer lookup example.com   # CLI command mode
./target/release/seer                      # REPL
./target/release/seer tui example.com      # TUI
seer-api                                   # REST API on http://127.0.0.1:8000
seer-mcp                                   # MCP server on stdio
```

---

## Rules and Conventions

- **Keep core pure.** Normalization, validation, network I/O and parsing live
  in `seer-core`; `seer-cli`, `seer-py` and `seer-api` parse input, call core
  and present results.
- **Errors.** Return `seer_core::Result<T>` with a `SeerError` variant that
  carries context (`SeerError::WhoisError(format!("… {server}: {e}"))`).
  Anything shown to an external consumer (REST response, MCP result, Python
  exception) uses `SeerError::sanitized_message()`; log the full `Display`
  text instead.
- **No `unwrap()` in library code** (`clippy::unwrap_used` is a workspace
  lint; `clippy.toml` allows it in tests). `expect("…")` is reserved for true
  invariants such as compiled regex literals.
- **Timeouts on every network operation.** Defaults: WHOIS 15s, RDAP 15s (5s
  connect), DNS 5s (hickory `attempts = 2`), HTTP/SSL 10s — all tunable via
  the config file. New tunables go through `SeerConfig`, not a new env var or
  a hardcoded const.
- **Never weaken the SSRF guards.** Outbound hosts go through
  `net::resolve_public_host` / `net::validate_http_url`, redirects are
  followed manually with per-hop validation, and vetted addresses are pinned
  against DNS rebinding (`http.rs`, `webhook.rs`, RDAP client).
- **Retry boundary.** WHOIS and RDAP retry through `retry.rs`; `dns/`,
  `status/`, `ssl.rs` and `http.rs` are single-attempt by design — don't add
  retry loops there.
- **Bounded resources.** WHOIS responses cap at 1 MB and RDAP at 10 MB, HTTP
  bodies stream under a size cap, bulk concurrency defaults to 10 (max 50),
  and propagation queries its 30 servers concurrently.
- **Async hygiene.** Never block inside async code (`tokio::time::sleep`,
  `spawn_blocking` for file I/O). seer-py shares one process-wide Tokio
  runtime; never build a runtime per call.
- **Own types in public APIs.** Convert hickory/reqwest/x509 types into
  seer-core structs before returning them.
- **Document public APIs** with `///` and keep each module's `//!` overview
  current.
- **No hacks or workarounds.** Fix the root cause; if something can only be
  done fragilely, stop and raise it.
- **Naming:** standard Rust (PascalCase types, snake_case functions and
  modules, SCREAMING_SNAKE_CASE constants) and PEP 8 for Python.

### Domain Normalization

Normalize every domain before processing, in core — never in a presentation
layer. `validation::normalize_domain` strips the scheme and any path,
lowercases, converts IDNs to Punycode, validates the format and drops a
leading `www.` (only when a registrable name remains — `www.com` is kept
whole), which is right for registration-level operations (WHOIS, RDAP,
availability, history/watchlist keys). Anything about one specific DNS name
or host — DNS record queries (`dig`, propagation, follow, compare), per-host
probes (`ssl`, `status`, `headers`, `takeover`, subdomain classification) —
must use `validation::normalize_host`, which is identical but keeps `www.`
(`www` usually has its own CNAME and can serve a different site/cert).

### Lazy Statics

Process-wide caches, clients and compiled regexes are `std::sync::LazyLock`
statics (use `OnceLock` when a call site supplies the initializer):

```rust
use std::sync::LazyLock;

// lookup.rs — built on first use, shared by every SmartLookup
static LOOKUP_CACHE: LazyLock<TtlCache<String, LookupResult>> =
    LazyLock::new(|| TtlCache::new(LOOKUP_CACHE_TTL));

static IPV4_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").expect("IPV4_RE is a valid regex"));
```

### Adding a Capability End to End

A new lookup usually touches every surface:

1. **seer-core**: the logic and a `Serialize` result type, re-exported from
   `lib.rs`; a `format_*` method on `OutputFormatter` implemented for all four
   formats, with human + markdown `insta` snapshots.
2. **seer-cli**: the clap subcommand in `main.rs`, the REPL command (+
   completer entry), and a TUI lens where it fits.
3. **seer-py**: a binding in `src/lib.rs`, re-exported from
   `python/seer/__init__.py`.
4. **seer-api**: a router endpoint that dispatches through `run_seer`
   (`_run.py`), maps failures with `errors.http_error` and declares its rate
   limit, plus an MCP tool in `mcp/server.py`. Raise seer-api's
   `domain-seer>=` floor to the release that adds the binding.
5. **Docs**: README (CLI usage, Python list), seer-api/README (endpoint and
   tool tables), and a CHANGELOG `[Unreleased]` entry.

---

## Working with Git

### Branch Strategy

- `main`: Production-ready code
- Feature branches: `feature/description` or `claude/description-{sessionId}`
- Always create pull requests for review

### Commit Conventions

Follow conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`,
`perf:`, `build:`, `ci:`, `chore:`).

### Pre-commit Checklist

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check                          # when dependencies change
cd seer-py && maturin develop && pytest   # when the bindings change
cd seer-api && pytest                     # when the API changes
```

CI runs fmt, clippy on all targets (plus `seer-core --features otel`), tests
on 3 OSes, an MSRV `cargo check --locked`, informational llvm-cov coverage, a
cargo-deny supply-chain gate (`deny` job via EmbarkStudios/cargo-deny-action,
policy in root `deny.toml`: RUSTSEC advisories, explicit license allow-list,
wildcard-version ban, crates.io-only sources — it is the only advisory gate;
run locally with `cargo deny check`), AND a `python` job (ruff, maturin-builds
seer-py, installs seer-api, runs both pytest suites) — Python test failures
block merges just like Rust ones.

### Release Process

Releases are tag-driven; pushing a version tag is the entire entry point:

```bash
# 1. Bump version in Cargo.toml [workspace.package] and seer-api/pyproject.toml
#    (seer-py/pyproject.toml takes its version from the Cargo workspace via
#    dynamic = ["version"])
# 2. Sync the README's `seer-core = "x.y"` dependency snippet (Rust Library section)
# 3. Move CHANGELOG.md [Unreleased] entries into a new version section and add
#    its compare link at the bottom (cargo-dist uses that section verbatim as
#    the GitHub Release body, so keep it user-facing and accurate)
# 4. Commit, then:
git tag vX.Y.Z && git push --tags
```

What happens automatically:
1. `release.yml` (cargo-dist) builds `seer` binaries for 5 targets + shell/
   PowerShell installers, and creates the GitHub Release.
2. **Homebrew formula publish (automatic):** the `publish-homebrew-formula`
   job in `release.yml` pushes `Formula/seer.rb` to the
   `TheZacillac/homebrew-tap` repo using the `HOMEBREW_TAP_TOKEN` secret. This
   runs *inside* the release plan (not `publish.yml`), so the anti-recursion
   quirk below does not affect it. Install: `brew install TheZacillac/tap/seer`.
   The formula is named `seer` (not `seer-cli`) via `formula = "seer"` in
   `seer-cli/Cargo.toml`'s `[package.metadata.dist]`.
3. **Manual step — dispatch the publish workflow:** `gh workflow run
   publish.yml`. It does NOT fire automatically: dist creates the release
   with the workflow's `GITHUB_TOKEN`, and GitHub suppresses events from
   such actions (anti-recursion), so the `release: published` trigger never
   sees it. The dispatched run publishes seer-core then seer-cli to
   crates.io. (`publish.yml` currently publishes **only** to crates.io.)

**Homebrew (enabled 2026-07-04):** `installers` includes `"homebrew"`, with
`tap = "TheZacillac/homebrew-tap"` and `publish-jobs = ["homebrew"]` in
`dist-workspace.toml`. The tap repo is public and the `HOMEBREW_TAP_TOKEN` repo
secret is a fine-grained PAT with Contents:read/write scoped to the tap repo
only (`GITHUB_TOKEN` can't push cross-repo). If the tap push ever 403s, the PAT
has expired/been revoked — mint a new one and re-set the secret.

**Deferred publishers (tracked for later):** PyPI publishing is still disabled.
- *PyPI*: the `wheels`/`sdist`/`publish-pypi` jobs were removed from
  `publish.yml` (restore from git history to re-enable).

When PyPI is re-enabled: the bindings publish as **`domain-seer`** (the bare
name `seer` is taken by an unrelated project; the import name remains `seer`)
via PyPI Trusted Publishing (OIDC), no token secret. seer-api pins a
`domain-seer>=` floor in its pyproject. `importlib.metadata.version("domain-seer")`
in `seer-py/python/seer/__init__.py` keys off the distribution name.

`dist-workspace.toml` holds the cargo-dist config; after editing it, run
`dist generate` to regenerate `release.yml` (never hand-edit that file).

---

## Configuration

### Environment Variables

The API/runtime environment variables (`SEER_HOST`, `SEER_API_KEY`,
`SEER_RATE_LIMIT`, `SEER_RATE_LIMIT_STORAGE`, `SEER_MCP_ALLOWED_*`,
`SEER_DOMAIN_ALLOWLIST`, …) are documented in one table:
README.md → Configuration → Environment Variables. Add new ones there.

### User Config File

`seer-core/src/config.rs` loads `~/.seer/config.toml` at client construction
(missing file → defaults). `seer config --init` scaffolds it. Settings:
default output format, nameserver, per-protocol timeouts, bulk concurrency,
rate-limit delay — all clamped to safe, per-protocol ranges (concurrency
1–50; whois/rdap timeouts 1–300s; dns 1–60s; http 1–120s) — plus two tables:
`[watch]` with `webhook_url` (Option, default None; the `--webhook` CLI flag
overrides it) and `[tui]` with `theme` (default `"frappe"`; read through
`SeerConfig::tui_theme()`, which trims/lowercases and clamps anything that
isn't `"latte"` — including `"frappé"` and unknown names — to `"frappe"`).
When adding a tunable, prefer wiring it through `SeerConfig` over a new env
var or hardcoded const.

Past breaking changes (the 2026-04-20 deployment defaults, the 2026-05-27
propagation result shape) are recorded in CHANGELOG.md.

---

**Last Updated**: 2026-09-22
