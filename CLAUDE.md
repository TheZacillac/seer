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
- Hickory-resolver (DNS resolution, incl. DoT/DoH)
- Rustls on aws-lc-rs (the only TLS/crypto stack — no OpenSSL, no ring)
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
├── lib.rs              # Module exports and re-exports; crate-internal static_regex! macro
├── error.rs            # Centralized error types (SeerError enum)
├── colors.rs           # Catppuccin color palette for terminal output
├── config.rs           # User config file (~/.seer/config.toml), clamped ranges; [watch]/[tui] tables
├── doctor.rs           # `seer doctor` self-diagnosis: 4 concurrent probes (config/DNS/WHOIS-43/RDAP-bootstrap)
├── lookup.rs           # Smart lookup (RDAP-first with WHOIS fallback, in-flight coalescing)
├── availability.rs     # Domain availability detection (RDAP 404 + DNS + patterns)
├── domain_info.rs      # Merged RDAP + WHOIS flat structure
├── retry.rs            # RetryPolicy/RetryExecutor: exponential backoff + jitter
├── cache.rs            # Generic capacity-bounded TtlCache (plain TTL expiry)
├── net.rs              # SSRF guards: resolve/validate public hosts (refuses loopback/private)
├── validation.rs       # Domain normalization, reserved-IP descriptions, SEER_DOMAIN_ALLOWLIST
├── psl.rs              # (private) Public Suffix List: registrable-domain boundary (example.co.uk)
├── dates.rs            # (private) shared "days until expiry" arithmetic
├── fsutil.rs           # (private) atomic owner-only saves + persisted_store! for the ~/.seer stores
├── ssl.rs              # SSL inspection: full presented chain + negotiated TLS version (single-attempt)
├── tls.rs              # (private) inspection-only rustls handshake + RFC 6125 host matching (ssl + status)
├── caa.rs              # CAA policy lookup + issuer comparison
├── posture.rs          # Email/DNS security posture: SPF/DMARC/MTA-STS/BIMI/DANE verdicts
├── headers.rs          # HTTP security-header + cookie audit, weighted 0-100 score -> A+-F grade
├── takeover.rs         # Subdomain takeover: provider CNAME match + HTTP body fingerprint confirmation
├── http.rs             # (private) SSRF-guarded HTTP GET (status/headers/takeover) + shared capped body reader
├── confusables.rs      # Typosquat/homoglyph look-alike generation + registration scoring
├── subdomains/         # Subdomain enumeration via CT logs: ordered source chain (crt.sh→certspotter) + per-source retry treating crt.sh 404/429/HTML-body as transient
├── diff.rs             # Side-by-side domain comparison
├── drift.rs            # Registration drift detection vs stored history snapshot
├── watchlist.rs        # Cert/registration expiry watchlist
├── webhook.rs          # SSRF-guarded JSON webhook POST (watch --webhook): pinned addrs, no redirects
├── history.rs          # Lookup history
├── logging.rs          # tracing setup (+ optional OTel via `otel` feature)
│
├── whois/              # WHOIS: TCP client w/ referral following, parsers/ fn table, servers.rs TLD tables
├── rdap/               # RDAP: HTTP client, IANA bootstrap (+bootstrap.rs), types
├── dns/                # DNS: resolver, records, propagation/, compare, follow, DNSSEC, delegation
├── status/             # Domain health: HTTP/SSL/expiration/DNS (single-attempt by design)
├── tld/                # TLD info (WHOIS server, RDAP endpoint, registry URL)
├── bulk/               # Concurrent bulk executor + domain-list parsing
└── output/             # OutputFormatter (macro-generated) + human/, markdown/, json, yaml, contact.rs
```

Each directory module's `mod.rs` opens with a `//!` overview (rendered on
docs.rs); there are no per-module README files.

#### Module Responsibilities

- **error.rs**: All error types in one place, uses thiserror
- **config.rs**: Loads `~/.seer/config.toml` (timeouts, concurrency, output format, nameserver, `[watch] webhook_url`, `[tui] theme`); values clamped to safe ranges; `seer config --init` scaffolds it
- **whois/**: WHOIS protocol, referral following (max depth: 3), IANA discovery fallback for unmapped TLDs (24h TTL cache). Registry parsers are a private static table in `parsers/mod.rs`: each module exposes `const TLDS` + `fn parse`, matched by second-level zone or TLD in table order, falling back to `WhoisResponse::parse_internal`. Field regexes are built from label lists (`field_patterns` / `line_field_patterns`), and the EDUCAUSE, NIC.it, SIDN and DENIC parsers read dates through the shared `whois::parse_date` (registry-specific formats such as JPRS's keep their own). `servers.rs` keeps its map as whitespace-separated data: `NIC_TLDS` (served at `whois.nic.<tld>`), `HOSTED_TLDS` (host → TLD rows) and `IDN_ALIASES` (U-labels resolved to their A-label's server). Keep the lists sorted — `server_tables_are_sorted` enforces it, and `server_tables_list_each_tld_once` guards duplicates
- **rdap/**: RDAP protocol, IANA bootstrap caching (24h TTL, stale-while-revalidate), domain/IP/ASN lookups, multi-candidate base-URL fallback, 429 Retry-After honoring
- **dns/**: DNS resolution (16 record types; default upstream Google Public DNS, or a custom UDP/`tls://`/`https://` nameserver), propagation checking (30 servers), compare, follow (live monitor), DNSSEC validation, NS delegation health (delegation.rs: parent NS set vs zone NS RRset + per-server RD=0 lameness probes, SSRF-vetted). A hostname nameserver's resolved upstreams are ordered **IPv4 first**: hickory's `lookup_ip` returns AAAA first, and the pool races only the first 2 servers under one per-query deadline, so on a host with an IPv6 route but no IPv6 transit an AAAA-first list timed out. Pinned-server configs share `single_server_config` / `google_or_pinned` / `fqdn` in `resolver.rs`
- **status/**: HTTP status, SSL certificates, domain expiration, DNS — deliberately single-attempt (see module docs: health probes must not retry-mask flakiness). The HTTP sub-check goes through `http::GuardedFetcher::send` and reads the body only for a 2xx `text/html` response; the TLS sub-check shares `tls::inspect` with `ssl.rs`
- **ssl.rs / tls.rs**: certificate inspection over rustls on aws-lc-rs, selected per config with `ClientConfig::builder_with_provider` (no process-global provider). The `InspectOnly` verifier accepts any chain — trust is reported, never enforced — and deliberately skips the handshake-signature check too: `inspect()` sends and trusts no application data, and no reported field (there is no fingerprint) depends on the peer holding the key, while rustls' strict signature path would refuse X.509 v1 leaves, unknown critical extensions and RSA < 2048 bits. It advertises the provider's schemes plus `EXTRA_SCHEMES` (Ed448, RSA/ECDSA SHA-1, SHA-1 last), so those certs are inspected and `ssl`'s weak-key warning fires. Only a server with no TLS 1.2+ version or no ECDHE+AEAD suite in common (CBC-only, static-RSA, DHE/DSS-only) fails, with an explanatory error. `ssl` reports the full chain as presented (leaf first) and the negotiated `TLSv1.3`/`TLSv1.2`. `tls::cert_matches_host` is the one RFC 6125 §6.4.4 hostname rule for both `ssl` and `status`: dNSName SANs decide alone, the CN counts only when there is no dNSName SAN, and an IP-literal host matches an equal iPAddress SAN
- **lookup.rs**: Smart lookup orchestration (RDAP → WHOIS fallback)
- **doctor.rs**: `seer doctor` diagnosis — 4 concurrent probes (config parse, DNS resolve, WHOIS port-43, RDAP bootstrap HTTPS), each stage-bounded (exchange legs 5s; the WHOIS probe's resolution stage runs through `net::resolve_public_host`, separately capped there, for parity with how production WHOIS connects); `overall` = worst check (malformed config = Warn since defaults still work; unreachable network = Fail); probe endpoints injectable via `#[cfg(test)]`-only seams. The RDAP-bootstrap probe fetches exactly like the real bootstrap load: `net::client_builder` (no redirects — a 3xx is FAIL) and `read_body_capped(.., Reject)` under `rdap::MAX_BOOTSTRAP_SIZE` (10 MB)
- **webhook.rs**: SSRF-guarded JSON webhook delivery for `seer watch --webhook` — resolved addresses vetted then pinned on the client (rebinding defense), redirects disabled, single-attempt, 10s timeout, non-2xx surfaces status only (never the body)
- **headers.rs**: `seer headers` — one non-intrusive GET graded across the security headers (HSTS, CSP, XFO, nosniff, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP), every `Set-Cookie`'s Secure/HttpOnly/SameSite flags, and version-disclosing banners. Weighted 0–100 score (weights sum to 100, asserted by a test) minus bounded cookie/disclosure penalties → A+–F. Verdicts reuse posture's Absent/Weak/Moderate/Strict/Present scale; CSP `frame-ancestors` counts as superseding `X-Frame-Options`. All grading is pure and unit-tested; only the fetch is async
- **takeover.rs**: `seer takeover` — the HTTP half of subdomain-takeover detection. `subdomains/classify.rs` already flags a dangling CNAME whose name stops resolving; this catches the commoner case where the provider still answers for a deprovisioned resource and only the response *body* says otherwise. 27 provider fingerprints in `takeover::PROVIDERS`, the single table `classify.rs` also matches against (via `match_provider`) — never add a second copy; `Vulnerable` requires a matched body marker and always records it as evidence, `Potential` is an unconfirmable dangling CNAME — never promote one to the other without evidence. Hosts whose CNAME matches no provider are never fetched, bounding the HTTP fan-out
- **http.rs** (private): SSRF-guarded HTTP GET shared by status/headers/takeover (`GuardedFetcher::send` returns the unread response, `read_body` applies the cap). Redirects are followed **manually** with `net::validate_http_url` re-run at every hop — reqwest's own redirect policy would skip the guard (redirect-SSRF bypass) — and validated addresses are pinned per hop against rebinding. `read_body_capped(.., Overflow::{Truncate, Reject})` is the one incremental body reader, also used by the RDAP and CT-log clients and doctor's bootstrap probe. Single-attempt, like status/ssl
- **bulk/**: `BulkExecutor` — bounded concurrent fan-out (`buffer_unordered`) paced by a slot-based rate limiter; per-row results never abort the batch; plain-text/CSV domain-list parsing. Build a batch with `execute_each(domains, |d| BulkOperation::…)` (or `execute`/`execute_streaming` on prepared operations); dispatch lives in the private `run_op`
- **cache.rs**: `TtlCache`, a plain capacity-bounded TTL cache (no stale-while-revalidate API). The RDAP bootstrap keeps its own stale-while-revalidate logic
- **fsutil.rs** (private): `persisted_store!(Type, "file", json|toml, "label")` generates `path`/`load`/`load_from_path`/`save`/`save_to_path` for the `~/.seer` stores (history, watchlist, subdomain baselines) with atomic owner-only writes and corrupt-file backup
- **retry.rs**: Shared retry framework — used by WHOIS/RDAP clients; dns/status/ssl intentionally don't (documented at their module level)
- **net.rs / validation.rs**: SSRF protection — all outbound hosts resolved and checked against reserved/private ranges (`net::is_reserved_ip`) before connect. `net::validate_http_url` is the single URL-shaped entry point (scheme, no credentials, ports 80/443 only, reserved-range check) shared by every HTTP fetch path — status, headers, takeover — so the policy cannot drift between them. `net::client_builder(timeout)` is the base reqwest builder for every leg and always disables automatic redirects; `net::url_host` unbrackets IPv6 hosts; `net::USER_AGENT` identifies seer's own probes
- **output/**: Human (colored), JSON, YAML, and Markdown formatters behind `get_formatter(OutputFormat)`. `with_report_methods!` in `output/mod.rs` is the single list of `OutputFormatter` methods — it generates the trait, the JSON/YAML impls and the forwarding impls — so a new report type is one row there plus human and markdown inherent methods (the forwarding impl is `#[deny(unconditional_recursion)]`, so a missing inherent method is a compile error, not a runtime stack overflow). `output/contact.rs` is the one contact view (`Contact`, `FlatContacts`, `ROLES`) every formatter renders registrant/admin/tech/billing through. Human label/value rows go through the private `Rows` writer and markdown through `Bullets`/`code_list`; both sanitize internally, so a row written through them cannot skip the terminal-injection / markdown escaping (bespoke layouts — tables, glyph lists — still sanitize by hand)
- **colors.rs**: Catppuccin Frappe color palette; the `CatppuccinExt` trait is generated from one `palette!` table
- **lib.rs**: `static_regex! { NAME = r"…"; }` declares every `LazyLock<Regex>` static in the crate (there are no hand-written ones)

### seer-cli/ (CLI Application)

```
seer-cli/src/
├── main.rs             # Entry point, clap commands, execute_command dispatch, exit_code(&Payload)
├── query.rs            # Query enum + Clients + run() -> Outcome: the single-shot pipeline shared by CLI and REPL
├── ops.rs              # Shared CLI/REPL/TUI pieces: BULK_OPS catalog, bulk bar/banner/CSV/summary, run_live_follow, watch/history bodies, lookup_source
├── payload.rs          # Payload enum (serde untagged) over every single-shot result: -q JSON, TUI raw view + `y` copy, REPL `copy`
├── utils.rs            # Shared helpers: table-driven bulk CSV export, raw-mode guard, follow key loop, bulk input readers
├── clipboard.rs        # OSC52 terminal clipboard copy
├── repl/               # Interactive REPL
│   ├── mod.rs          # REPL main loop, session state
│   ├── catalog.rs      # Command table: names, aliases, usage, help — drives completion/hints/help/usage errors
│   ├── commands.rs     # CommandContext + parse_query (REPL syntax -> Query)
│   └── completer.rs    # Tab completion + hints (reads catalog.rs)
├── display/            # Terminal progress UI
│   ├── spinner.rs      # Loading spinner for async operations
│   └── progress.rs     # Bulk progress bar that keeps tracing output from tearing it
└── tui/                # Full-screen ratatui TUI (`seer tui`)
    ├── mod.rs          # run(): terminal lifecycle + async select! loop
    ├── app.rs          # pure App state + update() (no ratatui imports)
    ├── action.rs       # FetchReq / Action / Msg / LensData / InputMode types
    ├── command.rs      # `:` command-line parser
    ├── event.rs        # normal-mode key → action mapping
    ├── data.rs         # async seer-core dispatch for lens fetches (mod.rs runs the follow/bulk streams)
    ├── filter.rs       # in-lens row filtering for the table lenses
    ├── line_editor.rs  # cursor-aware single-line editor for every input field
    ├── theme.rs        # Catppuccin Frappé + Latte palettes → ratatui Color (Theme::from_name)
    ├── render.rs       # frame rendering (shell + lens dispatch)
    ├── test_util.rs    # (cfg(test)) render_text / render_lines / render_buffer over a TestBackend
    ├── widgets/        # panel (panel::render → inner Rect), kv, gauge, dot, chips; or_dash, row_style
    ├── panes/          # interactive lens components (tld/dns/compare/diff/follow/bulk): state + handle_key
    └── lenses/         # static LENSES registry (lens(key, label, glyph, group) + .cmd()/.tabs()) + 18 renderers
```

**Key Points:**
- Uses Clap v4 with derive macros
- Defaults to REPL when no command provided
- Supports global `--format` flag (human/json/yaml/markdown) — must be placed before the subcommand
- **One single-shot pipeline.** Every single-shot command (lookup, whois,
  dig, status, ssl, … 23 in all) is a `query::Query`. The CLI's
  `execute_command` converts its clap subcommand into one, the REPL's
  `commands::parse_query` converts its own syntax, and both call
  `query::run(query, clients, config, spin)`, which returns an `Outcome`
  (`payload` + stderr `note`/`footnote`). The CLI renders it through
  `-q`/`--fields` or `payload::serialize`; the REPL prints it and keeps the
  payload for `copy`. Bulk, follow, watch, history and tui are handled
  outside the pipeline, over shared `ops.rs` helpers.
- **Check-style exit codes** all live in `main.rs` `exit_code(&Payload)`,
  pinned by a table test (a scripting contract): `status`, `avail`, `dnssec`,
  `compare`, `drift`, `takeover`, `subdomains --diff`, `doctor` and
  `delegation` exit 1 when their check fails. `cli_spinner()` lists the
  commands that show a spinner in one-shot mode.
- **Catalogs.** `ops::BULK_OPS` (name, description) drives the clap
  `OPERATION` help, the REPL completer and `bulk -h`, and the TUI's bulk
  presets; `repl/catalog.rs` drives REPL completion, hints, `help` and every
  usage error. Add a command or bulk op there, not in each consumer.
- `seer generate-key` mints a random API key (OsRng, 256-bit, URL-safe base64) for `SEER_API_KEY`
- `seer doctor` runs `seer_core::doctor` and exits 1 only when `overall` is
  FAIL (WARN exits 0 — documented in its help). Rendering lives in
  `pub(crate) render_doctor_report` (main.rs), reached through
  `payload::serialize` by both the CLI and the REPL, since no
  `OutputFormatter` method exists for doctor reports.
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
  run restart), and a list lens's selection is clamped whenever its data
  lands, so a shorter refresh never leaves it past the last row. Every core
  call honors the user config (clients via `*::from_config`), including the
  live follow (`DnsFollower::from_config` + `config.nameserver`). Two themes:
  Catppuccin Frappé (default) and Latte (light) — startup theme from
  `[tui] theme` in the config (`SeerConfig::tui_theme()` clamps unknown names
  to "frappe"), switchable live with `:theme <name>` through
  `App::set_theme_by_name`.

### seer-py/ (Python Bindings)

```
seer-py/
├── Cargo.toml          # Library config with crate-type = ["cdylib"]
├── pyproject.toml      # Maturin build config, ABI3 (Python 3.10+); version from the Cargo workspace
├── src/lib.rs          # PyO3 bindings, async→sync conversion, declarative #[pymodule] mod _seer
├── tests/              # pytest; conftest.py gates @pytest.mark.live tests on SEER_LIVE_TESTS=1
└── python/seer/        # Python wrapper package
    └── __init__.py     # Explicit re-exports + __all__; `rdap = rdap_auto` alias
```

**Key Points:**
- Single Tokio runtime via `OnceLock` (thread-safe singleton); `run_async`
  wraps every call in one `catch_unwind`
- All async Rust functions exposed synchronously to Python
- The 14 core clients are plain `LazyLock` statics (`SMART_LOOKUP`,
  `DNS_RESOLVER`, …, each `LazyLock::new(Type::new)`) that bindings name
  directly. `call_fn!` generates the single-argument bindings as
  `name(arg: T) => CORE_CALL;` rows (doc comments become `__doc__` — the
  `rdap_auto` row's doc is the docstring of both `seer.rdap` and
  `seer.rdap_auto`), and `bulk_fn!` the domain-only bulk bindings over one
  non-generic `execute_bulk`. `bulk_dig`/`bulk_propagation` stay hand-written
  to keep their validation order. A new binding is also added to the
  `#[pymodule_export]` list
- `#[pymodule_init]` installs the `pyo3_log` bridge at import, so `log` and
  `tracing` records reach Python `logging` (there is no init function to call)
- `nameserver_target(spec)` exposes `seer_core::dns::NameserverSpec::parse`
  (pure parsing) so seer-api's SSRF guard checks exactly the address the
  resolver would contact
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
    ├── _contract.py        # shared bulk limits/models, record-type + TLD validators, BULK/HEAVY rate limits
    ├── _env.py             # strict integer env-var parsing
    ├── _run.py             # run_seer: bounded dispatch pool + SEER_REQUEST_TIMEOUT deadline
    ├── errors.py           # http_error (exception → sanitized status) + as_http (await a core call under it)
    ├── limiting.py         # rate limiter + proxy-aware client-IP keying
    ├── middleware.py       # body-size cap, request logging + /metrics counters
    ├── ssrf.py             # SSRF guard for user-supplied connect targets (hosts; nameservers via seer.nameserver_target)
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
        └── server.py       # MCP server: the _TOOLS registry (30 tools) + dispatch + rate_limiter()
```

**Key Points:**
- Secure by default: binds `127.0.0.1`; startup hard-fails on a non-loopback
  `SEER_HOST` without `SEER_API_KEY`, and on more than one worker with the
  `memory://` rate-limit store (per-worker limiters would be bypassable)
- OpenAPI docs at `/docs` and `/redoc` (off unless `SEER_DOCS_ENABLED`)
- CORS configured via `SEER_CORS_ORIGINS` env var
- Every REST route declares its own rate limit; `SEER_RATE_LIMIT` governs only `POST /mcp`
- Bulk endpoints have limits (max 100 domains, max 50 concurrency), defined
  once in `_contract.py` and shared by REST and MCP
- Route handlers await core calls through `errors.as_http(call, message)`;
  SSRF guards run before it, so their 400s are not remapped
- **MCP tool registry.** Each tool is one `_TOOLS` entry in `mcp/server.py`:
  `_Tool(description, input_schema, handler, rate_limit)`, built from schema
  helpers (`_object`, `_string`, `_domains`, `_concurrency`) and handler
  factories (`_single`, `_scan`, `_bulk`). `tools/list`, dispatch and the
  per-tool limits all derive from it. `tools/list` is pinned by
  `tests/test_mcp_tool_snapshot.py` + `tests/fixtures/mcp_tools.json`;
  regenerate after an intentional change with
  `cd seer-api && python -m tests.test_mcp_tool_snapshot`. Tool results are
  compact JSON. `rate_limiter()` is the one moving-window limiter shared by
  the `/mcp` gate and the per-tool limits (it lives in the MCP module so the
  stdio server never builds slowapi's storage)
- Dependencies: plain `uvicorn` plus explicit `uvloop`/`httptools` (not the
  `[standard]` extra), FastAPI's default JSON response (no orjson), and
  `limits`/`starlette` declared because they are imported directly —
  `tests/test_declared_dependencies.py` fails on any undeclared import
  (first-party `seer` resolves via a fallback map, since editable installs
  don't record it). The dev extra needs `pytest>=8.4`, which fails — rather
  than skips — an async test with no plugin; there is no pytest-asyncio.
- Tests run against a `seer` stub when the extension isn't built
  (`tests/conftest.py`, marked `_IS_STUB`); `needs_ns_parser` skips only for
  the stub, so a compiled binding missing `nameserver_target` fails loudly
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

Building needs only a Rust toolchain and a C compiler (aws-lc-sys builds
through the `cc` crate). There is no OpenSSL anywhere in the tree, so no
`libssl-dev`/`pkg-config`, and the binaries and the Python extension link only
libc/libm/libgcc_s on Linux.

#### Build profiles

- **`[profile.release]`** (`cargo install --path seer-cli`, `cargo build
  --release`, and maturin's seer-py builds — a crates.io `cargo install
  seer-cli` ignores workspace profiles and uses Cargo's defaults): `opt-level = "s"`, fat LTO, `codegen-units = 1`,
  `strip = "symbols"`. Seer is network-bound, so size-optimizing costs nothing
  noticeable. Unwinding stays **on**: PyO3 relies on `catch_unwind` to turn a
  Rust panic into a Python exception.
- **`[profile.dist]`** (cargo-dist release artifacts): inherits release but
  turns LTO off (`codegen-units = 16`) — LTO intermediate objects
  deterministically tripped Windows Defender on GitHub's windows runners — and
  sets `panic = "abort"` (−21% on the shipped binary). cargo-dist builds the
  whole workspace, so seer-py is compiled with abort too, but only the CLI is
  shipped; the Python extension users get comes from maturin with
  `[profile.release]`, which unwinds. Never move abort into
  `[profile.release]`. Abort skips `Drop`, so seer-cli's `main()` first
  installs `utils::install_raw_mode_panic_hook()` (disables raw mode, then
  chains to the previous hook) to keep a panic during `follow` from leaving
  the terminal raw; the TUI's own hook chains on top. A panic in a spawned
  task ends the process in shipped builds.
- **`cli` feature (seer-core, default on):** gates the CLI-only layer —
  `colors`, `doctor`, `drift`, `fsutil`, `history`, `logging`, `output`,
  `watchlist`, `webhook`, `subdomains::baseline` — and its deps
  (`tracing-subscriber`, `tracing-appender`, `colored`). The workspace
  `seer-core` dependency sets `default-features = false`; seer-cli re-enables
  `cli`, seer-py doesn't (10 fewer crates in its tree, −1.6% `.so`, ~12% faster cold
  release build).
  `otel` implies `cli`. Keep the gated set closed: an ungated module must not
  use a gated one (CI clippy runs `-p seer-core --no-default-features`).
- seer-py sets `test = false`/`doctest = false` (its tests are pytest), so
  `cargo test` never compiles PyO3.
- One TLS/crypto stack: reqwest, hickory (DNSSEC/DoT/DoH) and `tls.rs` all use
  rustls on aws-lc-rs. Every rustls config names its provider explicitly;
  don't add a dependency that pulls in ring, native-tls or OpenSSL.

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
example.com, iana.org, etc.) are marked `#[ignore]` in Rust,
`@pytest.mark.live` in seer-py (gated in `tests/conftest.py`) and with a
`skipif` on `SEER_LIVE_TESTS` for seer-api's single live test. They are
opt-in so `cargo test` and `pytest` stay hermetic by default:

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
- **DNS** (`dns/test_support.rs`): one loopback UDP server loop
  (`spawn_mock_dns_fn`, scripted per query with `MockReply`, or the canned
  `MockMode::Zone`) behind every resolver, follow, compare, DNSSEC,
  delegation, posture and status test; `mock_dns_resolver[_default]` wires a
  resolver to it.
- **TLS** (`tls::test_support`): loopback rustls servers with throwaway
  P-256 certificates (valid until 2126) for the inspection handshake, chain
  order, TLS 1.2/1.3 and hostname-rule tests, plus legacy leaves
  (`V1_LEAF`, `CRITICAL_EXT_LEAF`, `RSA_1024_LEAF`; the openssl commands that
  made them sit beside them). aws-lc-rs can't sign with RSA < 2048, so
  `RSA_1024_LEAF` is served via `serve_once_signing_with` under the P-256 key.
- **Formatters** (`seer-core/tests/format_snapshots.rs`): `insta` snapshots of
  every human + markdown formatter path (plus JSON/YAML lookup), one
  `snapshot_tests!` row per snapshot — the row's fn name is the `.snap` name.
  After an intentional formatting change, run the test, inspect the generated
  `.snap.new` files, and rename them over the `.snap` baselines (or use
  `cargo insta review`).
- **Bulk CSV** (`seer-cli/src/utils.rs` `csv_golden`): byte-exact header,
  populated and failure rows for every bulk operation.
- **MCP surface** (`seer-api/tests/test_mcp_tool_snapshot.py`): `tools/list`
  and per-tool limits against `tests/fixtures/mcp_tools.json`.

The SSRF guards deliberately refuse loopback, so the clients expose
`#[cfg(test)]`-only seams (`allowing_private_hosts`/`with_port` on
`WhoisClient` and `DnsResolver`, `with_default_nameserver` on `DnsResolver`,
`allowing_private_hosts` on `GuardedFetcher` and `WebhookClient`,
`allowing_reserved_for_tests` on `RdapClient`). These do not exist in release
builds — never weaken the production validation path to make a test
reachable; thread the test flag instead.

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
  `net::resolve_public_host` / `net::validate_http_url`, reqwest clients start
  from `net::client_builder` (automatic redirects off), redirects are
  followed manually with per-hop validation, and vetted addresses are pinned
  against DNS rebinding (`http.rs`, `webhook.rs`, RDAP client, `tls.rs`).
- **Retry boundary.** WHOIS and RDAP retry through `retry.rs`; `dns/`,
  `status/`, `ssl.rs`/`tls.rs` and `http.rs` are single-attempt by design —
  don't add retry loops there.
- **Bounded resources.** WHOIS responses cap at 1 MB and RDAP at 10 MB, HTTP
  bodies stream under a size cap (`http::read_body_capped`), bulk concurrency
  defaults to 10 (max 50), and propagation queries its 30 servers
  concurrently.
- **One copy of every table.** Provider fingerprints (`takeover::PROVIDERS`),
  formatter methods (`with_report_methods!`), bulk ops (`ops::BULK_OPS`), REPL
  commands (`repl/catalog.rs`), TUI lenses (`LENSES`), MCP tools (`_TOOLS`)
  and the nameserver-spec parser (`NameserverSpec::parse`, exposed to Python)
  each live in one place. Extend the table; never fork a copy — hand-synced
  copies are how `subdomains --classify` and the API's nameserver SSRF check
  drifted out of step with `takeover` and the core parser.
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

Process-wide caches and clients are `std::sync::LazyLock` statics (use
`OnceLock` when a call site supplies the initializer); compiled regexes are
declared through the crate's `static_regex!` macro, which expands to the same
`LazyLock<Regex>`:

```rust
use std::sync::LazyLock;

// lookup.rs — built on first use, shared by every SmartLookup
static LOOKUP_CACHE: LazyLock<TtlCache<String, LookupResult>> =
    LazyLock::new(|| TtlCache::new(LOOKUP_CACHE_TTL));

static_regex! {
    IPV4_RE = r"\b(?:\d{1,3}\.){3}\d{1,3}\b";
}
```

### Adding a Capability End to End

A new lookup usually touches every surface:

1. **seer-core**: the logic and a `Serialize` result type, re-exported from
   `lib.rs`, with a `from_config` constructor if it is a client; one
   `format_*` row in `with_report_methods!` plus the human and markdown
   inherent methods, with `snapshot_tests!` rows for both.
2. **seer-cli**: a `Query` variant and its `query::run` arm (plus a `Payload`
   variant), the clap subcommand in `main.rs` (and an `exit_code` rule if it
   is check-style), the REPL `parse_query` arm and `repl/catalog.rs` row, and
   a TUI lens where it fits.
3. **seer-py**: a binding in `src/lib.rs` (a `call_fn!` row when it is one
   core call) added to the `#[pymodule_export]` list, re-exported from
   `python/seer/__init__.py` and its `__all__`.
4. **seer-api**: a router endpoint that dispatches through `run_seer`
   (`_run.py`), awaits it with `errors.as_http` and declares its rate limit,
   plus a `_TOOLS` entry in `mcp/server.py` (then regenerate the tool
   snapshot). Raise seer-api's `domain-seer>=` floor to the release that adds
   the binding.
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

CI runs fmt, clippy on all targets (plus `seer-core --features otel` and
`seer-core --no-default-features`), tests
on 3 OSes, an MSRV `cargo check --locked`, informational llvm-cov coverage, a
cargo-deny supply-chain gate (`deny` job via EmbarkStudios/cargo-deny-action,
policy in root `deny.toml`: RUSTSEC advisories, explicit license allow-list,
wildcard-version ban, crates.io-only sources — it is the only advisory gate;
run locally with `cargo deny check`), AND a `python` job (ruff, maturin-builds
seer-py with the dev profile, installs seer-api, runs both pytest suites) —
Python test failures block merges just like Rust ones. CI compiles with
`CARGO_PROFILE_DEV_DEBUG=line-tables-only` (smaller, faster test builds).

### Release Process

Releases are tag-driven; pushing a version tag is the entire entry point:

```bash
# 1. Bump version in Cargo.toml [workspace.package], the seer-core version in
#    [workspace.dependencies], and seer-api/pyproject.toml
#    (seer-py/pyproject.toml takes its version from the Cargo workspace via
#    dynamic = ["version"]). Also resolve the PENDING note on seer-api's
#    `domain-seer>=` floor (it must reach the first release with
#    `seer.nameserver_target`, i.e. the one after 0.48.0).
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
