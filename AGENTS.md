# AGENTS.md — Seer

Seer is a domain-name utility in Rust with Python bindings: WHOIS, RDAP, DNS
(dig, trace, propagation, DNSSEC, delegation), SSL, HTTP status/headers,
email posture, subdomain takeover and more, exposed as a CLI (commands, REPL,
TUI), a Python library, a FastAPI REST API and an MCP server.

This file holds the rules and the non-obvious parts. **How a module works
lives in its `//!` overview** (every `mod.rs` and major file has one) — read
that before changing a module, and keep it current when you do.

---

## Layout

```
seer/
├── seer-core/   # ALL business logic (Rust library)
├── seer-cli/    # `seer` binary: clap commands, REPL, ratatui TUI
├── seer-py/     # PyO3 bindings → Python package `seer` (dist name domain-seer)
└── seer-api/    # FastAPI REST + MCP server (Python), built on seer-py
```

```
seer-cli ──┐
           ├──> seer-core
seer-py ───┘
seer-api ──> seer-py ──> seer-core
```

**Keep core pure.** Normalization, validation, network I/O and parsing live
in `seer-core`. The other three parse input, call core and present results.

### seer-core/src — where things are

| Area | Files |
|------|-------|
| Registration | `lookup.rs` (RDAP-first, WHOIS fallback), `whois/` (client, `parsers/` table, `servers.rs` TLD map), `rdap/` (client, IANA bootstrap), `availability.rs`, `domain_info.rs`, `tld/` |
| DNS | `dns/` — `resolver.rs` (`resolve()`, the record-list API everything else uses), `query.rs` + `transport.rs` (`query()`, dig's raw view), `trace.rs`, `propagation/`, `compare`, `follow`, DNSSEC, `delegation.rs` |
| Probes | `ssl.rs` + `tls.rs` (inspection-only rustls), `status/`, `headers.rs`, `http.rs` (SSRF-guarded GET), `posture.rs` (SPF/DMARC/MTA-STS/BIMI/DANE), `caa.rs`, `takeover.rs`, `subdomains/` (CT logs), `confusables.rs` |
| Safety | `net.rs` (SSRF guards, `ipv4_first`, `connect_any`, `client_builder`), `validation.rs` (normalization), `psl.rs` |
| Infra | `error.rs`, `config.rs`, `retry.rs`, `cache.rs`, `bulk/`, `logging.rs`, `fsutil.rs` (`~/.seer` stores), `doctor.rs`, `webhook.rs` |
| CLI-only | `output/` (formatters), `colors.rs`, `history.rs`, `watchlist.rs`, `drift.rs`, `diff.rs` |

### seer-cli/src

- `main.rs` — clap commands, `exit_code(&Payload)` (all check-style exit codes).
- `query.rs` — `Query` enum + `query::run()`: the **one** single-shot pipeline
  for the CLI, REPL and TUI. `payload.rs` is the serializable result enum.
- `dig_args.rs` / `dns_args.rs` — the one dig and compare/follow grammars.
- `bulk.rs`, `manage.rs` (watch/history/config), `ops.rs` (shared pieces,
  `BULK_OPS`, `STORE_LOCK`), `utils.rs`.
- `repl/` — `catalog.rs` is the command table driving completion, hints,
  help and usage errors.
- `tui/` — `app.rs` is pure state + `update()` (no I/O, no ratatui);
  `mod.rs` owns the event loop and I/O; `lenses/` holds the `LENSES`
  registry + renderers; `panes/` the interactive lens components.

### seer-py and seer-api

- `seer-py/src/lib.rs` — one process-wide Tokio runtime (`OnceLock`), clients
  as `LazyLock` statics, `call_fn!`/`bulk_fn!` row macros. Every new binding
  also goes in the `#[pymodule_export]` list and in
  `python/seer/__init__.py` + `__all__`.
- `seer-api/seer_api/` — `main.py` (auth, middleware, startup checks),
  `_run.py` (`run_seer` dispatch + deadline), `errors.py` (exception →
  status, `clean_message`), `ssrf.py`, `routers/`, `mcp/server.py` (the
  `_TOOLS` registry).

---

## Commands

```bash
cargo build --release                      # whole workspace
cargo install --path seer-cli              # `seer` onto PATH
cd seer-py && maturin develop --release    # Python bindings
cd seer-api && pip install -e '.[dev]'     # API + test deps

./target/release/seer lookup example.com   # one-shot; bare `seer` = REPL
./target/release/seer tui example.com
seer-api                                   # REST on 127.0.0.1:8000
seer-mcp                                   # MCP over stdio
```

Building needs only a Rust toolchain and a C compiler (aws-lc-sys). There is
no OpenSSL anywhere — no `libssl-dev`/`pkg-config`.

### Before committing (mirrors CI)

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p seer-core --no-default-features --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc -p seer-core --no-deps                          # docs changed
RUSTDOCFLAGS="-D warnings" cargo doc -p seer-core --no-deps --document-private-items
cargo deny check                                                                      # deps changed
ruff check seer-py/python seer-py/tests seer-api                                      # Python changed
cd seer-py && maturin develop && pytest                                               # bindings changed
cd seer-api && pytest                                                                 # API changed
```

CI also runs clippy with `--features otel`, the rustdoc gate with
`--no-default-features`, tests on Linux/macOS/Windows, an MSRV
`cargo check --locked` (Rust 1.89, set by rustyline 18's `File::lock`) and
informational coverage. Python test failures block merges like Rust ones.

---

## Testing

- Unit tests sit beside the code in `#[cfg(test)] mod tests`. **Every bug
  fix comes with a hermetic regression test.**
- Default runs are hermetic. Live-network tests are `#[ignore]` (Rust),
  `@pytest.mark.live` (seer-py) or skipped without `SEER_LIVE_TESTS`
  (seer-api): `cargo test --workspace -- --ignored`, `SEER_LIVE_TESTS=1 pytest`.
  They can fail transiently and are not in CI.
- Mock servers that do run in CI:
  - WHOIS: local `TcpListener` fixture (`whois/client.rs` tests).
  - RDAP: `wiremock` against `query_rdap_with_retry` (bypasses the global
    bootstrap cache).
  - DNS: `dns/test_support.rs` — `spawn_mock_dns_fn` scripted with
    `MockReply` (+ `_with_tcp` for truncation), `mock_dns_resolver[_default]`.
    A `query()` below the registrable domain also sends the wildcard probe
    (`seer-probe-<hex>.<parent>`), so handlers see one extra query.
  - TLS: `tls::test_support` loopback rustls servers and legacy leaves.
- **SSRF seams.** Guards refuse loopback, so clients expose
  `#[cfg(test)]`-only seams (`allowing_private_hosts`, `with_port`,
  `with_root_hints`, `with_unroutable`, …). Thread a test flag through one of
  these — never weaken the production path to reach a fixture.
- **Snapshots — regenerate after an intentional change:**
  - Formatters: `seer-core/tests/format_snapshots.rs` (`insta`, one
    `snapshot_tests!` row per snapshot). Run, inspect the `.snap.new`
    files, then `cargo insta review`.
  - Bulk CSV: `csv_golden` in `seer-cli/src/utils.rs` (byte-exact).
  - MCP `tools/list`: `cd seer-api && python -m tests.test_mcp_tool_snapshot`.
  - CLI exit codes: the table test beside `exit_code` (a scripting contract).
- seer-api tests run against a `seer` stub when the extension isn't built
  (`tests/conftest.py`). pytest ≥ 9.1.1 with **no pytest-asyncio**: an async
  test without a plugin fails rather than skips.

---

## Rules

### Security (never weaken)

- **SSRF.** Every outbound host goes through `net::resolve_public_host` or
  `net::validate_http_url` (the one URL policy: http/https, no credentials,
  ports 80/443, reserved ranges refused). Reqwest clients start from
  `net::client_builder` (redirects and proxies off). Redirects are followed
  manually with validation at every hop, and vetted addresses are **pinned**
  against DNS rebinding. Nameserver addresses learned from DNS data pass
  `delegation::partition_reserved`; a user's nameserver spec is vetted once
  in `DnsResolver::custom_upstream_config`. `dns::transport` never resolves
  a name.
- **Remote text is hostile.** Human output goes through `sanitize_line` (or
  the `Rows` writer), Markdown through `MdSafe`/`MdCode` (or `Bullets`), TUI
  widgets sanitize too. No remote value may span rows.
- **External errors** (REST, MCP, Python exceptions) use
  `SeerError::sanitized_message()`; log the full `Display` instead.

### Behavior

- **Retry boundary.** WHOIS and RDAP retry via `retry.rs`. `dns/`,
  `status/`, `ssl.rs`/`tls.rs`, `http.rs` are single-attempt on purpose —
  health probes must not retry-mask flakiness. Failing over to the next
  address/server is allowed; re-sending the same query is not.
- **Timeouts on every network operation**, bounded by one overall deadline
  where a walk could chain them (trace, delegation, `query()`). Defaults:
  WHOIS/RDAP 15s, DNS 5s, HTTP/SSL 10s, CT 30s.
- **Bounded resources.** WHOIS 1 MB, RDAP 10 MB, HTTP bodies via
  `http::read_body_capped`; bulk concurrency 10 (max 50).
- **IPv4 first** for every multi-address connect (`net::ipv4_first`) —
  hickory returns AAAA first, which timed out on hosts with an IPv6 route but
  no IPv6 transit.
- **New tunables go through `SeerConfig`** (`~/.seer/config.toml`, values
  clamped), not a new env var or hardcoded const.

### Normalization (always in core)

- `validation::normalize_domain` — registration-level ops (WHOIS, RDAP,
  availability, history/watchlist keys). Drops a leading `www.`.
- `validation::normalize_host` — per-host probes (ssl, status, headers,
  takeover, subdomain classification). Keeps `www.`.
- `dns::resolver::prepare_query` → `normalize_query_name` — DNS queries;
  the only path that accepts a leading `*.` wildcard label.

### One copy of every table

Extend the table; never fork a copy (hand-synced copies are how
`subdomains --classify` and the API's nameserver SSRF check drifted out of
step). The tables:

| What | Where |
|------|-------|
| Takeover provider fingerprints | `takeover::PROVIDERS` (also used by `subdomains/classify.rs`) |
| Formatter methods | `with_report_methods!` in `output/mod.rs` |
| Shared report / dig wording | `output/mod.rs`, `output::dig`, `output/diff_table.rs` |
| Contact rendering | `output/contact.rs` |
| Availability ladder | `availability::classify_fallback` |
| Record types / ANY fan-out | `RecordType::ALL`, `ANY_TYPES` |
| Root hints | `trace::ROOT_SERVERS` |
| WHOIS servers / parsers | `whois/servers.rs` (sorted, test-enforced), `whois/parsers/mod.rs` |
| Nameserver-spec parser | `NameserverSpec::parse` (exposed to Python for seer-api's SSRF check) |
| Bulk ops | `ops::BULK_OPS` |
| REPL commands | `repl/catalog.rs` |
| dig / compare / follow grammar | `dig_args.rs`, `dns_args.rs` |
| TUI lenses | `LENSES` |
| MCP tools | `_TOOLS` in `seer-api/seer_api/mcp/server.py` |
| Bulk / API limits | `seer-api/seer_api/_contract.py` |

### Code

- `seer_core::Result<T>` with a `SeerError` variant carrying context.
- **No `unwrap()` in library code** (workspace lint; allowed in tests).
  `expect("…")` only for true invariants such as regex literals.
- Process-wide state is `LazyLock` (`OnceLock` if the call site supplies
  the initializer); regexes are declared through `static_regex!`.
- **Async hygiene:** never block in async code (`spawn_blocking` for file
  I/O); seer-py shares one Tokio runtime — never build one per call.
- **Own types in public APIs:** convert hickory/reqwest/x509 types into
  seer-core structs before returning.
- Document public items with `///`. An intra-doc link must resolve in a
  non-test build — name `#[cfg(test)]` or other modules' private items in
  plain backticks instead.
- `seer-cli`'s `main` returns `ExitCode`; nothing calls `process::exit`.
- No hacks or workarounds: fix the root cause, or stop and raise it.

---

## Gotchas

- **`cli` feature.** seer-core's default `cli` feature gates the CLI-only
  modules (`output`, `colors`, `doctor`, `drift`, `fsutil`, `history`,
  `logging`, `watchlist`, `webhook`, `subdomains::baseline`). seer-py builds
  without it. An ungated module must never use a gated one — CI clippy with
  `--no-default-features` catches it.
- **One TLS stack:** rustls on aws-lc-rs, provider named explicitly in every
  config. Don't add a dependency that pulls in ring, native-tls or OpenSSL.
- **`tls::InspectOnly` accepts any chain and skips the handshake-signature
  check deliberately** — `ssl` reports trust, it doesn't enforce it, and
  verification would refuse the v1 / RSA<2048 certs `ssl` exists to flag.
  Not a bug; see `tls.rs`.
- **`panic = "abort"` lives only in `[profile.dist]`.** `[profile.release]`
  must keep unwinding: PyO3 relies on `catch_unwind`. Because dist skips
  `Drop`, `main()` installs `utils::install_raw_mode_panic_hook()` first.
  `[profile.dist]` also turns LTO off (it tripped Windows Defender).
- **`dig` vs `resolve()`.** `DnsResolver::query()` (dig) bypasses hickory's
  resolver so NXDOMAIN/NODATA/referrals keep their header and CNAME chain;
  everything else uses `resolve()`. NXDOMAIN/NODATA are `Ok` results there,
  and a referral is `referral_zone()`, never `is_nodata()`.
- **Exit codes are a contract.** Check-style commands (status, avail,
  dnssec, compare, drift, takeover, `subdomains --diff`, doctor, delegation)
  exit 1 on failure; dig, headers and posture don't. All of it lives in
  `exit_code` + its table test.
- **`--format` goes before the subcommand**; `--fields` implies `-q`;
  `+short` is a usage error with `-q`/`--fields`.
- **TUI:** every lens change goes through `App::goto_lens`; async results
  are dropped by a per-lens generation guard; `~/.seer` store edits hold
  `ops::STORE_LOCK`.
- **seer-api is secure by default:** binds loopback, hard-fails on a
  non-loopback `SEER_HOST` without `SEER_API_KEY` or on multiple workers with
  the `memory://` rate-limit store. Every REST route declares its own rate
  limit. `test_declared_dependencies.py` fails on any undeclared import.
- **seer-py errors** map to typed `seer.SeerError` subclasses; seer-api maps
  statuses from those classes — never by matching message text.
- Env vars are documented in one place: README → Configuration →
  Environment Variables. Add new ones there.

---

## Adding a capability end to end

1. **seer-core:** logic + `Serialize` result type, re-exported from
   `lib.rs` (`from_config` constructor if it's a client); a
   `with_report_methods!` row + human and markdown methods + `snapshot_tests!`
   rows.
2. **seer-cli:** `Query` variant + `query::run` arm + `Payload` variant, clap
   subcommand (and an `exit_code` row if check-style), REPL `parse_query` arm
   + `catalog.rs` row, a TUI lens where it fits.
3. **seer-py:** binding (a `call_fn!` row if it's one core call), the
   `#[pymodule_export]` list, `__init__.py` + `__all__`.
4. **seer-api:** router endpoint via `run_seer` + `errors.as_http` with a
   rate limit; a `_TOOLS` entry; regenerate the MCP snapshot; raise the
   `domain-seer>=` floor.
5. **Docs:** README (CLI usage, Python list), seer-api/README (endpoint and
   tool tables), CHANGELOG `[Unreleased]`.

---

## Git and releases

- Branch from `main` (`feature/…` or `claude/…`), open a PR. Conventional
  commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `perf:`,
  `build:`, `ci:`, `chore:`).
- **Release** (tag-driven):
  1. Bump `[workspace.package] version`, the `seer-core` version in
     `[workspace.dependencies]`, and `seer-api/pyproject.toml`
     (seer-py reads the workspace version). Raise seer-api's `domain-seer>=`
     floor if it needs a new binding.
  2. Sync the README's `seer-core = "x.y"` snippet.
  3. Move CHANGELOG `[Unreleased]` into a version section + compare link —
     cargo-dist uses that section verbatim as the GitHub Release body.
  4. Commit, `git tag vX.Y.Z && git push --tags`.
  5. **Then run `gh workflow run publish.yml` by hand** (crates.io). It never
     fires on its own: the release is created with `GITHUB_TOKEN`, and GitHub
     suppresses the follow-on event.
- `release.yml` (cargo-dist) builds 5 targets + installers and pushes the
  Homebrew formula to `TheZacillac/homebrew-tap` (`HOMEBREW_TAP_TOKEN`, a
  fine-grained PAT — a 403 there means it expired). Never hand-edit
  `release.yml`: edit `dist-workspace.toml`, then `dist generate`.
- **PyPI publishing is disabled** (jobs removed from `publish.yml`; restore
  from git history). When re-enabled it publishes `domain-seer` via Trusted
  Publishing; the import name stays `seer`.
- Past breaking changes are recorded in CHANGELOG.md.
