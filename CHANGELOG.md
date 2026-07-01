# Changelog

All notable changes to Seer are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> Releases are tag-driven (see `CLAUDE.md` → Release Process). When cutting a
> release, move the `[Unreleased]` entries into a new version section. cargo-dist
> reads the matching section as the GitHub Release body.

## [Unreleased]

## [0.37.1] - 2026-06-30

A bug-fix and hardening release resolving 13 defects surfaced by a full-codebase
audit ([#98]).

### Security
- **RDAP error sanitization gap.** When a lookup fell back to WHOIS, the RDAP
  error string was returned unsanitized, so an SSRF-guard rejection could leak
  an internal/reserved IP address. It is now redacted like every other path.
- **Status redirect SSRF oracle.** A blocked redirect target echoed the
  resolved internal IP in the error message, acting as an internal-DNS oracle.
  The detail is now logged at debug and a generic message is returned.
- **SSL hostname verification.** The certificate Common Name was consulted even
  when Subject Alternative Names were present, contrary to RFC 6125, which could
  report a certificate as matching the host when it did not. The CN is now used
  only when no SANs exist.

### Fixed
- **RDAP contact redaction.** Contacts whose only populated fields were redacted
  ("REDACTED FOR PRIVACY") were still displayed; the redaction filter now works.
- **RDAP response timeout.** A configured RDAP timeout above 15s was ignored
  while reading the response body; the configured value is now honored end to
  end.
- **DNS follow change counts.** A transient resolver error mid-run was counted
  as every record being removed and then re-added, inflating the change count.
  Errored iterations no longer produce phantom changes.
- **DNSSEC unsupported digest types.** A DS record using a digest type Seer
  cannot compute (e.g. GOST) marked an otherwise-valid signed zone as
  "misconfigured"; such records are now treated as "not evaluated".
- **Domain diff creation date.** The creation date now falls back to WHOIS when
  RDAP omits it, matching the expiration date's behavior.
- **Registry URL for brand TLDs.** TLDs that share a WHOIS host (e.g. `.datsun`)
  no longer derive an unrelated registry URL; they fall back to the IANA page.
- **WHOIS organization parsing.** A bare `Organization:` field could capture the
  admin or tech contact's organization and mislabel it as the registrant's; the
  patterns are now line-anchored.
- **Subdomain enumeration.** Underscore service labels (e.g. `_acme-challenge`,
  `_dmarc`) present in Certificate Transparency logs were silently dropped and
  are now kept.
- **WHOIS connect retries.** Transient connect failures such as "network
  unreachable" / "no route to host" were not retried; they now use the
  retryable error path so the configured retry policy applies.
- **TUI Follow lens.** Failed DNS checks were rendered as healthy; they now show
  as an error row.

## [0.37.0] - 2026-06-30

### Added
- **`seer_core::MAX_FOLLOW_INTERVAL_SECS` / `MAX_FOLLOW_ITERATIONS`** are now
  public, so front-ends can clamp follow interval/count to the same range
  `FollowConfig::new` enforces.

### Fixed
- **`.edu` availability inversion.** The EDUCAUSE WHOIS parser stamped every
  response with `registrar = "EDUCAUSE"`, including "No match" (unregistered)
  bodies — which made `is_available()` short-circuit to "registered" and also
  bypassed the thin-response availability fallback. The registrar is now set
  only when a real record is present, so unregistered `.edu` domains report as
  available again.
- **RDAP multi-candidate 404 loss.** When an earlier candidate URL returned a
  definitive 404 but a later one failed differently (timeout/5xx), the
  authoritative not-found signal was discarded, misreporting an available
  domain as inconclusive. The 404 is now preserved across candidates.
- **DNS propagation: `SRV` against a bare domain** deterministically failed on
  every server and was rendered as a network-wide outage. It is now rejected up
  front with a clear input error.
- **Watchlist file I/O** ran synchronously on the async runtime in the CLI,
  REPL, and TUI; it now runs on a blocking thread, matching the history paths.
- **TUI Follow lens** clamped interval/count only on the low end, so an
  over-range value silently no-op'd the run. Both are now clamped to the valid
  range.
- **DNS resolver timeout.** The primary system-resolver lookup had no timeout;
  a black-holed host could hang a worker thread. It is now bounded, falling
  through to the (already bounded) fallback resolver.
- **`.jp` WHOIS** could capture a bracket label into a nameserver value in the
  English-format fallback; it now extracts only the hostname.
- **`.de` WHOIS** mislabeled `Status: failed` (a nameserver-delegation failure)
  as the unrelated EPP `redemptionPeriod`; it now reads
  `failed (nameserver check failed)`.
- **Markdown diff** rendered multi-item lists with mangled separators (backticks
  turned into apostrophes); each item is now sanitized individually.
- **`--format json|yaml` on bad record types.** `dig`/`prop`/`follow`/`compare`
  printed a raw error instead of the structured `{"error": ...}` payload; they
  now honor the requested format.
- **`compare` argument order.** The defaulted `record_type` positional preceded
  the required nameservers, which panicked clap in debug builds and parsed
  ambiguously. Usage is now
  `seer compare <domain> <server_a> <server_b> [record_type]`.
- **TUI terminal restore.** If terminal setup failed after entering raw mode,
  the shell was left wedged in raw mode; setup now restores terminal state on
  error.

## [0.36.0] - 2026-06-27

### Added
- **TUI Bulk lens: live streaming results.** A new `execute_streaming` path in
  `seer-core` streams each `BulkResult` to the UI the moment it completes, so the
  progress gauge and results table fill in row-by-row during a run instead of
  snapping from 0% to 100% only when the whole batch finished.
- **TUI Bulk lens: inspect individual results.** Move the selection with `j`/`k`
  (or the arrow keys) and press `↵`/`v` to open a detail panel showing the
  selected row's status, duration, error, and a pretty-printed dump of the
  returned data.
- **TUI Bulk lens: cancel a run.** Press `x` to abort an in-flight batch,
  mirroring the Follow lens's stop control.
- **TUI Bulk lens: ok/failed summary** in the status line, plus four more op
  presets — `whois`, `rdap`, `ssl`, and `prop`.
- **TUI TLD lens: full catalog browser.** The TLD lens previously cycled a
  hardcoded list of 7 TLDs with `h`/`l`. It is now a live-filterable, scrollable
  browser over the entire ~1,400-entry TLD catalog: `/` (or `f`) edits a
  substring filter that narrows the list as you type, `j`/`k`/arrows move,
  `g`/`G` jump to top/bottom, and `↵`/`l` loads the selected TLD's registry
  detail (WHOIS server, RDAP URL, registry URL, type). New
  `seer_core::all_tlds()` exposes the catalog (WHOIS server map ∪ RDAP-only
  TLDs).

## [0.35.6] - 2026-06-26

### Fixed
- **TUI: selectable list lenses now scroll.** Propagation, Subdomains, History,
  Watchlist, and DNS-records rendered plain non-scrolling tables, so a selection
  moved past the viewport edge became invisible with no way to bring it back
  (worst on Propagation's ~30 resolvers and Subdomains' often-hundreds of rows).
  They now render statefully and keep the selected row in view; the Bulk results
  table pins to the newest row as results stream in. ([#94])
- **TUI: pane-driven lenses render in raw mode.** Toggling `r` (raw output) on
  the Follow, Diff, or Bulk lens no longer drops them to the generic
  "press / to look up a domain" idle hint — they have no raw serialization, so
  they now render their normal pane in every output format. ([#94])
- **TUI: RDAP IP tab** no longer fires an RDAP-IP lookup against a domain string
  when no address has been resolved yet; it shows the idle hint instead. ([#94])

## [0.35.5] - 2026-06-24

### Changed
- **MSRV is now Rust 1.88**, pinned in `Cargo.toml` and enforced by a CI job. The
  previous "1.70" claim was untested and incorrect (the floor comes from
  `x509-parser → time → time-macros`).
- Dependency updates, several major: ratatui 0.30, rustyline 17, rand 0.10,
  colored 3, toml 1.1, crossterm 0.29, dirs 6, x509-parser 0.18, and the
  OpenTelemetry stack (opentelemetry 0.32 / tracing-opentelemetry 0.33).
- CLI API-key generation (`seer generate-key`) now draws OS entropy via
  `getrandom` directly (the correct CSPRNG primitive); `seer-cli` no longer
  depends on `rand`.

### Internal
- CI now compiles the optional `otel` feature (`cargo check --features otel`),
  which was previously never built, and Dependabot groups the OpenTelemetry
  crates and leaves the MSRV toolchain pin alone.

## [0.35.4] - 2026-06-24

### Added
- `CHANGELOG.md` — backfilled release history in Keep a Changelog format, wired
  into the release process so future releases stay documented.
- Dependabot configuration covering the cargo (workspace), github-actions, pip
  (`seer-api`), and uv (`seer-py`) ecosystems, grouping minor/patch updates per
  ecosystem to reduce PR noise.
- CI `Coverage` job (cargo-llvm-cov) that prints a coverage summary and uploads
  an HTML report artifact. Informational — it does not gate merges.

## [0.35.3] - 2026-06-24

### Fixed
- Resolved whole-codebase code-review findings (1 High, 5 Medium, ~20 Low). The
  High unified the availability-fallback ladder across the smart-lookup hot path
  and the `avail` path, so a registry refusal or rate-limit can no longer be
  misclassified as "available" or "registered". ([#63])

## [0.35.2] - 2026-06-23

### Fixed
- Resolved all 17 open adversarial-review issues (#45–#61), including a critical
  availability inversion where RDAP-failure paths could report a domain as
  *available, high confidence*. Also hardened WHOIS/RDAP date-order inference,
  control-character sanitization, YAML quoting, and MCP-over-HTTP dispatch and
  rate-limiting. ([#62])
- Subdomain enumeration now falls back from crt.sh to certspotter and paginates
  certspotter results instead of truncating to the first page. ([#43])

### Security
- Upgraded PyO3 to 0.29 and removed the RUSTSEC audit ignores. ([#44])

## [0.35.1] - 2026-06-22

### Changed
- Deferred Homebrew and PyPI publishing; releases publish to crates.io only for
  now. Dependency updates.

## [0.35.0] - 2026-06-18

### Fixed
- MCP: de-duplicated the `Invalid input:` error prefix and corrected the
  `bulk_ssl` TLS-version claim.

## [0.34.0] - 2026-06-17

### Fixed
- DNS: repaired five `dig` edge-case bugs.
- Resolved issues found in an oppositional code review.

### Documentation
- Corrected the release flow — `publish.yml` requires a manual dispatch.

## [0.33.0] - 2026-06-12

### Added
- CLI: `seer generate-key` mints a random 256-bit URL-safe API key for
  `SEER_API_KEY`.
- API: MCP exposed over Streamable HTTP at `POST /mcp` (same tool registry as the
  stdio transport).
- Packaging: prebuilt CLI binaries and shell/PowerShell installers via cargo-dist;
  Python bindings published to PyPI as `domain-seer` (import name stays `seer`);
  seer-py wheels attached to GitHub releases.

### Changed
- CI now builds seer-py and runs both the seer-py and seer-api pytest suites.
  Added deterministic mock-server tests (WHOIS `TcpListener`, RDAP `wiremock`) and
  `insta` formatter snapshots.

### Fixed
- Release: disabled LTO in the dist profile to avoid a Windows Defender false
  positive.

## [0.32.0] - 2026-06-04

### Added
- TUI: Bulk lens accepts typed/pasted domains; always-visible domain-B field on
  the Diff lens; bracketed-paste support in text fields.

### Fixed
- TUI: the Follow pane now renders (was unreachable); lookups are recorded to
  history; Enter re-runs the Diff comparison when domain B is set.

## [0.31.0] - 2026-06-04

### Added
- Full-screen `seer tui` ratatui interface. All 16 lenses are wired with live
  data and full in-pane inputs, including the streaming Follow (live monitor) and
  Bulk (concurrent + CSV export) lenses, OSC52 clipboard copy, live TLD switching,
  and a Catppuccin Frappé theme. A per-lens/per-stream generation guard drops
  stale async results. Additive — the REPL and all subcommands are unchanged.

### Fixed
- CI: granted the audit job `checks: write` so the Security Audit passes on push
  to `main`.

## [0.30.0] - 2026-06-03

### Security
- Unified the reserved-IP/SSRF blocklist on `net::is_reserved_ip` across every
  outbound leg (RDAP, WHOIS, status, DNS).
- Disabled RDAP redirect-following and connect WHOIS only to validated IPs,
  closing the resolve-then-connect (DNS-rebinding) window.
- Create history/watchlist files owner-only (mode 0600) on Unix.
- Prevented a remote panic from Unicode lowercasing during WHOIS status parsing.

### Changed
- **Breaking:** renamed the DNSSEC verdict vocabulary (signed/unsigned) and
  stopped implying cryptographic *validation* — the report attests
  digest-consistency, not authentication.
- **Breaking:** stripped transport detail from sanitized error messages.

### Fixed
- Availability: never report a domain that carries registration data as
  available; report REGISTERED for RDAP-only TLDs when RDAP is unavailable.
- Output: escape table-cell pipes and MdSafe-wrap propagation fields; honor
  `--format` on error paths.

## [0.29.2] - 2026-06-02

### Fixed
- Availability: detect unregistered domains across many more registries via an
  authoritative RDAP-404 signal, a DNS-NXDOMAIN cross-check, and additional
  registry "not found" wordings.
- RDAP: bound 429 retries and honor `Retry-After` so a sticky rate limit falls
  through to WHOIS/DNS quickly instead of hanging.
- DNS: made propagation consensus tie-breaking deterministic.

## [0.29.0] - 2026-05-28

### Changed
- **Breaking:** consolidated NS-specific propagation data into a single
  `NameserverDetails` structure.

## Earlier releases (0.1.0 – 0.28.0, 2026-01 – 2026-05)

The project's foundational period, summarized — see the
[git tags](https://github.com/TheZacillac/seer/tags) for per-version detail:

- **Core engines:** WHOIS (TCP client with referral following), RDAP (IANA
  bootstrap, multi-candidate fallback), DNS (16 record types, propagation across
  ~30 servers, DNSSEC, compare/follow), and domain status/health (HTTP, SSL, CAA,
  expiry, subdomain enumeration via CT logs).
- **Interfaces:** the `seer` CLI with an interactive REPL, PyO3 Python bindings,
  the FastAPI REST API, and the MCP server (stdio + HTTP) — all thin layers over
  `seer-core`.
- **Features:** smart lookup (concurrent RDAP + WHOIS), merged domain info, bulk
  concurrent operations, watchlist, history, diff, a user config file
  (`~/.seer/config.toml`), and human/JSON/YAML/Markdown output formatters.

Two notable breaking changes landed in this period (see `CLAUDE.md` for details):

- **2026-04-20** — the API default bind moved from `0.0.0.0` to `127.0.0.1`, a
  public bind without `SEER_API_KEY` now hard-fails startup, multi-worker setups
  on a `memory://` rate-limit store are refused, and `/docs` is disabled by
  default (set `SEER_DOCS_ENABLED=true`).
- **2026-05-27** — the propagation result shape changed: `consensus_values` and
  `inconsistencies` became typed (`ConsensusValue` / `Inconsistency`) instead of
  pre-formatted strings.

[Unreleased]: https://github.com/TheZacillac/seer/compare/v0.37.1...HEAD
[0.37.1]: https://github.com/TheZacillac/seer/compare/v0.37.0...v0.37.1
[0.37.0]: https://github.com/TheZacillac/seer/compare/v0.36.0...v0.37.0
[0.36.0]: https://github.com/TheZacillac/seer/compare/v0.35.6...v0.36.0
[0.35.6]: https://github.com/TheZacillac/seer/compare/v0.35.5...v0.35.6
[0.35.5]: https://github.com/TheZacillac/seer/compare/v0.35.4...v0.35.5
[0.35.4]: https://github.com/TheZacillac/seer/compare/v0.35.3...v0.35.4
[0.35.3]: https://github.com/TheZacillac/seer/compare/v0.35.2...v0.35.3
[0.35.2]: https://github.com/TheZacillac/seer/compare/v0.35.1...v0.35.2
[0.35.1]: https://github.com/TheZacillac/seer/compare/v0.35.0...v0.35.1
[0.35.0]: https://github.com/TheZacillac/seer/compare/v0.34.0...v0.35.0
[0.34.0]: https://github.com/TheZacillac/seer/compare/v0.33.0...v0.34.0
[0.33.0]: https://github.com/TheZacillac/seer/compare/v0.32.0...v0.33.0
[0.32.0]: https://github.com/TheZacillac/seer/compare/v0.31.0...v0.32.0
[0.31.0]: https://github.com/TheZacillac/seer/compare/v0.30.0...v0.31.0
[0.30.0]: https://github.com/TheZacillac/seer/compare/v0.29.2...v0.30.0
[0.29.2]: https://github.com/TheZacillac/seer/compare/v0.29.0...v0.29.2
[0.29.0]: https://github.com/TheZacillac/seer/compare/v0.28.0...v0.29.0
[#43]: https://github.com/TheZacillac/seer/pull/43
[#44]: https://github.com/TheZacillac/seer/pull/44
[#62]: https://github.com/TheZacillac/seer/pull/62
[#63]: https://github.com/TheZacillac/seer/pull/63
[#94]: https://github.com/TheZacillac/seer/pull/94
[#98]: https://github.com/TheZacillac/seer/pull/98
