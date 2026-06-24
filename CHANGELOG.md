# Changelog

All notable changes to Seer are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> Releases are tag-driven (see `CLAUDE.md` → Release Process). When cutting a
> release, move the `[Unreleased]` entries into a new version section. cargo-dist
> reads the matching section as the GitHub Release body.

## [Unreleased]

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

[Unreleased]: https://github.com/TheZacillac/seer/compare/v0.35.3...HEAD
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
