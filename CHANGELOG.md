# Changelog

All notable changes to Seer are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> Releases are tag-driven (see `CLAUDE.md` → Release Process). When cutting a
> release, move the `[Unreleased]` entries into a new version section. cargo-dist
> reads the matching section as the GitHub Release body.

## [Unreleased]

## [0.43.1] - 2026-07-12

A maintenance release: raises the minimum supported Rust version and
refreshes dependencies (rustyline 18, regex 1.13, rand 0.10.2,
getrandom 0.4).

### Changed
- MSRV raised from Rust 1.88 to 1.89: rustyline 18 (REPL line editor,
  dependabot bump) uses `std::fs::File::lock`, stabilized in 1.89.

## [0.43.0] - 2026-07-12

Adds a REPL `copy` command for grabbing results straight to the clipboard. ([#112])

### Added
- REPL `copy [markdown|json|yaml]` command — copies the last shown result
  (lookup/whois/rdap/dig/ssl/…) to the clipboard via OSC52, defaulting to
  Markdown. The payload/serialize/clipboard stack is now shared between the
  REPL and the TUI (which already had `y`).

## [0.42.0] - 2026-07-12

A defect-sweep release: 15 fixes from a full-codebase multi-agent review
(2026-07-11), spanning availability-verdict consistency, output completeness,
CLI/REPL parity, TUI lifecycle, and API rate-limit parity. ([#111])

### Fixed
- **Registrar detail + lifecycle fields now rendered** — the seven 0.38.0
  fields (registrar abuse email/phone, IANA ID, URL; days-until-expiration,
  domain age, expiry status, decoded status codes) were computed and
  serialized but never shown by the human/markdown formatters or the bulk
  `info` CSV; they were JSON/YAML-only. `seer info` now shows a
  "Registrar Detail" block, lifecycle lines, and decoded status codes in
  every format, and the info CSV gained the seven matching columns.
- **WHOIS-retired TLDs restored to the catalog** — the 0.40.1/0.41.0
  dead-server cleanups removed 12 TLDs (`apple`, `brussels`, `cymru`,
  `wales`, `vlaanderen`, `pharmacy`, `na`, `рус`, `lk` + IDN aliases, `mt`)
  from `WHOIS_SERVERS` without listing them as WHOIS-less, so they vanished
  from `all_tlds()` and the TUI's `:tld` command rejected them. A new
  `WHOIS_RETIRED_TLDS` constant keeps them discoverable.
- **Availability ladders agree on RDAP-404 confidence** — for a thin WHOIS
  response plus an authoritative registry RDAP 404, `seer lookup` reported
  `likely_available` (medium/whois_thin_response) while `seer check`
  reported `available` (high/rdap) for the same domain. Both now classify as
  high-confidence via RDAP.
- **"All rights reserved." no longer reads as a registry refusal** — the
  bare `reserved` substring in the refusal patterns matched the near-universal
  copyright footer, short-circuiting genuinely-unregistered domains to
  "inconclusive" before the DNS tie-breaker. Replaced with anchored
  reserved-status phrasings.
- **`seer bulk` exits non-zero on total failure** — a run where every domain
  failed (network down, malformed list) previously exited 0, giving scripted
  callers a false green. Zero successes over a non-empty batch now exits 1;
  partial failures still exit 0 (per-row status is in the output).
- **First retry now jittered** — `RetryPolicy::delay_for_attempt(0)` returned
  the fixed initial delay before the jitter branch, so concurrent callers
  hit by the same 429/outage all retried in lockstep (thundering herd on
  exactly the attempt where it matters most).
- **TLD-swap look-alikes survive the candidate cap** — confusable candidates
  were truncated after concatenation with tld-swaps generated last, so
  labels of ~16+ characters (`wellsfargobanking.com`) silently lost every
  TLD-swap candidate. Swaps now have a reserved budget.
- **REPL `follow` honors the configured nameserver** — unlike `dig` and the
  CLI's `seer follow`, the REPL's follow ignored `nameserver` from
  `~/.seer/config.toml` and always used the default resolver.
- **REPL errors honor `set output json|yaml|markdown`** — errors now render
  the same `{"error": ...}` / `**Error:**` shapes as the CLI instead of
  always printing ANSI-colored prose.
- **TUI: switching domains cancels a live Follow run** — the background DNS
  monitor for the old domain previously kept polling (invisibly, up to its
  full iteration budget) after a domain switch; only its UI updates were
  dropped. The switch now emits `StopFollow`.
- **TUI: Follow/Bulk spinners animate** — both lenses rendered a frozen
  first-frame glyph instead of the shared spinner animation.
- **`resolve_srv` normalizes its domain input** — the one public resolver
  entry point that skipped `normalize_domain`, so URL-form/garbage input
  produced a misclassified DNS error instead of an input-validation error.
- **MCP per-tool rate limits match REST** — `seer_bulk_ssl`/`seer_bulk_status`/
  `seer_bulk_propagation`/`seer_confusables` are now limited to 5/minute and
  the other bulk tools to 10/minute (mirroring the REST routers' per-route
  limits) on both MCP transports, instead of only the flat `SEER_RATE_LIMIT`.

### Added
- **Quote-aware REPL tokenization** — arguments may now be quoted
  shell-style, so `bulk lookup "Domain Lists/prod.txt"` works; unbalanced
  quotes produce a clear error instead of garbage tokens.

## [0.41.0] - 2026-07-05

A ccTLD coverage release: second-level registry zones (`.co.za` and friends)
now resolve, and live probing recovered two working registries IANA doesn't
advertise (`.ga`, relocated `.ps`).

### Added
- **Second-level registry zone support** — some ccTLDs have no top-level
  port-43 WHOIS while registrations live under SLD zones with a working
  registry server. WHOIS lookups now resolve the most specific zone first,
  starting with ZACR's `co.za`/`net.za`/`org.za`/`web.za`
  (`whois.registry.net.za`) — `seer whois google.co.za` previously failed
  with "no WHOIS server for .za" and now returns the full record. ([#108])

- **`.ga` (Gabon) WHOIS support** — ANINF (post-Freenom) runs a port-43
  server at `whois.nic.ga` that IANA does not advertise; found by live
  hostname probing. The generic parser also learned ANINF's French field
  labels (`Date de création`, `Date d'expiration`, `Dernière modification`,
  `Serveur de noms`), which benefits other francophone registries. ([#108])

### Fixed
- **`.ps` (Palestine) WHOIS restored** — PNINA relocated its registry server
  from the dead `whois.pnina.ps` (still listed by IANA) to
  `whois.registry.ps`, found by live hostname probing; the map and the
  Arabic IDN alias now point at the working server. ([#108])
- **Removed 4 dead WHOIS mappings** found by the same ccTLD follow-up audit:
  `lk` (+ its Sinhala/Tamil IDN variants) and `mt` — servers answer nothing
  and IANA no longer publishes a `whois:` field for them. These TLDs now get
  the clean "check whois via <registry URL>" guidance. A probe of all 248
  IANA ccTLDs (516 candidate hostnames) confirmed no other ccTLD has a
  reachable port-43 server seer is missing — the remaining unmapped ones,
  `.gr` included, are web-only registries. ([#108])

## [0.40.1] - 2026-07-04

A WHOIS reliability release: every one of the 1,246 mapped TLDs was exercised
live against its registry (registered + unregistered probes), and everything
that surfaced was fixed.

### Fixed
- **Availability detection across ~30 registries** — a full sweep of all 1,246
  mapped TLDs (registered + unregistered probe per TLD) found and fixed several
  gaps in WHOIS availability detection ([#107]):
  - Verdicts printed on `%`/`#` comment lines (AFNIC `%% NOT FOUND`, NIC.br
    `% No match for`, CZ.NIC `%ERROR:101: no entries found`, NORID, NIC.AT,
    ISNIC, RNIDS, RESTENA, NIC.SN, and others) are now detected — comment
    markers are stripped rather than the line skipped, with the existing
    word-count gate and refusal veto still applied.
  - Sentence-form verdicts longer than the status-line word gate (KISA `.kr`,
    EDUCAUSE `.edu`, NASK `.pl`) match anchored at line start.
  - New phrasings: RESTENA `.lu` "No such domain", NIC Mexico's
    `Object_Not_Found` token, NIC Argentina's Spanish response, and
    suffix-anchored "<domain> is free" (SIDN `.nl`, SETAR `.aw`).
  - The JPRS (`.jp`) and EDUCAUSE (`.edu`) parsers stamped a synthesized
    registrar onto *not-found* responses (EDUCAUSE's current format echoes the
    queried `Domain Name:`, defeating its old guard), which made unregistered
    domains impossible to report as available.
- **WHOIS-retirement notices** (ICANN RDAP transition) — registries that
  retired port-43 WHOIS (e.g. GMO Registry's 35 brand TLDs, May 2026) answer
  every query with a retirement notice; it is now classified as "no usable
  WHOIS service" so the smart-lookup ladder routes to RDAP instead of treating
  the notice as a thin record. ([#107])
- **Removed 8 dead WHOIS server mappings** (`apple`, `brussels`, `cymru`,
  `wales`, `vlaanderen`, `pharmacy`, `na`, `xn--p1acf`/`рус`) whose hostnames
  no longer resolve and whose IANA records no longer publish a `whois:` field
  (RDAP-only transitions). `seer whois` on these TLDs now returns the clean
  "check whois via <registry URL>" guidance instead of a DNS failure. ([#107])
- **WHOIS registry-format refresh** — a live audit against real registries fixed
  four gaps ([#106]):
  - `.de`: DENIC is now queried with `-T dn,ace`, restoring nameservers, DNSKEY,
    and change date (a bare query returns only `Status: connect`).
  - `.jp`: the JPRS parser understands the current bracket-label format
    (`[Name Server]`, `[Registrant]`, Japanese and `/e` English variants) and
    extracts the expiration date JPRS now publishes; the client sends the `/e`
    suffix for English responses.
  - `.lv`: the `Nserver: -` no-delegation placeholder is no longer reported as a
    literal nameserver.
  - `.dk`: Punktum's `Hostname:` nameserver lines and `Registered:` creation
    date now parse.

## [0.40.0] - 2026-07-04

### Added
- **Homebrew distribution** — Seer is now installable via a Homebrew tap:
  `brew install TheZacillac/tap/seer` (macOS/Linux, prebuilt binary, no Rust
  toolchain required). The formula is generated and pushed to
  [`TheZacillac/homebrew-tap`](https://github.com/TheZacillac/homebrew-tap)
  automatically by cargo-dist on each tagged release. ([#103])

## [0.39.0] - 2026-07-03

A feature release adding encrypted DNS transports, subdomain-change monitoring,
and broader bulk coverage, on top of internal core hardening ([#102]).

### Added
- **DoT / DoH nameservers** — every surface that accepts a custom nameserver
  (`seer dig --server`, `seer dns compare`, the REPL `@server` selector, and the
  `~/.seer/config.toml` `nameserver` setting) now understands `tls://host[:port]`
  (DNS over TLS) and `https://host/dns-query` (DNS over HTTPS), plus `host:port`
  and bracketed-IPv6 (`[2001:db8::1]:5353`) forms. Bare IPs/hostnames keep their
  existing UDP behavior byte-for-byte.
- **Subdomain baseline monitoring** — `seer subdomains <domain> --record` stores
  a CT-log enumeration snapshot under `~/.seer/subdomain_baselines.json`, and
  `--diff` compares a fresh enumeration against it, exiting 1 when NEW names have
  appeared (a classic phishing / zone-compromise signal) for cron/CI use. A
  first run with no baseline exits 0; removals are reported but not treated as
  material, since CT logs are append-mostly. Mirrors the `seer drift` model.
- **`seer watch --fail-on <warning|critical>`** — controls the severity
  threshold at which the check-all form exits non-zero (default `critical`).
- **More bulk operations** — `seer bulk` now supports `info`, `ssl`, `posture`,
  `confusables`, and `caa` in addition to the existing lookup/whois/rdap/dig/
  prop/status/avail operations.

### Changed
- Core hardening: unified the SSRF validation path, reused a single RDAP client
  across lookups, collapsed DNS resolver construction, and decoupled error
  classification from transport internals — no user-facing behavior change.
- The CLI and REPL now share a single subdomain-baseline / drift pipeline so the
  two surfaces cannot diverge.

## [0.38.0] - 2026-07-01

A feature release adding a suite of domain-intelligence capabilities and wiring
them through every interface — CLI, REPL, TUI, Python library, REST, and MCP
([#101]).

### Added
- **Domain drift** (`seer drift <domain>`) — diffs a fresh lookup against the
  last stored history snapshot (nameservers, registrar, expiry, DNSSEC,
  registrant) and exits non-zero on material change, for cron/CI monitoring.
- **Email/DNS security posture** (`seer posture <domain>`) — reports SPF, DMARC,
  MTA-STS, BIMI, and DANE (TLSA) with per-mechanism verdicts and advisories.
- **CAA policy** (`seer caa <domain>`) — surfaces the iodef incident-reporting
  contact and flags when the wildcard (`issuewild`) issuance policy is broader
  than the base (`issue`) policy.
- **Typosquat / look-alike scan** (`seer confusables <domain>`) — generates
  homoglyph and typo variants and reports which are registered, freshly
  registered first.
- **Subdomain classification** (`seer subdomains --resolve`) — resolves each
  discovered name, marks it live/dead/wildcard, and flags dangling CNAMEs that
  point at takeover-prone providers.
- **Richer lookups** — merged domain info now includes derived lifecycle fields
  (days-to-expiry, age, expiry band, plain-English status decoding) and the
  registrar abuse contact / IANA ID / URL. SSL reports include security-posture
  warnings (weak key, deprecated signature, self-signed, expiry, hostname
  mismatch); DNSSEC reports include a verification-depth tier and an opt-in
  RRSIG expiry check.
- **REST + MCP parity** — new single-domain endpoints and tools for ssl,
  availability, subdomains, dnssec, dns/compare, diff, info, caa, posture, and
  confusables, plus an optional `SEER_REQUEST_TIMEOUT` request deadline.
- **Python bindings** for `caa`, `posture`, `confusables`, and
  `subdomains_classify`.
- **Bulk over stdin** — `seer bulk <op> -` reads the domain list from stdin,
  and `--format json`/`yaml` streams a structured result array to stdout.
- **TUI** — full cursor-aware line editing in every input field (Home/End,
  Ctrl-W, mid-string edits) and an in-lens `/` find-filter for the subdomains,
  history, and propagation lenses.

### Changed
- The REPL and TUI now honor `~/.seer/config.toml` (per-protocol timeouts,
  nameserver, bulk concurrency; output format), matching the CLI subcommands.
- `seer bulk` writes its progress/summary lines to stderr so stdout is reserved
  for structured (`--format json/yaml`) output.

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

[Unreleased]: https://github.com/TheZacillac/seer/compare/v0.43.1...HEAD
[0.43.1]: https://github.com/TheZacillac/seer/compare/v0.43.0...v0.43.1
[0.43.0]: https://github.com/TheZacillac/seer/compare/v0.42.0...v0.43.0
[0.42.0]: https://github.com/TheZacillac/seer/compare/v0.41.0...v0.42.0
[0.41.0]: https://github.com/TheZacillac/seer/compare/v0.40.1...v0.41.0
[0.40.1]: https://github.com/TheZacillac/seer/compare/v0.40.0...v0.40.1
[0.40.0]: https://github.com/TheZacillac/seer/compare/v0.39.0...v0.40.0
[0.39.0]: https://github.com/TheZacillac/seer/compare/v0.38.0...v0.39.0
[0.38.0]: https://github.com/TheZacillac/seer/compare/v0.37.1...v0.38.0
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
[#101]: https://github.com/TheZacillac/seer/pull/101
[#102]: https://github.com/TheZacillac/seer/pull/102
[#103]: https://github.com/TheZacillac/seer/pull/103
[#106]: https://github.com/TheZacillac/seer/pull/106
[#107]: https://github.com/TheZacillac/seer/pull/107
[#108]: https://github.com/TheZacillac/seer/pull/108
[#111]: https://github.com/TheZacillac/seer/pull/111
[#112]: https://github.com/TheZacillac/seer/pull/112
