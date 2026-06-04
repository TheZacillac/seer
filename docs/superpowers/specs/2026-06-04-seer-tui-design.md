# Seer TUI — Design Spec

- **Date:** 2026-06-04
- **Status:** Approved (brainstorming → ready for implementation plan)
- **Author:** Zac Roach (with Claude)

## Context

Seer is a domain-intelligence suite (WHOIS / RDAP / DNS / SSL / status /
propagation / bulk) with a Rust core (`seer-core`), a CLI + rustyline REPL
(`seer-cli`), Python bindings (`seer-py`), and a FastAPI/MCP server
(`seer-api`). There is **no TUI today**.

A full-screen TUI was mocked up in Claude Design as an HTML/React prototype
(Catppuccin-Frappé, JetBrains Mono, ratatui-style box-drawing panels). The
prototype is the **visual source of truth**; this spec recreates it as a real
ratatui application wired to the existing `seer-core` backends. The prototype's
sample/synthesized data is **not** carried over — every implemented lens pulls
live data.

Prototype reference (handoff bundle): `Seer TUI.html` + `seer-tui/seer-*.{js,jsx}`
(grouped nav, 16 lenses, command bar, raw-output toggle, copy-to-clipboard,
help overlay, Frappé theme).

## Goals

1. A keyboard-first, full-screen TUI launched via `seer tui [domain]`.
2. Pixel-faithful to the Frappé mockup's layout, palette, and components.
3. **7 core lenses wired to live `seer-core`** in this pass; the full 16-entry
   grouped nav is present, with the remaining 9 as clean placeholders so
   follow-up passes are drop-in.
4. No business logic in the TUI layer — reuse `seer-core` clients and
   formatters exactly as the existing CLI subcommands do.

## Decisions (locked)

| Decision | Choice |
|---|---|
| Functional scope | Real shell + 7 core lenses wired to live `seer-core`; remaining lenses in follow-up passes |
| Launch / placement | New `seer tui [domain]` subcommand; code in a self-contained `seer-cli/src/tui/` module tree. REPL + existing subcommands untouched |
| Theme | Catppuccin Frappé (matches mockup `:root` and `seer-core::colors`) |
| Clipboard | OSC52 escape sequence, hand-rolled with the existing `base64` dep (zero new clipboard crates; works over SSH). Isolated in `clipboard.rs` for easy swap to `arboard` later |
| Unimplemented nav entries | Show all 16 grouped entries; unimplemented ones render a dimmed "planned — not yet wired" placeholder pane |
| Async model | Async message-loop ("Elm-style"): `tokio::select!` over crossterm `EventStream`, an `mpsc` results channel, and a tick interval. `App` is pure state |

## Architecture

**Async message-loop.** A single `tokio::select!` loop drives three sources:

1. **crossterm `EventStream`** — terminal input (keys/resize).
2. **`mpsc::Receiver<Msg>`** — completed background lookups + their results.
3. **`tokio::time::interval`** — animation tick for the braille spinner.

`App` is **pure state** with `update(&mut self, Msg) -> Vec<Action>` and
`view(&self, &mut Frame)`. Input is mapped to an `Action` (intent); data
lookups are dispatched as `tokio::spawn`ed tasks that call `seer-core` and send
`Msg::Data { lens, domain, result }` back over the channel. The UI never blocks
on the network — a lens in flight shows the spinner (the mock's `resolving…` /
loading state). Results are cached per `(lens, domain)` so re-visiting is
instant.

Rejected alternatives: synchronous `event::poll(16ms)` loop (less idiomatic
with the existing tokio runtime, but acceptable fallback); `block_on` per
lookup inline (freezes UI, kills the spinner UX — not acceptable).

## Module structure

```
seer-cli/src/tui/
├── mod.rs          # run(domain): terminal setup/teardown (raw mode, alt screen,
│                   #   panic hook to restore terminal), the select! event loop
├── app.rs          # App state + update(): focus (nav|pane), current lens,
│                   #   active sub-tab, selected row, output format, target domain,
│                   #   per-lens load state (Loading|Loaded|Error), toast, help.
│                   #   PURE / unit-testable.
├── action.rs       # Action enum (Fetch, MoveSel, JumpLens, ToggleFocus,
│                   #   CycleTab, EnterPane, Back, ToggleRaw, Copy, SetFormat,
│                   #   EditDomain, Command, Help, Quit, …) + Msg enum
│                   #   (Data, Tick, Input, Resize).
├── event.rs        # key/KeyEvent → Action mapping (keybindings). PURE / testable.
├── command.rs      # ':' command-line parser → Action. PURE / testable.
├── data.rs         # ONLY seer-core-coupled piece: Action::Fetch → spawn the
│                   #   matching core client → Msg::Data.
├── theme.rs        # Catppuccin Frappé → ratatui::style::Color (reuse
│                   #   seer-core::colors where possible).
├── clipboard.rs    # copy_osc52(text) — terminal-native clipboard via base64.
├── widgets/
│   ├── mod.rs
│   ├── panel.rs    # bordered Block, title embedded in top border (┤ title ├),
│   │               #   accent color + focus glow.
│   ├── kv.rs       # key/value rows with dotted leaders (kv__dots).
│   ├── table.rs    # selectable table w/ header row + row highlight.
│   ├── gauge.rs    # block-char gauge (█ / ░) with label.
│   ├── dot.rs      # colored status dot + text.
│   └── chips.rs    # chip row.
└── lenses/
    ├── mod.rs      # lens registry: ordered list w/ {key,label,glyph,cmd,group,tabs},
    │               #   groups (LOOKUP/DNS/SECURITY/POWER), number shortcuts.
    ├── overview.rs # SmartLookup
    ├── whois.rs    # WhoisClient
    ├── rdap.rs     # RdapClient (Domain tab; IP/ASN tabs = placeholder)
    ├── dns.rs      # DnsResolver (Records tab; DNSSEC/Compare tabs = placeholder)
    ├── ssl.rs      # SslChecker
    ├── status.rs   # StatusClient
    ├── propagation.rs # PropagationChecker
    └── placeholder.rs # "planned — not yet wired" pane for unimplemented lenses
```

`seer-cli/src/main.rs`: add `Tui { domain: Option<String> }` to the `Commands`
enum and dispatch to `tui::run(domain).await`. The `tui` module is declared in
`main.rs` alongside `repl` / `display`.

## Data flow & raw-output

- Entering a lens (nav move, number jump, `/` lookup, or `:` command) emits
  `Action::Fetch { lens, domain }`. `data.rs` spawns the matching `seer-core`
  call — the **same calls the CLI subcommands already make** (see the handlers
  in `main.rs`):
  - Overview → `SmartLookup::new().lookup(&domain).await`
  - WHOIS → `WhoisClient::new().lookup(&domain).await`
  - RDAP → `RdapClient::new()` domain lookup
  - DNS → `DnsResolver::new().resolve(&domain, RecordType, None).await`
  - Propagation → `dns::PropagationChecker::new()`
  - SSL → `SslChecker::new()`
  - Status → `StatusClient::new()`
- On completion the task sends `Msg::Data`; `App` stores the **typed response**
  (`LookupResult`, `WhoisResponse`, `RdapResponse`, `Vec<DnsRecord>`,
  `PropagationResult`, `SslReport`, `StatusResponse`) with a per-lens
  `Loading | Loaded | Error` state.
- **Human view** = the custom ratatui widgets per lens.
- **Raw view (`r`)** = reuse `seer_core::output::get_formatter(format)` and call
  `format_lookup / format_whois / format_rdap / format_dns / format_propagation /
  format_ssl / format_status` on the stored typed response. These are the exact
  code paths behind `seer --format json|yaml|markdown`. `OutputFormat` already
  has `{Human, Json, Yaml, Markdown}`, matching the mock's toggle.

## Lens scope & nav

Nav renders **all 16 entries in 4 groups**, matching the mockup:

```
LOOKUP    Overview · WHOIS · RDAP[Domain|IP|ASN] · Reverse · Availability · TLD Info
DNS       DNS Records[Records|DNSSEC|Compare] · Propagation · Follow
SECURITY  SSL/Cert · Status · Subdomains
POWER     Diff · Bulk · Watchlist · History
```

- **Implemented & wired (this pass):** Overview, WHOIS, RDAP (Domain tab), DNS
  (Records tab), SSL, Status, Propagation.
- **Placeholder (future passes):** Reverse, Availability, TLD, RDAP IP/ASN tabs,
  DNS DNSSEC/Compare tabs, Follow, Diff, Bulk, Watchlist, History. All have
  `seer-core` backends already; each is a drop-in lens module later.

## Keybindings & shell features

| Key | Action | Key | Action |
|---|---|---|---|
| `j`/`k`, `↑`/`↓` | move (nav or pane) | `r` | raw-output ⇄ human |
| `1`–`9` | jump to lens | `y` | copy/yank output |
| `Tab` | toggle focus nav ⇄ pane | `/` | edit target / lookup |
| `[` / `]` | switch sub-tabs | `:` | command mode |
| `↵` / `l` / `→` | enter pane | `?` | help overlay |
| `h` / `Esc` / `←` | back to nav | `g` / `G` | top / bottom |

- **Top bar:** `🔮 seer` brand · editable target field (`⌕` at rest, input when
  editing) · resolved IP (spinner while resolving) · `⧉ copy` · `--format` chip
  (shown when not human) · `‹nav›`/`‹pane›` mode · real `v{CARGO_PKG_VERSION}`.
- **Status bar:** current-lens label + keycap hints + auto-clearing toasts
  (ok/info/fail tones).
- **Command bar (`:`):** `lookup`, `whois`, `rdap`, `dig`, `ssl`, `status`,
  `prop`, `set output json|yaml|markdown|human`, `copy`/`yank`, `q`/`quit`.
  (`q` alone toasts "type :q to quit", per the mock.)
- **Help overlay (`?`):** keybinding reference; `Esc`/`?`/`q` closes.

## Dependencies

- Add **`ratatui = "0.29"`** to `seer-cli` (pins crossterm 0.28 — matches the
  workspace `crossterm` dep).
- Enable crossterm's **`event-stream`** feature (for async `EventStream`).
- Clipboard: **OSC52** via the existing workspace `base64` dep — **no new
  clipboard crate**.

## Testing (hermetic by default — matches repo convention)

Unit tests for the pure layers:

- `command.rs` — parse every `:` command + error cases.
- `event.rs` — key → Action mapping across focus modes.
- `app.rs` — `update()` state transitions (focus toggle, lens jump, sub-tab
  cycle, row selection clamping, format toggle, toast set/clear).
- `lenses/mod.rs` — registry/grouping, number-shortcut bounds, sub-tab cycling.
- Raw-format adapter — lens + typed response → expected `get_formatter` output.

Widget structure via **ratatui `TestBackend` buffer assertions**: Panel
title-in-border, Gauge fill ratio, KV dotted-leader rows.

Live `seer-core` network calls stay **out of** unit tests, behind the `Msg`
boundary — consistent with the repo's `#[ignore]` / opt-in live tests.

Pre-merge: `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt`.

## Out of scope (this pass)

- The 9 placeholder lenses' real rendering/wiring (future passes).
- Bulk file-picker, Follow streaming, Diff/Compare interactions.
- Replacing or changing the existing REPL / default `seer` behavior.
- `arboard`/native clipboard (OSC52 first; swap later if desired).

## Risks / notes

- **Terminal restore on panic:** install a panic hook that disables raw mode and
  leaves the alternate screen, so a panic never wrecks the user's terminal.
- **OSC52 support varies by terminal** (and tmux needs `set-clipboard on`); the
  copy toast reports success/failure honestly. `arboard` is the fallback option.
- **ratatui 0.29 ↔ crossterm 0.28** compatibility confirmed against the
  workspace pin before adding.
