# Seer TUI Completion — Design Spec

- **Date:** 2026-06-04
- **Status:** Approved (brainstorming → ready for implementation plan)
- **Builds on:** `2026-06-04-seer-tui-design.md` (the shipped 7-lens first pass, merged in PR #19)

## Context

The first pass shipped a working `seer tui` with 7 lenses (Overview, WHOIS, RDAP
domain, DNS records, SSL, Status, Propagation) and the full 16-entry nav, where
the other 9 lenses render a "planned" placeholder. This spec **completes** the
TUI: it wires the remaining **9 lenses + 4 sub-tabs + the custom-nameserver
field**, with **full in-pane inputs** matching the design mockup.

Everything is done in **one pass** (one spec → one plan → one PR), built and
reviewed incrementally (≈ one task per lens).

## Decisions (locked)

| Decision | Choice |
|---|---|
| Scope | All remaining lenses/tabs/inputs in one pass |
| Inputs | Full in-pane affordances per the mockup (switchers, editable fields, pickers) |
| Interactivity architecture | **Approach A — interactive lens "components"**: each interactive lens owns `(state, handle_key, render)`; `App` delegates pane-focused keys to it. Non-interactive lenses stay pure render-fns |
| Streaming (Follow, Bulk) | Background tasks emit incremental `Msg` steps over the existing channel; the lens component accumulates them |
| Multi-arg inputs | Parameterized fetch requests (`FetchReq`) + in-pane controls + extended `:` commands |
| Branch | `claude/seer-tui-completion` (off the merged first-pass state) |

## Lenses to complete

| Lens / tab | `seer-core` call | In-pane input / interactivity |
|---|---|---|
| Reverse DNS | `DnsResolver::resolve(ip, PTR, None)` | IP from target or `:reverse <ip>` |
| Availability | `AvailabilityChecker::check(domain)` | uses target; "other TLDs" sweep |
| TLD Info | `lookup_tld(tld)` → `TldInfo` | TLD switcher chips |
| RDAP · IP | `RdapClient::lookup_ip(ip)` | tab `[`/`]`; IP from target's A record |
| RDAP · ASN | `RdapClient::lookup_asn(u32)` | tab; ASN via `:rdap AS15169` |
| DNS · DNSSEC | `DnssecChecker::check(domain)` → `DnssecReport` | tab |
| DNS · Compare | `DnsComparator::compare(domain, rt, a, b)` → `DnsComparison` | resolver A/B pickers |
| DNS · custom NS | `DnsResolver::resolve(domain, rt, Some(ns))` | nameserver chips on Records tab |
| Diff | `DomainDiffer::diff(a, b)` → `DomainDiff` | editable second-domain field |
| Follow | `DnsFollower::follow(config, callback)` (stream) | interval/count fields, start/stop |
| Bulk | `BulkExecutor::execute_*` (stream) + `parse_domains_from_file` | source/op switchers, file-path field, export CSV |
| Watchlist | `Watchlist::load()` + `check_watchlist` | `a` add · `d` remove · `↵` open |
| History | `LookupHistory::load()` | `↵` replay · `c` clear |

## Architecture changes

The first pass modeled fetches as `Action::Fetch { lens, domain }` and stored
one `LensData` per lens. Completing the TUI needs parameterized fetches,
per-lens interactive state, generalized text inputs, and streaming. Four
focused changes:

### 1. Parameterized fetch requests (`FetchReq`)
Replace `Action::Fetch { lens, domain }` with `Action::Fetch(FetchReq)`, where
`FetchReq` is an enum carrying each request's arguments:

```
FetchReq::Overview(String) | Whois(String) | RdapDomain(String) | RdapIp(String)
       | RdapAsn(u32) | Dns { domain, record_type, nameserver: Option<String> }
       | Dnssec(String) | Compare { domain, record_type, a: String, b: String }
       | Ssl(String) | Status(String) | Prop(String) | Reverse(String)
       | Avail(String) | Tld(String) | Diff { a: String, b: String }
       | Watch | History
```

`data::fetch(req) -> Result<LensData, String>` matches on `FetchReq`. `Msg::Data`
carries the owning lens key + the result. This keeps the data layer the single
`seer-core`-coupled module while supporting per-lens arguments. The 7 existing
fetches migrate to `FetchReq` variants (behavior unchanged).

### 2. `LensData` gains variants
Add `Reverse(Vec<DnsRecord>)`, `Avail(Box<AvailabilityResult>)`,
`Tld(Box<TldInfo>)`, `Dnssec(Box<DnssecReport>)`, `Compare(Box<DnsComparison>)`,
`Diff(Box<DomainDiff>)`. RDAP IP/ASN reuse the existing `Rdap(RdapResponse)`
variant (render differs by active tab). Watchlist/History reuse a new
`Watch(Box<WatchReport>)` / `History(Vec<HistoryEntry>)`. Each new variant gets a
`raw.rs` arm (reusing `get_formatter`'s `format_dnssec`/`format_tld`/
`format_dns_comparison`/`format_diff`/`format_availability`/`format_watch`/etc.,
which already exist on the `OutputFormatter` trait).

### 3. Interactive lens components (`seer-cli/src/tui/panes/`)
Each **interactive** lens owns a small state struct + behavior, kept out of
`App`:

```
panes/mod.rs      # Panes { tld, dns, compare, diff, follow, bulk, watch } + routing
panes/tld.rs      # selected-TLD index; handle_key cycles; returns FetchReq::Tld
panes/dns.rs      # selected nameserver (system|8.8.8.8|1.1.1.1|custom); re-resolve
panes/compare.rs  # resolver A/B selection; returns FetchReq::Compare
panes/diff.rs     # second-domain text buffer; returns FetchReq::Diff
panes/follow.rs   # interval/count fields + streaming log + running flag (see §Streaming)
panes/bulk.rs     # source/op switchers, file-path field, streaming rows + progress
panes/watch.rs    # selected row + add/remove/open actions
```

Interface per component: `fn handle_key(&mut self, key: KeyEvent) -> PaneOutcome`
where `PaneOutcome` can be `None`, `Fetch(FetchReq)`, `StartStream(...)`, or
`Action(Action)`. `App`, when `focus == Pane` and the active lens is
interactive, delegates the key to `app.panes.<lens>.handle_key(...)` and
performs the outcome. Non-interactive lenses (Reverse, Availability, RDAP-IP/
ASN, DNSSEC, History view) remain pure render-fns of `LensData`.

### 4. Generalized text input + streaming messages
- Replace `InputMode::EditDomain(String)` with `InputMode::Field { target:
  EditTarget, buf: String }`, where `EditTarget` ∈ `{ Target, DiffB,
  FollowInterval, FollowCount, BulkPath }`. On `Enter`, `App` routes `buf` to the
  right place (Target → lookup; DiffB → diff fetch; Follow* → config; BulkPath →
  load+run). The top-bar `/` edit becomes `Field { Target }`.
- Add streaming `Msg` variants: `FollowStep(FollowIteration)`, `FollowDone`,
  `BulkStep(BulkRow)`, `BulkDone`. The component appends/updates its own state;
  `App::update` just forwards these to the active streaming component.

## Streaming flows

**Follow** — the component holds `{ interval, count, log: Vec, running, n }`.
On start it spawns `DnsFollower::follow(config, Some(callback))` where the
callback `move |it| { tx.send(Msg::FollowStep(it.clone())); }`; a final
`Msg::FollowDone` flips `running=false`. Restart re-spawns. Newest-first log,
`--changes-only` style highlight on change.

**Bulk** — the component holds `{ source, op, path_buf, rows, done, total,
running }`. Loading a path → `parse_domains_from_file(read(path))` (capped, same
rules as the CLI) → spawn the matching `BulkExecutor::execute_*` and stream
`Msg::BulkStep(row)` as each domain completes (gauge + per-row state), then
`Msg::BulkDone`. Built-in sample lists are offered alongside the path field
(a terminal has no native file dialog). "Export CSV" writes results to a path.

## Argument entry (commands + controls)

Extend the `:` parser with `reverse <ip>`, `tld <tld>`, `compare <domain> <a>
<b>`, `diff <a> <b>`, `follow <domain> [count] [interval]`, `bulk <op> <file>`.
These set the relevant lens, seed its component state, and dispatch the
`FetchReq`/stream. In-pane controls (switchers/fields) drive the same paths
without typing a command. Sensible defaults when no args: RDAP-IP uses the
target's resolved A record; Compare defaults to `8.8.8.8` vs `1.1.1.1`; Diff
requires a second domain (prompts the field).

## Stateful-lens actions

- **Watchlist:** `a` opens a `Field`-style add prompt → `Watchlist::add`; `d`
  removes the selected → `Watchlist::remove` + persist; `↵` loads that domain
  into Overview. Re-render via `check_watchlist`.
- **History:** `↵` replays the selected entry's lookup (loads it into Overview);
  `c` clears history (`LookupHistory::clear` + persist).

## Testing (hermetic, matches repo)

- Per-component `handle_key` unit tests: TLD/Compare/DNS selector cycling, Diff/
  Follow/Bulk field editing, Follow/Bulk stream accumulation via injected
  `Msg::*Step`, Watch add/remove/select, History clear/replay.
- `data::fetch` request routing is exercised indirectly; the network calls stay
  behind the `Msg` boundary (no live tests).
- `TestBackend` buffer tests for each new renderer (assert a known field/state
  shows; build minimal fixtures or skip where the type is large — same policy as
  the first pass).
- Extend `command.rs` tests for the new `:` commands.
- CI gates unchanged: `cargo clippy --workspace -- -D warnings`, `cargo fmt --all
  -- --check`, `cargo test --workspace`.

## Module structure additions

```
seer-cli/src/tui/
├── action.rs        # MODIFY: FetchReq enum, EditTarget, InputMode::Field,
│                    #   new LensData + Msg streaming variants
├── app.rs           # MODIFY: hold `panes`; delegate pane-focused keys; route
│                    #   streaming Msgs; migrate to FetchReq
├── command.rs       # MODIFY: parse the new commands
├── data.rs          # MODIFY: fetch(FetchReq) with the new seer-core calls
├── raw.rs           # MODIFY: serialize arms for the new LensData variants
├── render.rs        # MODIFY: sub-tab routing for RDAP/DNS; dispatch new lenses
├── panes/           # NEW: interactive lens components (see §3)
└── lenses/          # MODIFY: reverse.rs, avail.rs, tld.rs, dnssec.rs,
                     #   compare.rs, diff.rs, follow.rs, bulk.rs, watch.rs,
                     #   history.rs renderers (replace placeholders); rdap.rs +
                     #   dns.rs gain IP/ASN + DNSSEC/Compare tab rendering
```

## Out of scope / risks

- **No native file dialog** in a TUI → Bulk uses a path text-field + built-in
  sample lists, not an OS picker. Documented as such.
- **RDAP ASN** needs a numeric ASN; derived from an IP is not automatic, so the
  ASN tab defaults to requiring `:rdap AS…` (or shows a prompt) rather than
  guessing.
- This is a large change touching `action.rs`/`app.rs`; the `FetchReq` migration
  must keep the 7 existing lenses behaving identically (regression-tested).
- Interactive-input focus must never soft-lock: `Esc` always exits a field/
  component back to pane/nav, mirroring the first pass's guarantees.
