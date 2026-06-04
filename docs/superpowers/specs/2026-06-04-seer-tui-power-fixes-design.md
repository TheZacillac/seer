# Seer TUI — POWER-lens Fixes Design Spec

- **Date:** 2026-06-04
- **Status:** Approved (brainstorming → ready for implementation plan)
- **Builds on:** `2026-06-04-seer-tui-completion-design.md` (the 16-lens completion, shipped in PR #20 / released v0.31.0)

## Context

Interactive testing of the shipped TUI surfaced broken lenses. Investigation
found two distinct root causes:

### A. Pane-driven lenses never render (Diff, Bulk, Follow)

`render.rs::main_pane` returns early for every non-`Loaded` `LensState`
(Idle/Loading/Error), and the lens-renderer dispatcher (`lenses::render`) is
**only** called on `LensState::Loaded` (render.rs:224). But the interactive,
pane-driven lenses never receive a `FetchReq` (`default_req` returns `None` for
`diff`/`follow`/`bulk`), so their state stays `Idle` forever. Result: navigating
to Bulk, Follow, or an unloaded Diff shows the generic
`"press / to look up a domain"` hint and **none of their pane UI renders**.

Confirmed empirically: rendering the Bulk lens (even in Pane focus) produces the
`"press / to look up a domain"` hint with zero op-chips/gauge/results. The
`bulk::render` / `follow::render` functions are unreachable in the live TUI;
they only ran in isolated unit tests.

### B. Feature gaps in the (now-reachable) lenses

- **Diff** — even when reached (`:diff <a> <b>` sets `Loaded`), there is no
  always-visible way to enter domain B; the only hint (`e: set domain B`) lives
  *inside* the post-result renderer.
- **Bulk** — `panes/bulk.rs` cycles three *hardcoded* sample lists
  (`top-sites`/`portfolio`/`infrastructure`) instead of accepting domains — a
  brittle stand-in for "a terminal has no file dialog."
- **History** — the lens reads `~/.seer/history.json` correctly, but the TUI
  **never writes** to it. Only the CLI's `seer lookup` records
  (`main.rs:424-429`: `load → record → save`). In a pure-TUI session History is
  always empty.

Watchlist works (add `a` / remove `d` / open `↵` + live re-check) and is **out
of scope**.

## Decisions (locked)

| Decision | Choice |
|---|---|
| Render fix | `main_pane` renders the pane-driven interactive lenses (`diff`, `bulk`, `follow`) via their pane state in **all** `LensState`s (human view), not just `Loaded`. Remove their arms from the `lenses::render` dispatcher. |
| Follow | **In scope** — same render fix makes its existing live-monitor pane display; no other Follow changes needed. |
| Bulk input | Replace hardcoded presets with an editable **domains field** (type/paste a space/comma/newline-separated list). Keep op-switch (`o`), file-load (`f`), run (`r`/`↵`), CSV export (`e`). |
| Diff input | **Always-visible inline B field**: render `A · <domain>  ⇄  B · <b>` in every state, with `e` to edit and `↵` to compare. Standard interactive contract — edit in Pane focus; no `e`-from-Nav special-case. |
| History | Record each successful Overview/smart-lookup to `~/.seer/history.json`, best-effort, off the UI thread — mirroring the CLI. Make the History lens re-read on every entry so freshly-recorded lookups always appear. |
| Paste | Enable terminal **bracketed paste** so a multi-line domain list pastes as one string; route `Event::Paste` into the active text field / command buffer. |
| Renderer coupling | Diff/Bulk renderers take **explicit minimal context args** (domain, B, edit-buffer, focus, state), not `&App` — keeps lenses pure and unit-testable. Follow's renderer is unchanged. |
| Branch | `claude/seer-tui-power-fixes` (off `main` @ v0.31.0). |

## Fix 1 — Render interactive pane-lenses in all states

**Root cause A.** In `render.rs::main_pane`, after the sub-tab strip and
**before** the generic `LensState` match, special-case the three pane-driven
lenses in human view and `return`. Their content lives in `app.panes`, not in
`LensState`, so they render regardless of Idle/Loading/Error:

```rust
if app.format == OutputFormat::Human {
    match lens.key {
        "diff" => {
            let editing = field_buf(&app.input_mode, EditTarget::DiffB);
            let focused = app.focus == Focus::Pane;
            lenses::diff::render(
                f, content, theme, app.domain.as_deref(),
                &app.panes.diff.b, editing, focused, app.state_of(app.lens),
            );
            return;
        }
        "bulk" => {
            let editing = field_buf(&app.input_mode, EditTarget::BulkDomains);
            lenses::bulk::render(f, content, theme, &app.panes.bulk, editing);
            return;
        }
        "follow" => {
            lenses::follow::render(f, content, theme, &app.panes.follow);
            return;
        }
        _ => {}
    }
}
```

`field_buf(input_mode, target)` is a small render.rs helper returning
`Some(buf.as_str())` when `InputMode::Field { target, buf }` matches, else
`None`.

**Dispatcher (`lenses/mod.rs`):** remove the now-unreachable `"diff"`, `"bulk"`,
and `"follow"` arms from `lenses::render` (main_pane owns them; the dispatcher
is only entered for `Loaded` `LensData`, which these three never produce).

Raw view (`r`, non-human format) is unaffected: it still falls through to the
existing `Loaded → raw::serialize` path. Bulk/Follow have no serializable
`LensData`, so in raw mode they retain the generic idle hint (acceptable — the
raw toggle is meaningless without lens data); Diff serializes normally when
`Loaded`.

## Fix 2 — History records lookups

**Root cause B (History).** `data::fetch(FetchReq::Overview)` returns the result
without persisting.

**Change (`data.rs`):** after a successful Overview lookup, fire-and-forget a
blocking record+save, then return the result (the UI is not delayed):

```rust
FetchReq::Overview(d) => {
    let r = seer_core::SmartLookup::new().lookup(&d).await.map_err(e)?;
    // Record to history — best-effort, off the async reactor. Mirrors the
    // CLI lookup handler (main.rs). Detached: we don't await the save, so
    // the Overview result renders immediately.
    let (domain, result) = (d.clone(), r.clone());
    tokio::task::spawn_blocking(move || {
        let mut h = seer_core::LookupHistory::load();
        h.record(&domain, result);
        let _ = h.save();
    });
    Ok(LensData::Overview(Box::new(r)))
}
```

`LookupResult: Clone` is confirmed (the CLI clones it at main.rs:425). The
per-domain 50-entry cap (`MAX_ENTRIES_PER_DOMAIN`) already bounds growth.

**Change (`app.rs::fetch_current`):** History is a live disk view, so it must
never serve a stale cache. Before the existing `Loaded|Loading` cache check,
drop any cached `history` state so navigating to History always re-reads:

```rust
// History reflects on-disk state that lookups mutate behind its back;
// always re-read it rather than serving a cached (possibly empty) view.
if key == "history" {
    self.states.remove("history");
}
```

**Recording cadence:** every fresh Overview fetch records once. Re-visiting an
already-`Loaded` Overview for the same domain does not re-fetch (so does not
double-record); a new domain or an explicit re-`/`lookup does. This matches the
CLI's "each explicit lookup is an event" semantics.

## Fix 3 — Diff always-visible inline B field

Builds on Fix 1's render path. **Renderer (`lenses/diff.rs`)** — new signature
`render(f, area, theme, domain: Option<&str>, b: &str, editing: Option<&str>, focused: bool, state: &LensState)`.
Layout, top-to-bottom:

1. **Input bar** (always): `A · <domain or "(no target)">  ⇄  B · <value>`.
   - `editing = Some(buf)` → live buffer with cursor: `B · <buf>▏` (fixes the
     invisible-while-typing wart).
   - else `b` non-empty → show `b`; else a dim `[ press e ]`.
2. **Hint line** (focus-aware): `↵ focus pane` in Nav; `e edit B · ↵ compare`
   in Pane.
3. **Body** by `state`:
   - `Idle` → dim `set a second domain (e) to compare against <A>` (or
     `look up a domain first (/)` when no A).
   - `Loading` → `<spinner> comparing <A> ⇄ <B>…`.
   - `Error(msg)` → red error text (input bar stays, so the user can retry).
   - `Loaded(LensData::Diff)` → the existing FIELD | A | B comparison table.

**App (`app.rs`):** unchanged behavior — the `e`/`i`→`EditField(DiffB)` path
already works (diff pane `handle_key` → `apply_pane_outcome` →
`InputMode::Field{DiffB}` → `apply_field(DiffB,…)` → `FetchReq::Diff`).
`field_value(DiffB)` pre-fills the buffer; `Esc` already exits without
soft-locking.

## Fix 4 — Bulk type/paste domains

Builds on Fix 1's render path. **State (`panes/bulk.rs`):**
- **Remove** `SAMPLES`, `source_idx`, `source_name()`, `sample_domains()`, and
  the `t` key arm.
- **Add** `domains: String` (raw entered text) to `BulkState`.
- **Add** a parser with the same filter rules as `parse_domains_from_file`
  (trim, drop blank/`#`, require a dot) but splitting on whitespace **and**
  commas **and** newlines, capped at 50 (matching the file path in mod.rs):

```rust
/// Parse a free-form domains blob (typed or pasted) into a capped list.
/// Same filtering as `parse_domains_from_file`, but split on whitespace /
/// comma / newline so a single-line or multi-line paste both work.
pub fn parse_domains_input(s: &str) -> Vec<String> {
    s.split([',', ' ', '\t', '\n', '\r'])
        .map(str::trim)
        .filter(|t| !t.is_empty() && !t.starts_with('#') && t.contains('.'))
        .map(str::to_string)
        .take(50)
        .collect()
}
```

**Keys (`panes/bulk.rs::handle_key`):**
- `d` → `EditField(EditTarget::BulkDomains)` (open the domains field).
- `o` cycle op, `f` file-load, `e` CSV export — unchanged.
- `r`/`↵` → run `parse_domains_input(&self.domains)`; if empty, return
  `PaneOutcome::None` (App toasts `enter domains first (d)`).

**Field plumbing:**
- `action.rs`: add `EditTarget::BulkDomains`.
- `panes/mod.rs::field_value`: `BulkDomains => self.bulk.domains.clone()`.
- `panes/mod.rs::apply_field`: `BulkDomains => { self.bulk.domains = v; vec![] }`
  (stores text; does not auto-run — `r` runs, mirroring Follow's edit-then-run).
  `app.rs::apply_field` routes `BulkDomains` to `panes.apply_field`.

**Render (`lenses/bulk.rs`):** new signature
`render(f, area, theme, bulk: &BulkState, editing: Option<&str>)`.
- Replace the `source: <name> (N domains)` line with a **domains** line: parsed
  count + a short preview (`domains: 4 · google.com, github.com, …`), or a dim
  `domains: none — press d to enter` when empty; show the live buffer while
  editing.
- Hint row: `d domains · o op · r run · f file · e export`.
- Empty results placeholder: `enter domains (d) or load a file (f), then r to run`.

## Fix 5 — Follow (render only)

Follow's pane state, key handling (`s` start, `i` interval, `n` count, `x`
stop), and streaming (`Msg::FollowStep`/`FollowDone`) already work — they were
simply never displayed. Fix 1 makes `follow::render` reachable in all states; no
other Follow change is needed. Its renderer signature is unchanged
(`render(f, area, theme, &FollowState)`).

## Bracketed paste (supports the new text fields)

`mod.rs` never enables bracketed paste, so a pasted multi-line list arrives as
per-line key events and the first newline submits the field. Fix properly:

- **`mod.rs::setup_terminal`:** `execute!(stdout, EnterAlternateScreen, EnableBracketedPaste)?`.
- **`mod.rs::restore_terminal`** + **panic hook:** also `DisableBracketedPaste`.
  (Import `crossterm::event::{EnableBracketedPaste, DisableBracketedPaste}`.)
- **`app.rs::update`:** handle `Msg::Input(Event::Paste(s))` — if in
  `InputMode::Field { target, buf }`, append `s` to `buf`; if in
  `InputMode::Command(buf)`, append; otherwise ignore. (Today the catch-all
  `Msg::Input(_) => vec![]` drops paste.)

Works for the Diff B field, the Bulk domains field, and the command line, with
no terminal-specific hacks.

## Touched files

```
seer-cli/src/tui/
├── action.rs      # + EditTarget::BulkDomains
├── app.rs         # history re-read on entry; route BulkDomains;
│                  #   handle Event::Paste into active buffer
├── data.rs        # record Overview lookups to history (fire-and-forget)
├── mod.rs         # Enable/DisableBracketedPaste in setup/restore/panic
├── render.rs      # main_pane: render diff/bulk/follow in all states (human);
│                  #   field_buf helper
├── lenses/
│   ├── mod.rs     # drop unreachable diff/bulk/follow dispatch arms
│   ├── diff.rs    # render(domain,b,editing,focused,state): always-on input bar
│   └── bulk.rs    # render(bulk,editing): domains line + live buffer + new hints
└── panes/
    ├── bulk.rs    # drop SAMPLES/source; add `domains` + parse_domains_input;
    │              #   rekey (`d` domains, drop `t`)
    └── mod.rs     # field_value/apply_field for BulkDomains
```

No `seer-core` changes — all logic already exists there
(`LookupHistory`, `parse_domains_from_file`, `DomainDiffer`, `BulkExecutor`,
`DnsFollower`).

## Testing (hermetic — matches repo convention)

- **Render reachability (regression for root cause A):** `render::view` on the
  Bulk lens shows the op/run hint row (not `press /`); on Follow shows its
  monitor pane; on an Idle Diff shows the `A ·`/`B ·` input bar. These would
  have caught the dead-render bug.
- `panes/bulk.rs`: `parse_domains_input` — splits on space/comma/newline, drops
  blanks/`#`/dotless tokens, caps at 50. `d` opens the domains field; `r` with a
  populated `domains` emits `StartBulk` with the parsed list; `r` with empty
  `domains` returns `None`; `t` is gone. `to_csv` unchanged.
- `panes/mod.rs`: `field_value(BulkDomains)` round-trips; `apply_field(BulkDomains)`
  stores text without emitting an action.
- `app.rs`: navigating to History twice issues two fetches (cache always
  dropped); `Event::Paste` appends to a `Field` buffer and to a `Command` buffer.
- `lenses/diff.rs`: `TestBackend` — input bar shows `A ·`/`B ·` + current domain
  in **Idle**; comparison table renders when `Loaded`; live buffer shows when
  `editing = Some`.
- `lenses/bulk.rs`: `TestBackend` — empty state shows the `press d` prompt + new
  hint row; populated `domains` shows the preview/count; live buffer when editing.
- History recording (network) and live paste behavior stay out of unit tests,
  behind the `Msg`/`data::fetch` boundary — consistent with repo policy.
- CI gates unchanged: `cargo clippy --workspace -- -D warnings`,
  `cargo fmt --all -- --check`, `cargo test --workspace`.

## Out of scope / risks

- **Watchlist** is untouched (works today).
- **Bracketed-paste support varies by terminal.** When unsupported, paste falls
  back to per-line key events; the field parser still accepts a single-line
  space/comma-separated list, so manual entry always works. No regression for
  terminals that lack it.
- **Diff/Bulk renderers take explicit context args** (not `&App`), staying pure
  functions of their inputs; main_pane is the only place that reads `App` to
  assemble those args.
- **Detached history save** is not awaited; on an immediate quit a final save
  could be dropped. Lookups are near-instant and this is best-effort (the CLI
  ignores save errors too), so the risk is negligible.
- Interactive-input focus must never soft-lock: `Esc` always exits a field back
  to the pane/nav, preserving the existing guarantee.
```

