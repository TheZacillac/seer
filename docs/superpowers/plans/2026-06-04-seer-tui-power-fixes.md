# Seer TUI POWER-lens Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the TUI's interactive lenses actually work — render Diff/Bulk/Follow panes in every state, give Diff an always-visible domain-B field, replace Bulk's hardcoded presets with a type/paste domains field, and record lookups to History.

**Architecture:** Pure-state `App` (no I/O) + `update(Msg) -> Vec<Action>` + a `render.rs` that reads `&App`. Interactive lenses own pane state in `panes/`; their renderers live in `lenses/`. The root-cause render bug is that `main_pane` only dispatches lens renderers on `LensState::Loaded`, but pane-driven lenses (diff/bulk/follow) never fetch, so they never render — fixed by special-casing them in `main_pane` to render from pane state in all states. All engine logic already exists in `seer-core`.

**Tech Stack:** Rust, ratatui 0.29, crossterm 0.28 (event-stream + bracketed paste), tokio. Tests use ratatui `TestBackend` buffer assertions + pure `App` unit tests. `seer-cli` is a **binary** crate — run tests with `cargo test -p seer-cli <name>` (not `--lib`).

---

## File Structure

All changes are in `seer-cli/src/tui/` except none in `seer-core` (engine logic reused as-is):

- `action.rs` — add `EditTarget::BulkDomains` (Task 5).
- `app.rs` — History always-refresh + domain-less fetch (Task 1); `Event::Paste` into active buffer (Task 2); route `BulkDomains`, handle `PaneOutcome::Toast` (Task 5).
- `data.rs` — record Overview lookups to history (Task 1).
- `mod.rs` — enable/disable bracketed paste (Task 2).
- `render.rs` — `main_pane` renders diff/bulk/follow in all states (human view); `field_buf` helper (Tasks 3/4/5).
- `lenses/mod.rs` — drop the unreachable diff/bulk/follow dispatch arms (Tasks 3/4/5).
- `lenses/diff.rs` — new `render` signature: always-on A⇄B input bar (Task 4).
- `lenses/bulk.rs` — new `render` signature: domains line + live buffer + new hints (Task 5).
- `panes/bulk.rs` — drop `SAMPLES`/source; add `domains` + `parse_domains_input`; rekey (Task 5).
- `panes/mod.rs` — `PaneOutcome::Toast`; `field_value`/`apply_field` for `BulkDomains` (Task 5).

Each task compiles and tests green on its own.

---

## Task 1: History records lookups + always-fresh view

**Files:**
- Modify: `seer-cli/src/tui/data.rs:14-18` (Overview arm)
- Modify: `seer-cli/src/tui/app.rs:140-160` (`fetch_current`)
- Test: `seer-cli/src/tui/app.rs` (tests module)

- [ ] **Step 1: Write failing tests** (append inside `app.rs` `mod tests`, before the final `}`):

```rust
    #[test]
    fn history_always_refetches_even_when_loaded() {
        let mut app = App::new(None);
        app.domain = Some("example.com".into());
        let hidx = history_lens_idx();
        app.lens = hidx;
        // First entry → a History fetch is issued.
        let a1 = app.fetch_current();
        assert!(
            matches!(a1, Some(Action::Fetch { req: FetchReq::History, .. })),
            "first visit should fetch history, got {a1:?}",
        );
        // Simulate the result arriving.
        app.states.insert(
            crate::tui::lenses::lenses()[hidx].key,
            LensState::Loaded(LensData::History(vec![])),
        );
        // Second entry → cache is dropped, so it fetches again (fresh disk read).
        let a2 = app.fetch_current();
        assert!(
            matches!(a2, Some(Action::Fetch { req: FetchReq::History, .. })),
            "history must always refetch even when already Loaded, got {a2:?}",
        );
    }

    #[test]
    fn history_fetches_without_a_domain() {
        let mut app = App::new(None); // no target domain
        app.lens = history_lens_idx();
        let a = app.fetch_current();
        assert!(
            matches!(a, Some(Action::Fetch { req: FetchReq::History, .. })),
            "history should load with no domain set, got {a:?}",
        );
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p seer-cli history_always_refetches_even_when_loaded history_fetches_without_a_domain`
Expected: FAIL — second fetch returns `None` (cache hit), and no-domain fetch returns `None` (domain gate).

- [ ] **Step 3: Rewrite `fetch_current` in `app.rs`** (replace the whole method at lines 140-160):

```rust
    /// Queue a fetch for the current lens at the current domain, marking it
    /// Loading. Returns None if the lens isn't implemented or there's nothing
    /// to fetch. History and Watch do not require a target domain.
    fn fetch_current(&mut self) -> Option<Action> {
        let lens = self.current_lens();
        let (key, implemented) = (lens.key, lens.implemented);
        if !implemented {
            return None;
        }
        // History reflects on-disk state that lookups mutate behind its back;
        // always re-read it rather than serving a cached (possibly empty) view.
        if key == "history" {
            self.states.remove("history");
        }
        // Cached (or in flight) for the current domain → revisiting is instant.
        if matches!(
            self.states.get(key),
            Some(LensState::Loaded(_) | LensState::Loading)
        ) {
            return None;
        }
        // Most lenses need a target; History/Watch are global views.
        let req = match self.domain.clone() {
            Some(domain) => self.default_req(key, &domain)?,
            None => match key {
                "history" => FetchReq::History,
                "watch" => FetchReq::Watch,
                _ => return None,
            },
        };
        self.states.insert(key, LensState::Loading);
        Some(self.fetch_action(req))
    }
```

- [ ] **Step 4: Record Overview lookups to history in `data.rs`** (replace the `FetchReq::Overview(d)` arm at lines 14-18):

```rust
        FetchReq::Overview(d) => {
            let r = seer_core::SmartLookup::new().lookup(&d).await.map_err(e)?;
            // Record to history — best-effort, off the async reactor. Mirrors the
            // CLI lookup handler (main.rs). Detached (not awaited): the Overview
            // result renders immediately; the save lands a beat later.
            let (domain, result) = (d.clone(), r.clone());
            tokio::task::spawn_blocking(move || {
                let mut h = seer_core::LookupHistory::load();
                h.record(&domain, result);
                let _ = h.save();
            });
            Ok(LensData::Overview(Box::new(r)))
        }
```

- [ ] **Step 5: Run tests + full suite to verify green**

Run: `cargo test -p seer-cli history_always_refetches_even_when_loaded history_fetches_without_a_domain`
Expected: PASS

Run: `cargo test -p seer-cli`
Expected: PASS (no regressions)

- [ ] **Step 6: Commit**

```bash
git add seer-cli/src/tui/data.rs seer-cli/src/tui/app.rs
git commit -m "fix(tui): record lookups to history and always re-read it"
```

---

## Task 2: Bracketed paste into text fields

**Files:**
- Modify: `seer-cli/src/tui/mod.rs:21-72` (imports + setup/restore/panic)
- Modify: `seer-cli/src/tui/app.rs:312-314` (`update` input arms)
- Test: `seer-cli/src/tui/app.rs` (tests module)

- [ ] **Step 1: Write failing tests** (append inside `app.rs` `mod tests`):

```rust
    #[test]
    fn paste_appends_into_active_field() {
        use crossterm::event::Event;
        let mut app = App::new(None);
        app.input_mode = InputMode::Field {
            target: EditTarget::DiffB,
            buf: "a.com ".into(),
        };
        app.update(Msg::Input(Event::Paste("b.com c.com".into())));
        assert!(
            matches!(&app.input_mode, InputMode::Field { buf, .. } if buf == "a.com b.com c.com"),
            "paste should append to the field buffer, got {:?}",
            app.input_mode
        );
    }

    #[test]
    fn paste_appends_into_command_buffer() {
        use crossterm::event::Event;
        let mut app = App::new(None);
        app.input_mode = InputMode::Command("look".into());
        app.update(Msg::Input(Event::Paste("up x.com".into())));
        assert!(
            matches!(&app.input_mode, InputMode::Command(buf) if buf == "lookup x.com"),
            "paste should append to the command buffer, got {:?}",
            app.input_mode
        );
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p seer-cli paste_appends_into_active_field paste_appends_into_command_buffer`
Expected: FAIL — `Event::Paste` is dropped by the `Msg::Input(_) => vec![]` catch-all, so the buffers are unchanged.

- [ ] **Step 3: Handle paste in `app.rs::update`** — replace the two input arms at lines 312-313:

```rust
            // Only Press events — ignoring Repeat/Release avoids double-input on
            // Windows legacy consoles. (Held-key auto-repeat is not relied upon.)
            Msg::Input(Event::Key(key)) if key.kind == KeyEventKind::Press => self.on_key(key),
            Msg::Input(Event::Paste(s)) => {
                // Bracketed paste lands here as one string. Route it into whatever
                // text buffer is active so multi-line domain lists paste cleanly.
                match &mut self.input_mode {
                    InputMode::Field { buf, .. } => buf.push_str(&s),
                    InputMode::Command(buf) => buf.push_str(&s),
                    InputMode::Normal => {}
                }
                vec![]
            }
            Msg::Input(_) => vec![],
```

- [ ] **Step 4: Enable bracketed paste in `mod.rs`** — update the crossterm terminal import (lines 27-29) to add the paste commands:

```rust
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::event::{DisableBracketedPaste, EnableBracketedPaste};
```

Then update `setup_terminal` (lines 50-55):

```rust
fn setup_terminal() -> Result<Term> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableBracketedPaste)?;
    Ok(Terminal::new(CrosstermBackend::new(stdout))?)
}
```

`restore_terminal` (lines 57-62):

```rust
fn restore_terminal(terminal: &mut Term) -> Result<()> {
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        DisableBracketedPaste,
        LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;
    Ok(())
}
```

`install_panic_hook` body (lines 67-71):

```rust
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), DisableBracketedPaste, LeaveAlternateScreen);
        original(info);
    }));
```

- [ ] **Step 5: Run tests + full suite to verify green**

Run: `cargo test -p seer-cli paste_appends_into_active_field paste_appends_into_command_buffer`
Expected: PASS

Run: `cargo build -p seer-cli && cargo test -p seer-cli`
Expected: build OK, tests PASS.

- [ ] **Step 6: Commit**

```bash
git add seer-cli/src/tui/mod.rs seer-cli/src/tui/app.rs
git commit -m "feat(tui): enable bracketed paste into text fields"
```

---

## Task 3: Render the Follow pane in all states

**Files:**
- Modify: `seer-cli/src/tui/render.rs:144-158` (`main_pane` — insert special-case)
- Modify: `seer-cli/src/tui/lenses/mod.rs:245` (remove `follow` dispatch arm)
- Test: `seer-cli/src/tui/render.rs` (tests module)

- [ ] **Step 1: Write the failing test** (append inside `render.rs` `mod tests`):

```rust
    fn full_buf(app: &App, theme: &Theme) -> String {
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|f| view(f, app, theme)).unwrap();
        let buf = terminal.backend().buffer();
        let area = buf.area();
        let mut s = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                s.push_str(buf[(x, y)].symbol());
            }
        }
        s
    }

    #[test]
    fn follow_lens_renders_its_pane_not_the_generic_hint() {
        let theme = Theme::frappe();
        let mut app = App::new(None);
        app.lens = crate::tui::lenses::find_by_cmd_or_key("follow").unwrap();
        let s = full_buf(&app, &theme);
        assert!(s.contains("s start"), "Follow pane (hints) should render");
        assert!(
            !s.contains("press / to look up a domain"),
            "Follow must not fall back to the generic idle hint"
        );
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p seer-cli follow_lens_renders_its_pane_not_the_generic_hint`
Expected: FAIL — buffer contains "press / to look up a domain" and not "s start".

- [ ] **Step 3: Add the pane-lens special-case in `render.rs::main_pane`** — immediately after the `content` binding (after line 157, before the `match app.state_of(app.lens)` at line 159), insert:

```rust
    // Pane-driven interactive lenses render from `app.panes` state, not from a
    // fetched `LensData`, so they never reach `LensState::Loaded`. Render them
    // here in every state (human view only — they have no raw serialization).
    if app.format == seer_core::output::OutputFormat::Human {
        match lens.key {
            "follow" => {
                lenses::follow::render(f, content, theme, &app.panes.follow);
                return;
            }
            _ => {}
        }
    }
```

- [ ] **Step 4: Remove the now-unreachable `follow` arm from the dispatcher** in `lenses/mod.rs` — delete line 245:

```rust
        "follow" => follow::render(f, area, theme, &panes.follow),
```

(The `follow` module stays declared and is still called from `render.rs`. The dispatcher is only entered for `Loaded` data, which Follow never produces, so this arm was dead.)

- [ ] **Step 5: Run test + full suite to verify green**

Run: `cargo test -p seer-cli follow_lens_renders_its_pane_not_the_generic_hint`
Expected: PASS

Run: `cargo test -p seer-cli`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add seer-cli/src/tui/render.rs seer-cli/src/tui/lenses/mod.rs
git commit -m "fix(tui): render the Follow pane (was unreachable in main view)"
```

---

## Task 4: Diff — render in all states + always-visible B field

**Files:**
- Modify: `seer-cli/src/tui/lenses/diff.rs` (new `render` signature + input bar)
- Modify: `seer-cli/src/tui/render.rs` (`main_pane` diff case + `field_buf` helper + imports)
- Modify: `seer-cli/src/tui/lenses/mod.rs:240` (remove `diff` dispatch arm)
- Test: `seer-cli/src/tui/lenses/diff.rs` (tests module)

- [ ] **Step 1: Replace `lenses/diff.rs` entirely** with the new always-on input-bar renderer:

```rust
//! Diff lens — always-visible A⇄B input bar + 3-column comparison (FIELD|A|B).
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Row, Table};
use ratatui::Frame;

use crate::tui::action::{LensData, LensState};
use crate::tui::theme::Theme;
use crate::tui::widgets::panel;

/// Render the Diff lens. Pure function of its inputs (no `App` coupling):
/// - `domain`  current target = domain A
/// - `b`       committed second domain (B)
/// - `editing` `Some(buf)` while the B field is being typed
/// - `focused` whether the pane has focus
/// - `state`   the lens load state (drives the body)
pub fn render(
    f: &mut Frame,
    area: Rect,
    theme: &Theme,
    domain: Option<&str>,
    b: &str,
    editing: Option<&str>,
    focused: bool,
    state: &LensState,
) {
    let block = panel::block(theme, "Diff", theme.yellow, focused);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // input bar
            Constraint::Length(1), // hint
            Constraint::Min(0),    // body
        ])
        .split(inner);

    // ── input bar: A · <domain>   ⇄   B · <value> ────────────────────────────
    let a = domain.unwrap_or("(no target)");
    let (b_text, b_color) = match editing {
        Some(buf) => (format!("{buf}▏"), theme.text),
        None if !b.is_empty() => (b.to_string(), theme.text),
        None => ("[ press e ]".to_string(), theme.overlay0),
    };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("A · ", Style::default().fg(theme.overlay0)),
            Span::styled(a.to_string(), Style::default().fg(theme.text)),
            Span::styled("   ⇄   ", Style::default().fg(theme.yellow)),
            Span::styled("B · ", Style::default().fg(theme.overlay0)),
            Span::styled(b_text, Style::default().fg(b_color)),
        ])),
        chunks[0],
    );

    // ── hint (focus-aware) ───────────────────────────────────────────────────
    let hint = if focused {
        "e edit B · ↵ compare"
    } else {
        "↵ focus pane"
    };
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            hint,
            Style::default().fg(theme.overlay0),
        ))),
        chunks[1],
    );

    // ── body by state ────────────────────────────────────────────────────────
    match state {
        LensState::Loaded(LensData::Diff(d)) => comparison_table(f, chunks[2], theme, d),
        LensState::Loading => {
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    format!("⠋ comparing {a} ⇄ {b}…"),
                    Style::default().fg(theme.overlay),
                ))),
                chunks[2],
            );
        }
        LensState::Error(msg) => {
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    msg.clone(),
                    Style::default().fg(theme.red),
                ))),
                chunks[2],
            );
        }
        _ => {
            let idle = if domain.is_some() {
                format!("set a second domain (e) to compare against {a}")
            } else {
                "look up a domain first (/)".to_string()
            };
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    idle,
                    Style::default()
                        .fg(theme.overlay0)
                        .add_modifier(Modifier::ITALIC),
                ))),
                chunks[2],
            );
        }
    }
}

/// The FIELD | A | B comparison table for a completed diff.
fn comparison_table(f: &mut Frame, area: Rect, theme: &Theme, d: &seer_core::diff::DomainDiff) {
    let dash = "—".to_string();
    let mut raw: Vec<(&str, String, String)> = Vec::new();

    let (ra, rb) = &d.registration.registrar;
    raw.push((
        "registrar",
        ra.clone().unwrap_or_else(|| dash.clone()),
        rb.clone().unwrap_or_else(|| dash.clone()),
    ));
    let (oa, ob) = &d.registration.organization;
    raw.push((
        "organization",
        oa.clone().unwrap_or_else(|| dash.clone()),
        ob.clone().unwrap_or_else(|| dash.clone()),
    ));
    let (ca, cb) = &d.registration.created;
    raw.push((
        "created",
        ca.clone().unwrap_or_else(|| dash.clone()),
        cb.clone().unwrap_or_else(|| dash.clone()),
    ));
    let (ea, eb) = &d.registration.expires;
    raw.push((
        "expires",
        ea.clone().unwrap_or_else(|| dash.clone()),
        eb.clone().unwrap_or_else(|| dash.clone()),
    ));
    raw.push((
        "A records",
        d.dns.a_records.0.join(", "),
        d.dns.a_records.1.join(", "),
    ));
    raw.push((
        "nameservers",
        d.dns.nameservers.0.join(", "),
        d.dns.nameservers.1.join(", "),
    ));
    raw.push((
        "resolves",
        d.dns.resolves.0.to_string(),
        d.dns.resolves.1.to_string(),
    ));
    let (ia, ib) = &d.ssl.issuer;
    raw.push((
        "ssl issuer",
        ia.clone().unwrap_or_else(|| dash.clone()),
        ib.clone().unwrap_or_else(|| dash.clone()),
    ));
    let (vu_a, vu_b) = &d.ssl.valid_until;
    raw.push((
        "ssl valid until",
        vu_a.clone().unwrap_or_else(|| dash.clone()),
        vu_b.clone().unwrap_or_else(|| dash.clone()),
    ));
    let (dr_a, dr_b) = &d.ssl.days_remaining;
    raw.push((
        "ssl days",
        dr_a.map(|n| n.to_string()).unwrap_or_else(|| dash.clone()),
        dr_b.map(|n| n.to_string()).unwrap_or_else(|| dash.clone()),
    ));
    let (iv_a, iv_b) = &d.ssl.is_valid;
    raw.push((
        "ssl ok",
        iv_a.map(|b| b.to_string()).unwrap_or_else(|| dash.clone()),
        iv_b.map(|b| b.to_string()).unwrap_or_else(|| dash.clone()),
    ));

    let rows: Vec<Row> = raw
        .iter()
        .map(|(field, a_val, b_val)| {
            let same = a_val == b_val;
            let indicator = if same { "=" } else { "≠" };
            let value_color = if same { theme.text } else { theme.yellow };
            Row::new(vec![
                ratatui::text::Text::from(Line::from(Span::styled(
                    format!("{indicator} {field:<16}"),
                    Style::default().fg(if same { theme.overlay0 } else { theme.yellow }),
                ))),
                ratatui::text::Text::from(Line::from(Span::styled(
                    a_val.clone(),
                    Style::default().fg(value_color),
                ))),
                ratatui::text::Text::from(Line::from(Span::styled(
                    b_val.clone(),
                    Style::default().fg(value_color),
                ))),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(20),
            Constraint::Percentage(40),
            Constraint::Percentage(40),
        ],
    )
    .column_spacing(1);
    f.render_widget(table, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use seer_core::diff::{DnsDiff, DomainDiff, RegistrationDiff, SslDiff};

    fn buf_text(buf: &ratatui::buffer::Buffer) -> String {
        let a = buf.area();
        let mut s = String::new();
        for y in 0..a.height {
            for x in 0..a.width {
                s.push_str(buf[(x, y)].symbol());
            }
        }
        s
    }

    fn diff_fixture() -> DomainDiff {
        DomainDiff {
            domain_a: "a.com".into(),
            domain_b: "b.com".into(),
            registration: RegistrationDiff {
                registrar: (Some("NameCheap".into()), Some("GoDaddy".into())),
                organization: (None, None),
                created: (None, None),
                expires: (None, None),
            },
            dns: DnsDiff {
                a_records: (vec!["1.2.3.4".into()], vec!["5.6.7.8".into()]),
                nameservers: (vec![], vec![]),
                resolves: (true, true),
            },
            ssl: SslDiff {
                issuer: (None, None),
                valid_until: (None, None),
                days_remaining: (None, None),
                is_valid: (None, None),
            },
        }
    }

    #[test]
    fn idle_shows_input_bar_with_domain_a() {
        let theme = Theme::frappe();
        let backend = TestBackend::new(90, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| {
                render(
                    f,
                    f.area(),
                    &theme,
                    Some("acme.io"),
                    "",
                    None,
                    false,
                    &LensState::Idle,
                )
            })
            .unwrap();
        let text = buf_text(terminal.backend().buffer());
        assert!(text.contains("A ·"), "input bar shows A");
        assert!(text.contains("B ·"), "input bar shows B");
        assert!(text.contains("acme.io"), "shows current domain as A");
        assert!(text.contains("press e"), "prompts how to set B");
    }

    #[test]
    fn editing_shows_live_buffer() {
        let theme = Theme::frappe();
        let backend = TestBackend::new(90, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| {
                render(
                    f,
                    f.area(),
                    &theme,
                    Some("acme.io"),
                    "",
                    Some("typed.io"),
                    true,
                    &LensState::Idle,
                )
            })
            .unwrap();
        assert!(
            buf_text(terminal.backend().buffer()).contains("typed.io"),
            "live edit buffer should render"
        );
    }

    #[test]
    fn loaded_shows_comparison_table() {
        let theme = Theme::frappe();
        let state = LensState::Loaded(LensData::Diff(Box::new(diff_fixture())));
        let backend = TestBackend::new(90, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, Some("a.com"), "b.com", None, false, &state))
            .unwrap();
        let text = buf_text(terminal.backend().buffer());
        assert!(text.contains("NameCheap"), "table renders registrar A");
        assert!(text.contains("GoDaddy"), "table renders registrar B");
    }
}
```

- [ ] **Step 2: Run the diff tests to verify they fail to compile/pass**

Run: `cargo test -p seer-cli --no-run`
Expected: FAIL to compile — `render.rs` and `lenses/mod.rs` still call the old `diff::render(f, area, theme, data)` signature.

- [ ] **Step 3: Add the `field_buf` helper + diff case in `render.rs`** — add `EditTarget`/`Focus` to the action import at line 10:

```rust
use crate::tui::action::{EditTarget, Focus, InputMode, LensState};
```

Add this free function near the top of `render.rs` (after the `use` block, before `pub fn view`):

```rust
/// The in-progress edit buffer for `target`, if a matching field is active.
fn field_buf(mode: &InputMode, target: EditTarget) -> Option<&str> {
    match mode {
        InputMode::Field { target: t, buf } if *t == target => Some(buf.as_str()),
        _ => None,
    }
}
```

Extend the `main_pane` human-view match (from Task 3) with a `diff` arm:

```rust
    if app.format == seer_core::output::OutputFormat::Human {
        match lens.key {
            "follow" => {
                lenses::follow::render(f, content, theme, &app.panes.follow);
                return;
            }
            "diff" => {
                lenses::diff::render(
                    f,
                    content,
                    theme,
                    app.domain.as_deref(),
                    &app.panes.diff.b,
                    field_buf(&app.input_mode, EditTarget::DiffB),
                    app.focus == Focus::Pane,
                    app.state_of(app.lens),
                );
                return;
            }
            _ => {}
        }
    }
```

- [ ] **Step 4: Remove the `diff` dispatch arm** in `lenses/mod.rs` — delete line 240:

```rust
        "diff" => diff::render(f, area, theme, data),
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p seer-cli idle_shows_input_bar_with_domain_a editing_shows_live_buffer loaded_shows_comparison_table`
Expected: PASS

Run: `cargo test -p seer-cli`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add seer-cli/src/tui/lenses/diff.rs seer-cli/src/tui/render.rs seer-cli/src/tui/lenses/mod.rs
git commit -m "feat(tui): always-visible domain-B field on the Diff lens"
```

---

## Task 5: Bulk — type/paste domains (replace presets) + render path

**Files:**
- Modify: `seer-cli/src/tui/action.rs:23-30` (add `EditTarget::BulkDomains`)
- Modify: `seer-cli/src/tui/panes/bulk.rs` (state, parser, key handling)
- Modify: `seer-cli/src/tui/panes/mod.rs` (`PaneOutcome::Toast`, field plumbing)
- Modify: `seer-cli/src/tui/app.rs` (`apply_field` routing, `apply_pane_outcome` toast)
- Modify: `seer-cli/src/tui/lenses/bulk.rs` (new `render` signature, domains line)
- Modify: `seer-cli/src/tui/render.rs` (`main_pane` bulk case)
- Modify: `seer-cli/src/tui/lenses/mod.rs:246` (remove `bulk` dispatch arm)
- Test: `panes/bulk.rs`, `lenses/bulk.rs`

- [ ] **Step 1: Add `EditTarget::BulkDomains`** in `action.rs` (lines 22-30):

```rust
/// Which text field an `InputMode::Field` is editing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditTarget {
    Target,
    DiffB,
    FollowInterval,
    FollowCount,
    BulkPath,
    BulkDomains,
    WatchAdd,
}
```

- [ ] **Step 2: Write failing tests in `panes/bulk.rs`** — replace the existing `mod tests` content's affected tests. Add these (and remove `t_cycles_source`, fix `default_state_is_zeroed` and `r_sets_running_and_returns_start_bulk` per Step 5):

```rust
    #[test]
    fn parse_domains_input_splits_and_filters() {
        let got = parse_domains_input("google.com, github.com\nrust-lang.org  bad\n# comment.skip");
        assert_eq!(got, vec!["google.com", "github.com", "rust-lang.org"]);
        // "bad" has no dot → dropped; "# comment.skip" starts with # → dropped.
    }

    #[test]
    fn parse_domains_input_caps_at_50() {
        let many = (0..80).map(|i| format!("d{i}.com")).collect::<Vec<_>>().join(" ");
        assert_eq!(parse_domains_input(&many).len(), 50);
    }

    #[test]
    fn d_opens_domains_field() {
        let mut s = BulkState::default();
        let out = s.handle_key(key(KeyCode::Char('d')));
        assert!(matches!(
            out,
            Some(PaneOutcome::EditField(EditTarget::BulkDomains))
        ));
    }

    #[test]
    fn r_with_empty_domains_toasts_and_does_not_run() {
        let mut s = BulkState::default();
        let out = s.handle_key(key(KeyCode::Char('r')));
        assert!(!s.running, "empty run must not start");
        assert!(matches!(out, Some(PaneOutcome::Toast { .. })));
    }

    #[test]
    fn r_with_domains_starts_run_with_parsed_list() {
        let mut s = BulkState::default();
        s.domains = "a.com b.com".into();
        let out = s.handle_key(key(KeyCode::Char('r')));
        assert!(s.running);
        assert_eq!(s.gen, 1);
        match out {
            Some(PaneOutcome::Action(Action::StartBulk(p))) => {
                assert_eq!(p.op, "lookup");
                assert_eq!(p.domains, vec!["a.com", "b.com"]);
                assert_eq!(p.gen, 1);
            }
            other => panic!("expected StartBulk, got {other:?}"),
        }
    }
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p seer-cli --no-run`
Expected: FAIL to compile — `parse_domains_input`, `PaneOutcome::Toast`, `BulkState.domains`, and `EditTarget::BulkDomains` usages don't exist yet.

- [ ] **Step 4: Add `PaneOutcome::Toast` + field plumbing in `panes/mod.rs`** — update the enum (lines 20-26):

```rust
#[derive(Debug)]
pub enum PaneOutcome {
    None,
    Fetch(FetchReq),
    Action(Action),
    EditField(EditTarget),
    /// Show a transient toast (App calls `set_toast`).
    Toast { tone: &'static str, msg: &'static str },
}
```

In `apply_field` (the match at lines 69-97), add a `BulkDomains` arm before the `_`:

```rust
            EditTarget::BulkDomains => {
                self.bulk.domains = v;
                vec![]
            }
```

In `field_value` (lines 99-107), add before the `_`:

```rust
            EditTarget::BulkDomains => self.bulk.domains.clone(),
```

- [ ] **Step 5: Rewrite `panes/bulk.rs` state + parser + keys.** Replace `SAMPLES` (lines 11-33) — delete it. Replace `BulkState` (lines 35-52) and its impl down through `handle_key` with:

```rust
/// State for the Bulk lens — op selection, entered domains, rows, run status.
#[derive(Default)]
pub struct BulkState {
    /// Index into `OPS`.
    pub op_idx: usize,
    /// Raw domains text entered/pasted by the user (space/comma/newline separated).
    pub domains: String,
    /// Accumulated results for the current run.
    pub rows: Vec<BulkResult>,
    /// True while a bulk task is in flight.
    pub running: bool,
    /// Optional status note (e.g. error from file load).
    pub note: Option<String>,
    /// Generation counter — callbacks from superseded runs are dropped.
    pub gen: u64,
    /// Expected row count for the current run (drives the gauge denominator).
    pub total: usize,
}

/// Parse a free-form domains blob (typed or pasted) into a capped list. Same
/// filtering as `parse_domains_from_file` (trim, skip blank/`#`, require a dot)
/// but split on whitespace / comma / newline so single- or multi-line input works.
pub fn parse_domains_input(s: &str) -> Vec<String> {
    s.split([',', ' ', '\t', '\n', '\r'])
        .map(str::trim)
        .filter(|t| !t.is_empty() && !t.starts_with('#') && t.contains('.'))
        .map(str::to_string)
        .take(50)
        .collect()
}

impl BulkState {
    /// Current operation name.
    pub fn op(&self) -> &str {
        OPS[self.op_idx]
    }

    /// Append a result row (called from `App::update` on `Msg::BulkStep`).
    pub fn push(&mut self, r: BulkResult) {
        self.rows.push(r);
    }

    /// Handle a key event for the Bulk pane. `Some(_)` = consumed; never `Esc`.
    pub fn handle_key(&mut self, key: KeyEvent) -> Option<PaneOutcome> {
        match key.code {
            // Cycle operation
            KeyCode::Char('o') => {
                self.op_idx = (self.op_idx + 1) % OPS.len();
                Some(PaneOutcome::None)
            }
            // Edit the domains list
            KeyCode::Char('d') => Some(PaneOutcome::EditField(EditTarget::BulkDomains)),
            // Start a run with the entered domains
            KeyCode::Char('r') | KeyCode::Enter => {
                let domains = parse_domains_input(&self.domains);
                if domains.is_empty() {
                    return Some(PaneOutcome::Toast {
                        tone: "info",
                        msg: "enter domains first (d)",
                    });
                }
                self.rows.clear();
                self.running = true;
                self.note = None;
                self.gen += 1;
                self.total = domains.len();
                Some(PaneOutcome::Action(Action::StartBulk(BulkParams {
                    op: self.op().to_string(),
                    domains,
                    gen: self.gen,
                })))
            }
            // Open file-path field
            KeyCode::Char('f') => Some(PaneOutcome::EditField(EditTarget::BulkPath)),
            // Export results to CSV
            KeyCode::Char('e') => {
                if self.rows.is_empty() {
                    Some(PaneOutcome::None)
                } else {
                    let path = format!("seer-bulk-{}.csv", self.op());
                    let contents = self.to_csv();
                    Some(PaneOutcome::Action(Action::WriteCsv { path, contents }))
                }
            }
            _ => None,
        }
    }

    /// Build a CSV string from the current rows.
    pub fn to_csv(&self) -> String {
        let mut out = String::from("domain,success,error,duration_ms\n");
        for r in &self.rows {
            let domain = op_domain(&r.operation);
            let err = r.error.as_deref().unwrap_or("").replace(',', ";");
            out.push_str(&format!(
                "{},{},{},{}\n",
                domain, r.success, err, r.duration_ms
            ));
        }
        out
    }
}
```

Then fix the surviving tests in `panes/bulk.rs`, decisively:
- In `default_state_is_zeroed`: replace `assert_eq!(s.source_idx, 0);` with `assert!(s.domains.is_empty());`.
- **Delete** these three tests outright (replaced by Step 2's new ones): `t_cycles_source`, `r_sets_running_and_returns_start_bulk`, `enter_also_starts_run`.
- **Keep unchanged**: `o_cycles_op`, `f_returns_edit_field_bulk_path`, `e_with_no_rows_returns_pane_outcome_none`, `e_with_rows_returns_write_csv`, `esc_returns_none`, `to_csv_produces_header_and_row`, `to_csv_escapes_commas_in_error`, `op_domain_works_for_all_variants`.

- [ ] **Step 6: Route `BulkDomains` + handle `Toast` in `app.rs`.** In `apply_field` (lines 416-419) add `BulkDomains` to the delegated arm:

```rust
            EditTarget::FollowInterval
            | EditTarget::FollowCount
            | EditTarget::BulkPath
            | EditTarget::BulkDomains => {
                self.panes.apply_field(target, value, self.domain.clone())
            }
```

In `apply_pane_outcome` (lines 508-522) add a `Toast` arm:

```rust
            PaneOutcome::Toast { tone, msg } => {
                self.set_toast(tone, msg);
                vec![]
            }
```

- [ ] **Step 7: Rewrite the Bulk renderer top panel in `lenses/bulk.rs`.** Change the import (line 9) to drop `SAMPLES`:

```rust
use crate::tui::panes::bulk::{op_domain, BulkState, OPS};
```

Change the signature (line 13) and replace the `source_line`/gauge/hints block. New signature + the source→domains line + hints:

```rust
pub fn render(f: &mut Frame, area: Rect, theme: &Theme, bulk: &BulkState, editing: Option<&str>) {
```

Replace the `source_line` (lines 45-54) with a domains line that shows the live buffer when editing, else the parsed count + preview:

```rust
    let domains_line = if let Some(buf) = editing {
        Line::from(vec![
            Span::styled("domains: ", Style::default().fg(theme.overlay0)),
            Span::styled(format!("{buf}▏"), Style::default().fg(theme.text)),
        ])
    } else {
        let parsed = crate::tui::panes::bulk::parse_domains_input(&bulk.domains);
        if parsed.is_empty() {
            Line::from(Span::styled(
                "domains: none — press d to enter",
                Style::default().fg(theme.overlay0),
            ))
        } else {
            let preview = parsed
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            let more = if parsed.len() > 3 { ", …" } else { "" };
            Line::from(vec![
                Span::styled("domains: ", Style::default().fg(theme.overlay0)),
                Span::styled(parsed.len().to_string(), Style::default().fg(theme.sky)),
                Span::styled(
                    format!(" · {preview}{more}"),
                    Style::default().fg(theme.overlay0),
                ),
            ])
        }
    };
```

Update the references: rename `source_line` → `domains_line` in the `lines` vec (line 92), and change the hints string (line 88) to:

```rust
    let hints = "d domains  ·  o op  ·  r run  ·  f file  ·  e export";
```

Update the empty-results placeholder text (lines 110-112) to:

```rust
                "enter domains (d) or load a file (f), then r to run",
```

- [ ] **Step 8: Update `lenses/bulk.rs` tests for the new signature.** Make these exact changes to the three existing tests:
  - `renders_domain_in_results_table`: change the draw call to `render(f, f.area(), &theme, &bulk, None)`. Keep the `text.contains("rust-lang.org")` assertion.
  - `renders_idle_placeholder_when_empty`: change the draw call to `render(f, f.area(), &theme, &bulk, None)` **and** change the assertion from `text.contains("no results")` to `text.contains("enter domains")` (the placeholder text changed in Step 7).
  - `renders_op_chips_row`: change only the draw call to `render(f, f.area(), &theme, &bulk, None)`; the `"lookup"`/`"status"` op-chip assertions are unchanged.

  Then add this new test:

```rust
    #[test]
    fn empty_state_prompts_for_domains() {
        let theme = Theme::frappe();
        let bulk = BulkState::default();
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| render(f, f.area(), &theme, &bulk, None))
            .unwrap();
        let text = buf_text(&terminal);
        assert!(text.contains("press d to enter"), "prompts for domains");
        assert!(text.contains("d domains"), "shows the new hint row");
    }
```

- [ ] **Step 9: Add the bulk case in `render.rs::main_pane`** — extend the human-view match with a `bulk` arm:

```rust
            "bulk" => {
                lenses::bulk::render(
                    f,
                    content,
                    theme,
                    &app.panes.bulk,
                    field_buf(&app.input_mode, EditTarget::BulkDomains),
                );
                return;
            }
```

- [ ] **Step 10: Remove the `bulk` dispatch arm** in `lenses/mod.rs` — delete line 246:

```rust
        "bulk" => bulk::render(f, area, theme, &panes.bulk),
```

- [ ] **Step 11: Run the bulk tests + full suite**

Run: `cargo test -p seer-cli parse_domains_input_splits_and_filters parse_domains_input_caps_at_50 d_opens_domains_field r_with_empty_domains_toasts_and_does_not_run r_with_domains_starts_run_with_parsed_list empty_state_prompts_for_domains`
Expected: PASS

Run: `cargo test -p seer-cli`
Expected: PASS.

- [ ] **Step 12: Commit**

```bash
git add seer-cli/src/tui/action.rs seer-cli/src/tui/panes/bulk.rs seer-cli/src/tui/panes/mod.rs seer-cli/src/tui/app.rs seer-cli/src/tui/lenses/bulk.rs seer-cli/src/tui/render.rs seer-cli/src/tui/lenses/mod.rs
git commit -m "feat(tui): Bulk lens accepts typed/pasted domains (drop presets)"
```

---

## Task 6: Final verification

**Files:** none (verification only).

- [ ] **Step 1: Full workspace test**

Run: `cargo test --workspace`
Expected: PASS (hermetic; live-network tests remain `#[ignore]`).

- [ ] **Step 2: Lint (CI gate)**

Run: `cargo clippy --workspace -- -D warnings`
Expected: no warnings. (Watch for unused imports after removing dispatch arms — e.g. if `placeholder` or a lens module becomes unused, it won't, since all stay referenced.)

- [ ] **Step 3: Format (CI gate)**

Run: `cargo fmt --all -- --check`
Expected: clean. If it reports diffs, run `cargo fmt --all` and amend.

- [ ] **Step 4: Manual smoke (documented, not automated — no TTY in CI)**

```bash
cargo run --release -p seer-cli -- tui example.com
```
Verify by hand: Diff shows the `A ⇄ B` bar and `e` lets you type B; Bulk shows the domains prompt, `d` opens the field, paste a list, `r` runs; Follow renders its monitor; after a couple of lookups, History lists them.

- [ ] **Step 5: Commit any fmt fixups** (if Step 3 changed files)

```bash
git add -A
git commit -m "style(tui): rustfmt"
```

---

## Notes for the implementer

- **`seer-cli` is a binary crate.** `cargo test -p seer-cli --lib` errors with "no library targets". Use `cargo test -p seer-cli <name>`.
- **Clippy runs without `--all-targets`** in CI, so test-only `unwrap()` is fine, but keep non-test code `unwrap()`-free.
- **Removing a dispatch arm** (`diff`/`bulk`/`follow` in `lenses/mod.rs`) makes those keys fall to `other => placeholder::render`, which is unreachable because the dispatcher only runs on `Loaded` and these lenses never load. This is intentional — `main_pane` owns them now.
- **`Esc` must never be swallowed** by a pane `handle_key` — all the new arms return `None`/explicit outcomes for owned keys only, preserving the existing contract.
- **History recording is detached** (`spawn_blocking` not awaited) so the Overview result renders immediately. Not unit-tested (network path); verified via the manual smoke step.
```

