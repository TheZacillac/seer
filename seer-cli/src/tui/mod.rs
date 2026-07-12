//! Full-screen ratatui TUI for Seer. Launched via `seer tui [domain]`.
//!
//! `run()` sets up the terminal (raw mode + alternate screen + panic-restore
//! hook) and drives an async `tokio::select!` loop over crossterm input, a
//! results channel, and an animation tick. `App` (in `app`) is the pure state
//! machine; `render` draws it; `data` dispatches lookups to `seer-core`.

mod action;
mod app;
mod command;
mod data;
mod event;
mod filter;
mod lenses;
mod line_editor;
mod panes;
mod render;
mod theme;
mod widgets;

use std::io::{self, Stdout};
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{DisableBracketedPaste, EnableBracketedPaste, EventStream};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use futures::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use action::{Action, Msg};
use app::App;
use seer_core::{LookupHistory, Watchlist};
use theme::Theme;

use crate::clipboard;

type Term = Terminal<CrosstermBackend<Stdout>>;

/// Entry point for the `seer tui` subcommand.
pub async fn run(domain: Option<String>) -> Result<()> {
    let mut terminal = setup_terminal()?;
    install_panic_hook();
    let res = run_loop(&mut terminal, domain).await;
    restore_terminal(&mut terminal)?;
    res
}

fn setup_terminal() -> Result<Term> {
    enable_raw_mode()?;
    // From here on, raw mode is active. If any later step fails, `?` would
    // return without disabling it, leaving the user's shell wedged (no echo /
    // no line buffering). Undo the terminal state we entered on any error,
    // mirroring the panic-hook cleanup (best-effort).
    setup_terminal_after_raw().inspect_err(|_| {
        let _ = execute!(
            io::stdout(),
            DisableBracketedPaste,
            LeaveAlternateScreen,
            crossterm::cursor::Show
        );
        let _ = disable_raw_mode();
    })
}

fn setup_terminal_after_raw() -> Result<Term> {
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableBracketedPaste)?;
    Ok(Terminal::new(CrosstermBackend::new(stdout))?)
}

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

/// Restore the terminal even if a panic unwinds through the draw loop.
///
/// Mirrors [`restore_terminal`], including re-showing the cursor: ratatui hides
/// the cursor on every `draw`, so without `cursor::Show` a panic after the first
/// frame would return the user to a working shell with an invisible cursor
/// (issue #60).
fn install_panic_hook() {
    let original = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(
            io::stdout(),
            DisableBracketedPaste,
            LeaveAlternateScreen,
            crossterm::cursor::Show
        );
        original(info);
    }));
}

async fn run_loop(terminal: &mut Term, domain: Option<String>) -> Result<()> {
    let theme = Theme::frappe();
    let mut app = App::new(domain);
    // Seed session defaults (output format) from ~/.seer/config.toml so the TUI
    // honors the user's config like the CLI subcommands do.
    app.apply_config(&seer_core::SeerConfig::load());
    // Cancel token for the in-flight live-follow run. Held here (not in the pure
    // App) because it owns I/O: a new run or a stop signals the old background
    // DNS loop so restarts don't stack live tasks.
    let mut follow_cancel: Option<tokio::sync::watch::Sender<bool>> = None;
    // Abort handle for the in-flight bulk run. A new run or an explicit stop
    // aborts the prior task so restarts don't stack concurrent batches.
    let mut bulk_cancel: Option<tokio::task::AbortHandle> = None;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Msg>();
    let mut events = EventStream::new();
    let mut tick = tokio::time::interval(Duration::from_millis(100));

    for action in app.take_startup_actions() {
        handle_action(action, &tx, &mut follow_cancel, &mut bulk_cancel);
    }

    terminal.draw(|f| render::view(f, &app, &theme))?;

    loop {
        let msg = tokio::select! {
            maybe = events.next() => match maybe {
                Some(Ok(ev)) => Msg::Input(ev),
                _ => continue,
            },
            _ = tick.tick() => Msg::Tick,
            Some(m) = rx.recv() => m,
        };

        let actions = app.update(msg);
        for action in actions {
            handle_action(action, &tx, &mut follow_cancel, &mut bulk_cancel);
        }

        if app.should_quit {
            break;
        }
        terminal.draw(|f| render::view(f, &app, &theme))?;
    }
    Ok(())
}

/// Build the bulk operation list for a TUI op preset via the shared
/// `ops::bulk_operation_for` mapping (so new operations land here for free).
/// `dig`/`prop` default to an `A` record (matching the previous behaviour);
/// unknown presets fall back to the smart lookup.
fn build_bulk_operations(op: &str, domains: Vec<String>) -> Vec<seer_core::bulk::BulkOperation> {
    use seer_core::RecordType;
    // Resolve the preset once (with a throwaway domain); unknown → "lookup".
    let op = if crate::ops::bulk_operation_for(op, String::new(), RecordType::A).is_some() {
        op
    } else {
        "lookup"
    };
    domains
        .into_iter()
        .filter_map(|domain| crate::ops::bulk_operation_for(op, domain, RecordType::A))
        .collect()
}

/// Run a bulk batch, streaming each result over `tx` as it completes and a
/// terminal `BulkDone`. Returns the spawned task's abort handle so the run can
/// be cancelled.
fn spawn_bulk_run(
    tx: &tokio::sync::mpsc::UnboundedSender<Msg>,
    operations: Vec<seer_core::bulk::BulkOperation>,
    gen: u64,
) -> tokio::task::AbortHandle {
    let tx = tx.clone();
    let handle = tokio::spawn(async move {
        let ex = seer_core::BulkExecutor::new();
        let cb_tx = tx.clone();
        let cb: seer_core::bulk::ResultCallback =
            Box::new(move |r: &seer_core::bulk::BulkResult| {
                let _ = cb_tx.send(Msg::BulkStep {
                    gen,
                    result: Box::new(r.clone()),
                });
            });
        let _ = ex.execute_streaming(operations, cb).await;
        let _ = tx.send(Msg::BulkDone { gen });
    });
    handle.abort_handle()
}

/// Execute a side-effecting Action returned by `App::update`.
fn handle_action(
    action: Action,
    tx: &tokio::sync::mpsc::UnboundedSender<Msg>,
    follow_cancel: &mut Option<tokio::sync::watch::Sender<bool>>,
    bulk_cancel: &mut Option<tokio::task::AbortHandle>,
) {
    match action {
        Action::Quit => {}
        Action::Fetch { req, gen } => {
            let tx = tx.clone();
            let lens = req.lens_key().to_string();
            tokio::spawn(async move {
                let result = data::fetch(req).await;
                let _ = tx.send(Msg::Data { lens, gen, result });
            });
        }
        Action::Copy { text, label } => {
            let ok = clipboard::copy(&text).is_ok();
            // On success the label names the copied content ("copied <label>");
            // on failure the CopyResult handler shows the label verbatim, so
            // substitute a clipboard-specific error message.
            let label = if ok {
                label
            } else {
                "copy failed — clipboard unavailable".to_string()
            };
            let _ = tx.send(Msg::CopyResult { ok, label });
        }
        Action::WatchMutate { add, remove, gen } => {
            let tx = tx.clone();
            tokio::spawn(async move {
                // File I/O is blocking — run in spawn_blocking to keep the async loop free.
                tokio::task::spawn_blocking(move || {
                    let mut wl = Watchlist::load();
                    if let Some(a) = add {
                        let _ = wl.add(&a);
                    }
                    if let Some(r) = remove {
                        wl.remove(&r);
                    }
                    let _ = wl.save();
                })
                .await
                .ok();
                // Refresh the watchlist lens after mutation. `gen` is the watch
                // lens's current fetch generation (bumped by App when emitting
                // this action), so the refresh survives the staleness guard.
                let result = data::fetch(action::FetchReq::Watch).await;
                let _ = tx.send(Msg::Data {
                    lens: "watch".into(),
                    gen,
                    result,
                });
            });
        }
        Action::HistoryClear { gen } => {
            let tx = tx.clone();
            tokio::spawn(async move {
                tokio::task::spawn_blocking(|| {
                    let mut h = LookupHistory::load();
                    h.clear();
                    let _ = h.save();
                })
                .await
                .ok();
                // Refresh the history lens after clearing. `gen` is the history
                // lens's current fetch generation (see WatchMutate above).
                let result = data::fetch(action::FetchReq::History).await;
                let _ = tx.send(Msg::Data {
                    lens: "history".into(),
                    gen,
                    result,
                });
            });
        }
        Action::StartFollow(p) => {
            // Cancel any prior run so restarts don't stack live DNS loops, then
            // arm a fresh cancel token for this run.
            if let Some(prev) = follow_cancel.take() {
                let _ = prev.send(true);
            }
            let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
            *follow_cancel = Some(cancel_tx);
            let tx = tx.clone();
            let gen = p.gen;
            tokio::spawn(async move {
                let interval_minutes = p.interval_secs as f64 / 60.0;
                if let Ok(config) = seer_core::FollowConfig::new(p.iterations, interval_minutes) {
                    let config = config.with_changes_only(false);
                    let cb_tx = tx.clone();
                    let cb: seer_core::dns::FollowProgressCallback =
                        std::sync::Arc::new(move |it: &seer_core::dns::FollowIteration| {
                            let _ = cb_tx.send(Msg::FollowStep {
                                gen,
                                it: Box::new(it.clone()),
                            });
                        });
                    let _ = seer_core::DnsFollower::new()
                        .follow(
                            &p.domain,
                            seer_core::RecordType::A,
                            None,
                            config,
                            Some(cb),
                            Some(cancel_rx),
                        )
                        .await;
                }
                let _ = tx.send(Msg::FollowDone { gen });
            });
        }
        Action::StopFollow => {
            // Signal the in-flight follow's cancel token (if any) so its
            // background DNS loop stops instead of running to completion.
            if let Some(prev) = follow_cancel.take() {
                let _ = prev.send(true);
            }
        }
        Action::StartBulk(p) => {
            // Cancel any prior run so restarts don't stack concurrent batches.
            if let Some(prev) = bulk_cancel.take() {
                prev.abort();
            }
            let operations = build_bulk_operations(&p.op, p.domains);
            *bulk_cancel = Some(spawn_bulk_run(tx, operations, p.gen));
        }
        Action::StopBulk => {
            if let Some(prev) = bulk_cancel.take() {
                prev.abort();
            }
        }
        Action::StartBulkFromFile { op, path, gen } => {
            // Cancel any prior run before starting the file-driven one.
            if let Some(prev) = bulk_cancel.take() {
                prev.abort();
            }
            let tx = tx.clone();
            // The file read is blocking and the run must own the abort handle,
            // so the whole load+run lives in one task; we store its handle.
            let handle = tokio::spawn(async move {
                let read_result =
                    tokio::task::spawn_blocking(move || std::fs::read_to_string(&path)).await;
                let Ok(Ok(content)) = read_result else {
                    let _ = tx.send(Msg::CopyResult {
                        ok: false,
                        label: "bulk file not found".into(),
                    });
                    let _ = tx.send(Msg::BulkDone { gen });
                    return;
                };
                let mut domains = seer_core::bulk::parse_domains_from_file(&content);
                // Cap to 50 to match CLI bulk limit
                domains.truncate(50);
                let operations = build_bulk_operations(&op, domains);
                let ex = seer_core::BulkExecutor::new();
                let cb_tx = tx.clone();
                let cb: seer_core::bulk::ResultCallback =
                    Box::new(move |r: &seer_core::bulk::BulkResult| {
                        let _ = cb_tx.send(Msg::BulkStep {
                            gen,
                            result: Box::new(r.clone()),
                        });
                    });
                let _ = ex.execute_streaming(operations, cb).await;
                let _ = tx.send(Msg::BulkDone { gen });
            });
            *bulk_cancel = Some(handle.abort_handle());
        }
        Action::WriteCsv { path, contents } => {
            let tx = tx.clone();
            tokio::spawn(async move {
                let path_clone = path.clone();
                let ok = tokio::task::spawn_blocking(move || std::fs::write(&path_clone, contents))
                    .await
                    .map(|r| r.is_ok())
                    .unwrap_or(false);
                let label = if ok {
                    format!("wrote {path}")
                } else {
                    format!("failed to write {path}")
                };
                let _ = tx.send(Msg::CopyResult { ok, label });
            });
        }
    }
}
