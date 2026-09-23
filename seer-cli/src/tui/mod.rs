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
#[cfg(test)]
mod test_util;
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
use seer_core::Watchlist;

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

/// Restore the terminal on a panic in the draw loop, unwinding or not (a hook
/// also runs under `panic = "abort"`); chains to `main`'s raw-mode hook.
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
    let mut app = App::new(domain);
    // Seed session defaults (output format + theme) from ~/.seer/config.toml
    // so the TUI honors the user's config like the CLI subcommands do.
    // tui_theme() clamps to a known name (unknown → "frappe"), so the theme
    // swap cannot fail; App keeps Frappé if it somehow did.
    let config = seer_core::SeerConfig::load();
    app.apply_config(&config);
    app.set_theme_by_name(config.tui_theme());
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
        handle_action(action, &tx, &config, &mut follow_cancel, &mut bulk_cancel);
    }

    terminal.draw(|f| render::view(f, &app, app.theme()))?;

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
            handle_action(action, &tx, &config, &mut follow_cancel, &mut bulk_cancel);
        }

        if app.should_quit {
            break;
        }
        terminal.draw(|f| render::view(f, &app, app.theme()))?;
    }
    Ok(())
}

/// The operation list for a TUI bulk run, through the CLI's own mapping. The
/// presets are `ops::BULK_OPS`, so this only fails on a programming error;
/// `dig`/`prop` query `A` records (the lens has no record-type input).
fn bulk_operations(
    op: &str,
    domains: &[String],
) -> Result<Vec<seer_core::bulk::BulkOperation>, String> {
    crate::ops::build_bulk_operations(op, domains, seer_core::RecordType::A)
}

/// Ends a bulk run that could not start, telling the user why.
fn bulk_not_started(tx: &tokio::sync::mpsc::UnboundedSender<Msg>, msg: String, gen: u64) {
    let _ = tx.send(Msg::Toast { tone: "fail", msg });
    let _ = tx.send(Msg::BulkDone { gen });
}

/// Stream a bulk batch's results over `tx`, then a terminal `BulkDone`.
async fn run_bulk(
    tx: tokio::sync::mpsc::UnboundedSender<Msg>,
    executor: seer_core::BulkExecutor,
    operations: Vec<seer_core::bulk::BulkOperation>,
    gen: u64,
) {
    let cb_tx = tx.clone();
    let cb: seer_core::bulk::ResultCallback = Box::new(move |r: &seer_core::bulk::BulkResult| {
        let _ = cb_tx.send(Msg::BulkStep {
            gen,
            result: Box::new(r.clone()),
        });
    });
    let _ = executor.execute_streaming(operations, cb).await;
    let _ = tx.send(Msg::BulkDone { gen });
}

/// Run a bulk batch in the background. Returns the spawned task's abort handle
/// so the run can be cancelled.
fn spawn_bulk_run(
    tx: &tokio::sync::mpsc::UnboundedSender<Msg>,
    executor: seer_core::BulkExecutor,
    operations: Vec<seer_core::bulk::BulkOperation>,
    gen: u64,
) -> tokio::task::AbortHandle {
    tokio::spawn(run_bulk(tx.clone(), executor, operations, gen)).abort_handle()
}

/// Read and validate a bulk domains file with the CLI's guards: tilde
/// expansion, regular files only (a FIFO would block the read forever) under
/// the size cap, and the same non-empty / `MAX_BULK_DOMAINS` domain-count
/// limits — an over-long list is rejected rather than silently truncated.
fn load_bulk_file(path: &str) -> Result<Vec<String>, String> {
    let path = crate::utils::expand_tilde(path);
    let content = crate::utils::read_bulk_input(&path)?;
    crate::ops::parse_bulk_domains(&content)
}

/// Apply a watchlist edit, returning the toast to show for anything the user
/// would otherwise not notice (an invalid domain, a duplicate). `None` means
/// the refreshed lens speaks for itself.
fn mutate_watchlist(
    wl: &mut Watchlist,
    add: Option<&str>,
    remove: Option<&str>,
) -> Option<(&'static str, String)> {
    let mut notice = None;
    if let Some(a) = add {
        notice = match wl.add(a) {
            Ok(true) => None,
            Ok(false) => Some(("info", format!("{a} is already on the watchlist"))),
            Err(e) => Some(("fail", format!("cannot watch {a}: {e}"))),
        };
    }
    if let Some(r) = remove {
        if !wl.remove(r) {
            notice = Some(("info", format!("{r} is not on the watchlist")));
        }
    }
    notice
}

/// Execute a side-effecting Action returned by `App::update`.
fn handle_action(
    action: Action,
    tx: &tokio::sync::mpsc::UnboundedSender<Msg>,
    config: &seer_core::SeerConfig,
    follow_cancel: &mut Option<tokio::sync::watch::Sender<bool>>,
    bulk_cancel: &mut Option<tokio::task::AbortHandle>,
) {
    match action {
        Action::Quit => {}
        Action::Fetch { req, gen } => {
            let tx = tx.clone();
            let lens = req.lens_key().to_string();
            let config = config.clone();
            tokio::spawn(async move {
                let result = data::fetch(req, &config).await;
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
            let config = config.clone();
            tokio::spawn(async move {
                // File I/O is blocking — run in spawn_blocking to keep the async loop free.
                let notice = tokio::task::spawn_blocking(move || {
                    let mut wl = Watchlist::load();
                    let notice = mutate_watchlist(&mut wl, add.as_deref(), remove.as_deref());
                    match wl.save() {
                        Ok(()) => notice,
                        Err(e) => Some(("fail", format!("failed to save watchlist: {e}"))),
                    }
                })
                .await
                .ok()
                .flatten();
                // An invalid domain was previously dropped without a word.
                if let Some((tone, msg)) = notice {
                    let _ = tx.send(Msg::Toast { tone, msg });
                }
                // Refresh the watchlist lens after mutation. `gen` is the watch
                // lens's current fetch generation (bumped by App when emitting
                // this action), so the refresh survives the staleness guard.
                let result = data::fetch(action::FetchReq::Watch, &config).await;
                let _ = tx.send(Msg::Data {
                    lens: "watch".into(),
                    gen,
                    result,
                });
            });
        }
        Action::HistoryClear { gen } => {
            let tx = tx.clone();
            let config = config.clone();
            tokio::spawn(async move {
                // Best-effort: the refreshed lens shows whatever remains.
                let _ = crate::ops::clear_history().await;
                // Refresh the history lens after clearing. `gen` is the history
                // lens's current fetch generation (see WatchMutate above).
                let result = data::fetch(action::FetchReq::History, &config).await;
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
            // Honor the config's DNS timeout and nameserver, like the CLI and
            // REPL `follow` (and the TUI's own DNS lens) do.
            let follower = seer_core::DnsFollower::from_config(config);
            let nameserver = config.nameserver.clone();
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
                    let _ = follower
                        .follow(
                            &p.domain,
                            seer_core::RecordType::A,
                            nameserver.as_deref(),
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
            match bulk_operations(&p.op, &p.domains) {
                Ok(operations) => {
                    // from_config: honor ~/.seer/config.toml (concurrency,
                    // rate limit, timeouts) like `seer bulk` does.
                    let executor = seer_core::BulkExecutor::from_config(config);
                    *bulk_cancel = Some(spawn_bulk_run(tx, executor, operations, p.gen));
                }
                Err(msg) => bulk_not_started(tx, msg, p.gen),
            }
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
            let executor = seer_core::BulkExecutor::from_config(config);
            // The file read is blocking and the run must own the abort handle,
            // so the whole load+run lives in one task; we store its handle.
            let handle = tokio::spawn(async move {
                let loaded = tokio::task::spawn_blocking(move || load_bulk_file(&path))
                    .await
                    .unwrap_or_else(|e| Err(format!("failed to read bulk file: {e}")));
                match loaded.and_then(|domains| bulk_operations(&op, &domains)) {
                    Ok(operations) => run_bulk(tx, executor, operations, gen).await,
                    Err(msg) => bulk_not_started(&tx, msg, gen),
                }
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
                // A Toast, not a CopyResult: the copy handler prefixes
                // "copied ", which read as "copied wrote seer-bulk-….csv".
                let (tone, msg) = if ok {
                    ("ok", format!("wrote {path}"))
                } else {
                    ("fail", format!("failed to write {path}"))
                };
                let _ = tx.send(Msg::Toast { tone, msg });
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watchlist_add_of_an_invalid_domain_reports_why() {
        let mut wl = Watchlist::default();
        let notice = mutate_watchlist(&mut wl, Some("not a domain!"), None);
        assert!(
            matches!(notice, Some(("fail", ref m)) if m.contains("not a domain!")),
            "invalid add must surface an error toast, got {notice:?}"
        );
        assert!(wl.domains.is_empty());
    }

    #[test]
    fn watchlist_add_and_duplicate_add() {
        let mut wl = Watchlist::default();
        assert_eq!(mutate_watchlist(&mut wl, Some("example.com"), None), None);
        assert_eq!(wl.domains, vec!["example.com".to_string()]);
        assert!(matches!(
            mutate_watchlist(&mut wl, Some("example.com"), None),
            Some(("info", _))
        ));
    }

    #[test]
    fn bulk_file_load_rejects_missing_and_non_regular_paths() {
        // A missing path errors with a reason (was: silent "not found").
        let missing = std::env::temp_dir().join("seer-tui-no-such-bulk-file.txt");
        assert!(load_bulk_file(missing.to_str().unwrap()).is_err());
        // A directory is not a regular file — read_bulk_input's guard
        // (the same one that stops a FIFO from blocking the read forever).
        let dir = std::env::temp_dir();
        let err = load_bulk_file(dir.to_str().unwrap()).unwrap_err();
        assert!(err.contains("not a regular file"), "got: {err}");
    }

    #[test]
    fn bulk_file_load_enforces_the_cli_domain_cap_instead_of_truncating() {
        let dir = std::env::temp_dir().join(format!("seer-tui-bulk-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("domains.txt");

        std::fs::write(&path, "a.com\nb.com\n").unwrap();
        assert_eq!(
            load_bulk_file(path.to_str().unwrap()).unwrap(),
            vec!["a.com".to_string(), "b.com".to_string()],
        );

        // More than 50 (the old silent truncation point) but within the CLI's
        // MAX_BULK_DOMAINS is accepted in full.
        let many: String = (0..60).map(|i| format!("d{i}.com\n")).collect();
        std::fs::write(&path, many).unwrap();
        assert_eq!(load_bulk_file(path.to_str().unwrap()).unwrap().len(), 60);

        // Over the cap is rejected with a message, not truncated.
        let too_many: String = (0..=crate::ops::MAX_BULK_DOMAINS)
            .map(|i| format!("d{i}.com\n"))
            .collect();
        std::fs::write(&path, too_many).unwrap();
        let err = load_bulk_file(path.to_str().unwrap()).unwrap_err();
        assert!(err.contains("maximum"), "got: {err}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
