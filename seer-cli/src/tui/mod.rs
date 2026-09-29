//! Full-screen ratatui TUI for Seer. Launched via `seer tui [domain]`.
//!
//! `run()` sets up the terminal (raw mode + alternate screen + panic-restore
//! hook) and drives an async `tokio::select!` loop over crossterm input, a
//! results channel, and an animation tick. `App` (in `app`) is the pure state
//! machine; `render` draws it (only when it changed, or while something
//! animates); `data` runs lookups through the CLI's single-shot pipeline.
//! Every background task is owned by [`Tasks`], which aborts it when its
//! result is superseded and when the loop ends.

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

use std::collections::HashMap;
use std::io::{self, Stdout, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use crossterm::event::{DisableBracketedPaste, EnableBracketedPaste, EventStream};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use futures::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::AbortHandle;

use action::{Action, FetchReq, LensKey, Msg};
use app::App;
use seer_core::{SeerConfig, Watchlist};

use crate::clipboard;
use crate::query::Clients;

type Term = Terminal<CrosstermBackend<Stdout>>;

/// Entry point for the `seer tui` subcommand.
pub async fn run(domain: Option<String>) -> Result<()> {
    let mut terminal = setup_terminal()?;
    install_panic_hook();
    let res = run_loop(&mut terminal, domain).await;
    let restored = restore_terminal(&mut terminal);
    // The loop's own error explains the exit; a restore failure is reported
    // only when there is none.
    res.and(restored)
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

/// Undo `setup_terminal`. Every step runs even when an earlier one fails —
/// stopping at a failed `disable_raw_mode` would strand the user on the
/// alternate screen with a hidden cursor — and the first failure is returned.
fn restore_terminal(terminal: &mut Term) -> Result<()> {
    let raw = disable_raw_mode();
    let screen = execute!(
        terminal.backend_mut(),
        DisableBracketedPaste,
        LeaveAlternateScreen
    );
    let cursor = terminal.show_cursor();
    raw?;
    screen?;
    cursor?;
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
    // The theme comes from `[tui] theme` in ~/.seer/config.toml. tui_theme()
    // clamps to a known name (unknown → "frappe"), so the swap cannot fail;
    // App keeps Frappé if it somehow did. The CLI's `output_format` is not
    // applied: the TUI always opens on its rendered view (`r` toggles raw).
    let config = SeerConfig::load();
    app.set_theme_by_name(config.tui_theme());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Msg>();
    let mut tasks = Tasks::new(tx, config);
    let mut events = EventStream::new();
    let mut tick = tokio::time::interval(Duration::from_millis(100));

    for action in app.take_startup_actions() {
        tasks.handle(action);
    }

    terminal.draw(|f| render::view(f, &app, app.theme()))?;

    loop {
        let msg = tokio::select! {
            maybe = events.next() => match maybe {
                Some(Ok(ev)) => Msg::Input(ev),
                // A read error or the end of the input stream will not clear
                // up on the next poll; retrying would spin at full CPU.
                Some(Err(e)) => return Err(e.into()),
                None => return Err(anyhow!("terminal input stream closed")),
            },
            _ = tick.tick() => Msg::Tick,
            // `tasks` holds a sender for the whole loop, so this never ends.
            Some(m) = rx.recv() => m,
        };

        for action in app.update(msg) {
            tasks.handle(action);
        }

        if app.should_quit {
            break;
        }
        if app.take_redraw() {
            terminal.draw(|f| render::view(f, &app, app.theme()))?;
        }
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
fn bulk_not_started(tx: &UnboundedSender<Msg>, msg: String, gen: u64) {
    let _ = tx.send(Msg::Toast { tone: "fail", msg });
    let _ = tx.send(Msg::BulkDone { gen });
}

/// Stream a bulk batch's results over `tx`, then a terminal `BulkDone`.
async fn run_bulk(
    tx: UnboundedSender<Msg>,
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

/// Load, edit and save the watchlist as one cycle under
/// [`crate::ops::STORE_LOCK`], so it cannot interleave with another store
/// edit (a second add, a history record or clear) and lose one of them.
async fn edit_watchlist(
    add: Option<String>,
    remove: Option<String>,
) -> Option<(&'static str, String)> {
    let store = crate::ops::STORE_LOCK.lock().await;
    tokio::task::spawn_blocking(move || {
        let _store = store;
        let mut wl = Watchlist::load();
        let notice = mutate_watchlist(&mut wl, add.as_deref(), remove.as_deref());
        match wl.save() {
            Ok(()) => notice,
            Err(e) => Some(("fail", format!("failed to save watchlist: {e}"))),
        }
    })
    .await
    .unwrap_or_else(|e| Some(("fail", format!("watchlist edit failed: {e}"))))
}

/// Create `name` in `dir`, or the first free `<stem>-<n>.<ext>` beside it,
/// and write `contents` there. `create_new` makes the existence check and
/// the creation one step, so an existing file is never overwritten, even by
/// a race. Returns the path written.
fn write_new_file(dir: &Path, name: &str, contents: &str) -> io::Result<PathBuf> {
    const MAX_SUFFIX: usize = 1000;
    let (stem, ext) = match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem, Some(ext)),
        _ => (name, None),
    };
    for n in 0..MAX_SUFFIX {
        let candidate = match (n, ext) {
            (0, _) => name.to_string(),
            (n, Some(ext)) => format!("{stem}-{n}.{ext}"),
            (n, None) => format!("{stem}-{n}"),
        };
        let path = dir.join(candidate);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                return match file.write_all(contents.as_bytes()) {
                    Ok(()) => Ok(path),
                    Err(e) => {
                        // Leave no truncated export behind.
                        let _ = std::fs::remove_file(&path);
                        Err(e)
                    }
                };
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!("{name} and its first {MAX_SUFFIX} numbered variants all exist"),
    ))
}

/// The background work `run_loop` starts, and the handles that cancel it.
/// Dropping it (when the loop ends, by `:q` or an error) aborts everything
/// still running.
struct Tasks {
    tx: UnboundedSender<Msg>,
    config: SeerConfig,
    /// One client set for the session, shared by every fetch (like the
    /// REPL's), so resolver caches stay warm between lenses.
    clients: Arc<Clients>,
    /// Each lens's in-flight fetch; a newer fetch or a cancel aborts it.
    fetches: HashMap<LensKey, AbortHandle>,
    /// Cancel token for the live-follow run: a new run or a stop signals the
    /// old background DNS loop so restarts don't stack live tasks.
    follow_cancel: Option<tokio::sync::watch::Sender<bool>>,
    /// The bulk run; a new run or an explicit stop aborts it so restarts
    /// don't stack concurrent batches.
    bulk: Option<AbortHandle>,
}

impl Drop for Tasks {
    fn drop(&mut self) {
        self.abort_all();
    }
}

impl Tasks {
    fn new(tx: UnboundedSender<Msg>, config: SeerConfig) -> Self {
        Self {
            tx,
            clients: Arc::new(Clients::from_config(&config)),
            config,
            fetches: HashMap::new(),
            follow_cancel: None,
            bulk: None,
        }
    }

    fn cancel_fetch(&mut self, lens: LensKey) {
        if let Some(prev) = self.fetches.remove(&lens) {
            prev.abort();
        }
    }

    fn stop_follow(&mut self) {
        if let Some(prev) = self.follow_cancel.take() {
            let _ = prev.send(true);
        }
    }

    fn stop_bulk(&mut self) {
        if let Some(prev) = self.bulk.take() {
            prev.abort();
        }
    }

    fn abort_all(&mut self) {
        for (_, fetch) in self.fetches.drain() {
            fetch.abort();
        }
        self.stop_follow();
        self.stop_bulk();
    }

    /// Spawn `req`, sending its result as `Msg::Data` tagged with `gen`.
    fn spawn_fetch(&mut self, req: FetchReq, gen: u64) {
        let lens = req.lens_key();
        let tx = self.tx.clone();
        let clients = Arc::clone(&self.clients);
        let config = self.config.clone();
        let handle = tokio::spawn(async move {
            let result = data::fetch(req, &clients, &config).await;
            let _ = tx.send(Msg::Data { lens, gen, result });
        })
        .abort_handle();
        if let Some(prev) = self.fetches.insert(lens, handle) {
            prev.abort();
        }
    }

    /// Run a store edit, toast its notice, then run `refresh` under `gen`
    /// (the lens's current generation, bumped by `App` when it emitted the
    /// edit, so the refresh survives the staleness guard). Not registered
    /// for cancellation: a store write must finish once started.
    fn spawn_store_edit<F>(&self, refresh: FetchReq, gen: u64, edit: F)
    where
        F: std::future::Future<Output = Option<(&'static str, String)>> + Send + 'static,
    {
        let tx = self.tx.clone();
        let clients = Arc::clone(&self.clients);
        let config = self.config.clone();
        let lens = refresh.lens_key();
        tokio::spawn(async move {
            if let Some((tone, msg)) = edit.await {
                let _ = tx.send(Msg::Toast { tone, msg });
            }
            let result = data::fetch(refresh, &clients, &config).await;
            let _ = tx.send(Msg::Data { lens, gen, result });
        });
    }

    /// Execute a side-effecting Action returned by `App::update`.
    fn handle(&mut self, action: Action) {
        match action {
            Action::Quit => self.abort_all(),
            Action::Fetch { req, gen } => self.spawn_fetch(req, gen),
            Action::CancelFetch(lens) => self.cancel_fetch(lens),
            Action::Copy { text, label } => {
                let ok = clipboard::copy(&text).is_ok();
                // On success the label names the copied content ("copied
                // <label>"); on failure the CopyResult handler shows the label
                // verbatim, so substitute a clipboard-specific error message.
                let label = if ok {
                    label
                } else {
                    "copy failed — clipboard unavailable".to_string()
                };
                let _ = self.tx.send(Msg::CopyResult { ok, label });
            }
            Action::WatchMutate { add, remove, gen } => {
                self.spawn_store_edit(FetchReq::Watch, gen, edit_watchlist(add, remove));
            }
            Action::HistoryClear { gen } => {
                self.spawn_store_edit(FetchReq::History, gen, async {
                    crate::ops::clear_history().await.err().map(|e| ("fail", e))
                });
            }
            Action::StartFollow(p) => self.start_follow(p),
            Action::StopFollow => self.stop_follow(),
            Action::StartBulk(p) => {
                self.stop_bulk();
                match bulk_operations(&p.op, &p.domains) {
                    Ok(operations) => {
                        // from_config: honor ~/.seer/config.toml (concurrency,
                        // rate limit, timeouts) like `seer bulk` does.
                        let executor = seer_core::BulkExecutor::from_config(&self.config);
                        let run = run_bulk(self.tx.clone(), executor, operations, p.gen);
                        self.bulk = Some(tokio::spawn(run).abort_handle());
                    }
                    Err(msg) => bulk_not_started(&self.tx, msg, p.gen),
                }
            }
            Action::StopBulk => self.stop_bulk(),
            Action::StartBulkFromFile { op, path, gen } => {
                self.stop_bulk();
                let tx = self.tx.clone();
                let executor = seer_core::BulkExecutor::from_config(&self.config);
                // The file read is blocking and the run must own the abort
                // handle, so the whole load+run lives in one task.
                let handle = tokio::spawn(async move {
                    let loaded = tokio::task::spawn_blocking(move || load_bulk_file(&path))
                        .await
                        .unwrap_or_else(|e| Err(format!("failed to read bulk file: {e}")));
                    match loaded.and_then(|domains| bulk_operations(&op, &domains)) {
                        Ok(operations) => run_bulk(tx, executor, operations, gen).await,
                        Err(msg) => bulk_not_started(&tx, msg, gen),
                    }
                });
                self.bulk = Some(handle.abort_handle());
            }
            Action::WriteCsv { name, contents } => {
                let tx = self.tx.clone();
                tokio::spawn(async move {
                    let written = tokio::task::spawn_blocking(move || {
                        let dir = std::env::current_dir()?;
                        write_new_file(&dir, &name, &contents)
                    })
                    .await
                    .unwrap_or_else(|e| Err(io::Error::other(e)));
                    // A Toast, not a CopyResult: the copy handler prefixes
                    // "copied ", which read as "copied wrote seer-bulk-….csv".
                    let (tone, msg) = match written {
                        Ok(path) => ("ok", format!("wrote {}", path.display())),
                        Err(e) => ("fail", format!("CSV export failed: {e}")),
                    };
                    let _ = tx.send(Msg::Toast { tone, msg });
                });
            }
        }
    }

    fn start_follow(&mut self, p: action::FollowParams) {
        // Cancel any prior run so restarts don't stack live DNS loops, then
        // arm a fresh cancel token for this run.
        self.stop_follow();
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        self.follow_cancel = Some(cancel_tx);
        let tx = self.tx.clone();
        let gen = p.gen;
        // Honor the config's DNS timeout and nameserver, like the CLI and
        // REPL `follow` (and the TUI's own DNS lens) do.
        let follower = seer_core::DnsFollower::from_config(&self.config);
        let nameserver = self.config.nameserver.clone();
        tokio::spawn(async move {
            let interval_minutes = p.interval_secs as f64 / 60.0;
            if let Ok(config) = seer_core::FollowConfig::new(p.iterations, interval_minutes) {
                let config = config.with_changes_only(false);
                let cb_tx = tx.clone();
                let cb: seer_core::dns::FollowProgressCallback =
                    Arc::new(move |it: &seer_core::dns::FollowIteration| {
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

    #[test]
    fn csv_export_never_overwrites_an_existing_file() {
        let dir = std::env::temp_dir().join(format!("seer-tui-csv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let first = write_new_file(&dir, "seer-bulk-lookup.csv", "one").unwrap();
        let second = write_new_file(&dir, "seer-bulk-lookup.csv", "two").unwrap();
        let third = write_new_file(&dir, "seer-bulk-lookup.csv", "three").unwrap();
        assert_eq!(first, dir.join("seer-bulk-lookup.csv"));
        assert_eq!(second, dir.join("seer-bulk-lookup-1.csv"));
        assert_eq!(third, dir.join("seer-bulk-lookup-2.csv"));
        assert!(first.is_absolute(), "the toast names the full path");
        assert_eq!(std::fs::read_to_string(&first).unwrap(), "one");
        assert_eq!(std::fs::read_to_string(&second).unwrap(), "two");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
