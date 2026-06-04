//! Full-screen ratatui TUI for Seer. Launched via `seer tui [domain]`.
//!
//! `run()` sets up the terminal (raw mode + alternate screen + panic-restore
//! hook) and drives an async `tokio::select!` loop over crossterm input, a
//! results channel, and an animation tick. `App` (in `app`) is the pure state
//! machine; `render` draws it; `data` dispatches lookups to `seer-core`.

mod action;
mod app;
mod clipboard;
mod command;
mod data;
mod event;
mod lenses;
mod panes;
mod raw;
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
fn install_panic_hook() {
    let original = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), DisableBracketedPaste, LeaveAlternateScreen);
        original(info);
    }));
}

async fn run_loop(terminal: &mut Term, domain: Option<String>) -> Result<()> {
    let theme = Theme::frappe();
    let mut app = App::new(domain);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Msg>();
    let mut events = EventStream::new();
    let mut tick = tokio::time::interval(Duration::from_millis(100));

    for action in app.take_startup_actions() {
        handle_action(action, &tx);
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
            handle_action(action, &tx);
        }

        if app.should_quit {
            break;
        }
        terminal.draw(|f| render::view(f, &app, &theme))?;
    }
    Ok(())
}

/// Execute a side-effecting Action returned by `App::update`.
fn handle_action(action: Action, tx: &tokio::sync::mpsc::UnboundedSender<Msg>) {
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
            let _ = tx.send(Msg::CopyResult { ok, label });
        }
        Action::WatchMutate { add, remove } => {
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
                // Refresh the watchlist lens after mutation.
                // gen 0 is always accepted: WatchMutate bypasses the fetch_action
                // path so fetch_gen["watch"] stays at 0 unless a lens navigation fetch
                // has already bumped it (rare race — see generation guard in app.rs).
                let result = data::fetch(action::FetchReq::Watch).await;
                let _ = tx.send(Msg::Data {
                    lens: "watch".into(),
                    gen: 0,
                    result,
                });
            });
        }
        Action::HistoryClear => {
            let tx = tx.clone();
            tokio::spawn(async move {
                tokio::task::spawn_blocking(|| {
                    let mut h = LookupHistory::load();
                    h.clear();
                    let _ = h.save();
                })
                .await
                .ok();
                // Refresh the history lens after clearing.
                // gen 0: same rationale as WatchMutate above.
                let result = data::fetch(action::FetchReq::History).await;
                let _ = tx.send(Msg::Data {
                    lens: "history".into(),
                    gen: 0,
                    result,
                });
            });
        }
        Action::StartFollow(p) => {
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
                            None,
                        )
                        .await;
                }
                let _ = tx.send(Msg::FollowDone { gen });
            });
        }
        Action::StartBulk(p) => {
            let tx = tx.clone();
            let gen = p.gen;
            tokio::spawn(async move {
                let ex = seer_core::BulkExecutor::new();
                let results = match p.op.as_str() {
                    "status" => ex.execute_status(p.domains).await,
                    "dig" => ex.execute_dns(p.domains, seer_core::RecordType::A).await,
                    "avail" => ex.execute_avail(p.domains).await,
                    "info" => ex.execute_info(p.domains).await,
                    _ => ex.execute_lookup(p.domains).await,
                };
                for r in results {
                    let _ = tx.send(Msg::BulkStep {
                        gen,
                        result: Box::new(r),
                    });
                }
                let _ = tx.send(Msg::BulkDone { gen });
            });
        }
        Action::StartBulkFromFile { op, path, gen } => {
            let tx = tx.clone();
            tokio::spawn(async move {
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
                let ex = seer_core::BulkExecutor::new();
                let results = match op.as_str() {
                    "status" => ex.execute_status(domains).await,
                    "dig" => ex.execute_dns(domains, seer_core::RecordType::A).await,
                    "avail" => ex.execute_avail(domains).await,
                    "info" => ex.execute_info(domains).await,
                    _ => ex.execute_lookup(domains).await,
                };
                for r in results {
                    let _ = tx.send(Msg::BulkStep {
                        gen,
                        result: Box::new(r),
                    });
                }
                let _ = tx.send(Msg::BulkDone { gen });
            });
        }
        Action::WriteCsv { path, contents } => {
            let tx = tx.clone();
            tokio::spawn(async move {
                let path_clone = path.clone();
                let ok = tokio::task::spawn_blocking(move || std::fs::write(&path_clone, contents))
                    .await
                    .map(|r| r.is_ok())
                    .unwrap_or(false);
                let _ = tx.send(Msg::CopyResult {
                    ok,
                    label: format!("wrote {path}"),
                });
            });
        }
    }
}
