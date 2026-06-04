//! Full-screen ratatui TUI for Seer. Launched via `seer tui [domain]`.
//!
//! NOTE: `run()` is a stub here; the real terminal lifecycle + event loop are
//! added in a later task once App, render, data, and clipboard exist. The
//! submodules are scaffolded (empty or stub) so the crate compiles green.

mod action;
mod app;
mod clipboard;
mod command;
mod data;
mod event;
mod lenses;
mod raw;
mod render;
mod theme;
mod widgets;

use std::io::{self, Stdout};
use std::time::Duration;

use anyhow::Result;
use crossterm::event::EventStream;
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use futures::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use action::{Action, Msg};
use app::App;
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
    execute!(stdout, EnterAlternateScreen)?;
    Ok(Terminal::new(CrosstermBackend::new(stdout))?)
}

fn restore_terminal(terminal: &mut Term) -> Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

/// Restore the terminal even if a panic unwinds through the draw loop.
fn install_panic_hook() {
    let original = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
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
        Action::Fetch { lens, domain } => {
            let tx = tx.clone();
            tokio::spawn(async move {
                let result = data::fetch(lens, &domain).await;
                let _ = tx.send(Msg::Data { lens, domain, result });
            });
        }
        Action::Copy { text, label } => {
            let ok = clipboard::copy(&text).is_ok();
            let _ = tx.send(Msg::CopyResult { ok, label });
        }
    }
}
