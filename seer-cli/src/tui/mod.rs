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

use anyhow::Result;

/// Entry point for the `seer tui` subcommand. Stub — the real loop is added later.
pub async fn run(_domain: Option<String>) -> Result<()> {
    Ok(())
}
