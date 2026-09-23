//! Terminal progress UI: the [`Spinner`] shown while a single command runs,
//! and the bulk progress bar that keeps tracing output from tearing it (see
//! `progress.rs`).

mod progress;
mod spinner;

pub use progress::{
    bar_println, clear_bulk_progress_bar, set_bulk_progress_bar, ProgressWriterFactory,
};
pub use spinner::Spinner;
