use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

pub struct Spinner {
    progress: ProgressBar,
}

impl Spinner {
    pub fn new(message: &str) -> Self {
        let progress = ProgressBar::new_spinner();
        progress.set_style(
            ProgressStyle::default_spinner()
                .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
                .template("{spinner:.cyan} {msg}")
                .expect("Spinner template is hardcoded and should be valid"),
        );
        progress.set_message(message.to_string());
        progress.enable_steady_tick(Duration::from_millis(80));

        Self { progress }
    }

    /// A spinner that only draws when `visible`; otherwise a no-op handle, so
    /// callers can report progress unconditionally.
    pub fn maybe(visible: bool, message: &str) -> Self {
        if visible {
            Self::new(message)
        } else {
            Self {
                progress: ProgressBar::hidden(),
            }
        }
    }

    pub fn set_message(&self, message: &str) {
        self.progress.set_message(message.to_string());
    }

    pub fn finish(&self) {
        self.progress.finish_and_clear();
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        self.progress.finish_and_clear();
    }
}
