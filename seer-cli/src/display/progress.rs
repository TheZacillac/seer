//! Progress bar management for bulk operations with tracing integration.
//!
//! This module provides a way to integrate indicatif progress bars with tracing
//! so that log output doesn't interfere with progress bar display.

use indicatif::ProgressBar;
use std::io::Write;
use std::sync::Mutex;

/// Global holder for the active bulk progress bar.
/// When set, tracing output will be routed through the progress bar's println method.
static BULK_PROGRESS_BAR: Mutex<Option<ProgressBar>> = Mutex::new(None);

/// Set the active bulk progress bar for tracing integration.
/// While set, all tracing output will be printed through the progress bar.
pub fn set_bulk_progress_bar(pb: ProgressBar) {
    let mut guard = BULK_PROGRESS_BAR
        .lock()
        .expect("progress bar mutex poisoned");
    *guard = Some(pb);
}

/// Clear the active bulk progress bar.
pub fn clear_bulk_progress_bar() {
    let mut guard = BULK_PROGRESS_BAR
        .lock()
        .expect("progress bar mutex poisoned");
    *guard = None;
}

/// Get a clone of the current bulk progress bar if one is set.
pub fn get_bulk_progress_bar() -> Option<ProgressBar> {
    let guard = BULK_PROGRESS_BAR
        .lock()
        .expect("progress bar mutex poisoned");
    guard.clone()
}

/// Prints `line` above `pb`, or straight to stderr when the bar is hidden.
///
/// indicatif hides a bar whose draw target is not a terminal (stderr piped or
/// redirected — e.g. `--progress verbose 2> log`), and `ProgressBar::println`
/// is a silent no-op on a hidden bar, so per-item progress lines and tracing
/// output routed through the bar were dropped whenever stderr wasn't a TTY.
pub fn bar_println(pb: &ProgressBar, line: &str) -> std::io::Result<()> {
    bar_println_or(pb, line, &mut std::io::stderr().lock())
}

/// [`bar_println`] with an injectable fallback sink (stderr in production).
fn bar_println_or<W: Write>(pb: &ProgressBar, line: &str, fallback: &mut W) -> std::io::Result<()> {
    if pb.is_hidden() {
        fallback.write_all(line.as_bytes())?;
        fallback.write_all(b"\n")
    } else {
        pb.println(line);
        Ok(())
    }
}

/// Writes one complete line of tracing output: through the active bulk
/// progress bar when there is one (so the bar redraws cleanly below it),
/// otherwise directly to stderr.
fn write_line(line: &str) -> std::io::Result<()> {
    match get_bulk_progress_bar() {
        Some(pb) => bar_println(&pb, line),
        None => {
            let mut stderr = std::io::stderr().lock();
            stderr.write_all(line.as_bytes())?;
            stderr.write_all(b"\n")
        }
    }
}

/// A writer that routes output through the bulk progress bar when active.
/// This prevents tracing logs from interfering with progress bar display.
pub struct ProgressWriter {
    buffer: Vec<u8>,
}

impl ProgressWriter {
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }
}

impl Default for ProgressWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl Write for ProgressWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buffer.extend_from_slice(buf);

        // Check for complete lines and flush them
        while let Some(newline_pos) = self.buffer.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.buffer.drain(..=newline_pos).collect();
            let line_str = String::from_utf8_lossy(&line);
            let trimmed = line_str.trim_end_matches('\n');
            write_line(trimmed)?;
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // Flush any remaining content
        if !self.buffer.is_empty() {
            let line_str = String::from_utf8_lossy(&self.buffer);
            let trimmed = line_str.trim_end();

            if !trimmed.is_empty() {
                write_line(trimmed)?;
            }
            self.buffer.clear();
        }
        Ok(())
    }
}

impl Drop for ProgressWriter {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

/// A MakeWriter implementation for tracing-subscriber that creates ProgressWriters.
pub struct ProgressWriterFactory;

impl ProgressWriterFactory {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ProgressWriterFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for ProgressWriterFactory {
    type Writer = ProgressWriter;

    fn make_writer(&'a self) -> Self::Writer {
        ProgressWriter::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hidden_bar_falls_back_to_the_stderr_sink() {
        // A hidden bar (what indicatif gives you when stderr is not a TTY)
        // swallows `println`; the line must reach the fallback sink instead.
        let pb = ProgressBar::hidden();
        let mut sink = Vec::new();
        bar_println_or(&pb, "\u{2717} bad.example (timeout)", &mut sink).expect("write");
        assert_eq!(
            String::from_utf8(sink).expect("utf8"),
            "\u{2717} bad.example (timeout)\n"
        );
    }
}
