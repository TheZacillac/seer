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
    let mut guard = BULK_PROGRESS_BAR.lock().unwrap();
    *guard = Some(pb);
}

/// Clear the active bulk progress bar.
pub fn clear_bulk_progress_bar() {
    let mut guard = BULK_PROGRESS_BAR.lock().unwrap();
    *guard = None;
}

/// Get a clone of the current bulk progress bar if one is set.
pub fn get_bulk_progress_bar() -> Option<ProgressBar> {
    let guard = BULK_PROGRESS_BAR.lock().unwrap();
    guard.clone()
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

            if let Some(pb) = get_bulk_progress_bar() {
                // Route through progress bar to maintain display
                pb.println(trimmed);
            } else {
                // No progress bar active, write directly to stderr
                let mut stderr = std::io::stderr();
                stderr.write_all(trimmed.as_bytes())?;
                stderr.write_all(b"\n")?;
            }
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // Flush any remaining content
        if !self.buffer.is_empty() {
            let line_str = String::from_utf8_lossy(&self.buffer);
            let trimmed = line_str.trim_end();

            if !trimmed.is_empty() {
                if let Some(pb) = get_bulk_progress_bar() {
                    pb.println(trimmed);
                } else {
                    let mut stderr = std::io::stderr();
                    stderr.write_all(trimmed.as_bytes())?;
                    stderr.write_all(b"\n")?;
                }
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
