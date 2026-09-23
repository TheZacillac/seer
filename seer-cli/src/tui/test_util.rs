//! Test-only helpers: draw one frame on a `TestBackend` and read it back.
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::{Frame, Terminal};

/// Draw one frame on a fresh `width`×`height` test terminal; return its buffer
/// (for tests that inspect cell styles rather than text).
pub fn render_buffer(width: u16, height: u16, draw: impl FnOnce(&mut Frame)) -> Buffer {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(draw).unwrap();
    terminal.backend().buffer().clone()
}

/// [`render_buffer`] as text: every cell's symbol, rows run together.
pub fn render_text(width: u16, height: u16, draw: impl FnOnce(&mut Frame)) -> String {
    buf_text(&render_buffer(width, height, draw), "")
}

/// [`render_buffer`] as text with a `\n` after each row, for assertions that
/// must not match across a row boundary or that split on `lines()`.
pub fn render_lines(width: u16, height: u16, draw: impl FnOnce(&mut Frame)) -> String {
    buf_text(&render_buffer(width, height, draw), "\n")
}

fn buf_text(buf: &Buffer, row_end: &str) -> String {
    let area = buf.area();
    let mut s = String::new();
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            s.push_str(buf[(x, y)].symbol());
        }
        s.push_str(row_end);
    }
    s
}
