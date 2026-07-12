//! Terminal-native clipboard via the OSC52 escape sequence. Works over SSH and
//! needs no system clipboard libraries. Honest about failure (returns Err).
use std::io::{self, Write};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

/// Build the OSC52 "set clipboard" escape sequence for `text`.
pub fn osc52_sequence(text: &str) -> String {
    let encoded = STANDARD.encode(text.as_bytes());
    format!("\x1b]52;c;{encoded}\x07")
}

/// Write the OSC52 sequence to stdout. Returns Err if the write fails.
pub fn copy(text: &str) -> io::Result<()> {
    let seq = osc52_sequence(text);
    let mut out = io::stdout();
    out.write_all(seq.as_bytes())?;
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn osc52_wraps_base64_payload() {
        // "hi" base64 = "aGk="
        let seq = osc52_sequence("hi");
        assert_eq!(seq, "\x1b]52;c;aGk=\x07");
    }
}
