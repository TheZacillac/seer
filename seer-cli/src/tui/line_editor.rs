//! A minimal cursor-aware single-line text editor for TUI input fields.
//!
//! Replaces the previous append-only buffers so every text prompt (domain
//! entry, filters, bulk lists, follow interval/count, diff B) supports real
//! editing: cursor movement, Home/End, mid-string insert/delete, and word
//! delete. Multibyte-safe: the cursor is a byte offset kept on `char`
//! boundaries.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// What a key did to the editor's owning input mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditOutcome {
    /// Enter — the field/command should be submitted.
    Submit,
    /// Esc — editing should be cancelled.
    Cancel,
    /// The key was consumed (or ignored); keep editing.
    Continue,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LineEditor {
    text: String,
    /// Cursor position as a byte offset into `text`, always on a `char` boundary.
    cursor: usize,
}

impl LineEditor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The cursor's byte offset (always on a `char` boundary). Renderers place
    /// the caret via [`Self::with_caret`]; this accessor is for tests.
    #[cfg(test)]
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn insert_char(&mut self, c: char) {
        self.text.insert(self.cursor, c);
        self.cursor += c.len_utf8();
    }

    pub fn insert_str(&mut self, s: &str) {
        self.text.insert_str(self.cursor, s);
        self.cursor += s.len();
    }

    /// Deletes the char before the cursor (Backspace).
    pub fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let prev = self.prev_boundary();
        self.text.replace_range(prev..self.cursor, "");
        self.cursor = prev;
    }

    /// Deletes the char at the cursor (Delete).
    pub fn delete(&mut self) {
        if self.cursor >= self.text.len() {
            return;
        }
        let next = self.next_boundary();
        self.text.replace_range(self.cursor..next, "");
    }

    pub fn left(&mut self) {
        if self.cursor > 0 {
            self.cursor = self.prev_boundary();
        }
    }

    pub fn right(&mut self) {
        if self.cursor < self.text.len() {
            self.cursor = self.next_boundary();
        }
    }

    pub fn home(&mut self) {
        self.cursor = 0;
    }

    pub fn end(&mut self) {
        self.cursor = self.text.len();
    }

    /// Deletes the word before the cursor (Ctrl-W): trailing spaces, then the
    /// run of non-spaces.
    pub fn delete_word(&mut self) {
        let bytes = self.text.as_bytes();
        let mut i = self.cursor;
        while i > 0 && bytes[i - 1] == b' ' {
            i -= 1;
        }
        while i > 0 && bytes[i - 1] != b' ' {
            // Step back one whole char (space is single-byte, so any non-space
            // start byte we care about is found by walking char boundaries).
            let prev = self.text[..i]
                .chars()
                .next_back()
                .map(|c| c.len_utf8())
                .unwrap_or(1);
            i -= prev;
        }
        self.text.replace_range(i..self.cursor, "");
        self.cursor = i;
    }

    /// The text with `caret` spliced in at the cursor, for rendering the field.
    pub fn with_caret(&self, caret: &str) -> String {
        let (before, after) = self.text.split_at(self.cursor);
        format!("{before}{caret}{after}")
    }

    /// Applies a key event, returning what it means for the owning mode.
    pub fn handle_key(&mut self, key: KeyEvent) -> EditOutcome {
        // Windows reports AltGr as CONTROL|ALT, and non-US layouts type
        // `\ @ { } [ ] | ~` with it — so that combination is a character,
        // not a Ctrl chord (crossterm already delivers the composed char).
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL)
            && !key.modifiers.contains(KeyModifiers::ALT);
        match key.code {
            KeyCode::Enter => return EditOutcome::Submit,
            KeyCode::Esc => return EditOutcome::Cancel,
            KeyCode::Backspace => self.backspace(),
            KeyCode::Delete => self.delete(),
            KeyCode::Left => self.left(),
            KeyCode::Right => self.right(),
            KeyCode::Home => self.home(),
            KeyCode::End => self.end(),
            KeyCode::Char('a') if ctrl => self.home(),
            KeyCode::Char('e') if ctrl => self.end(),
            KeyCode::Char('w') if ctrl => self.delete_word(),
            // Ignore other Ctrl-combos so they don't insert stray letters.
            KeyCode::Char(c) if !ctrl => self.insert_char(c),
            _ => {}
        }
        EditOutcome::Continue
    }

    fn prev_boundary(&self) -> usize {
        self.text[..self.cursor]
            .char_indices()
            .next_back()
            .map(|(i, _)| i)
            .unwrap_or(0)
    }

    fn next_boundary(&self) -> usize {
        self.text[self.cursor..]
            .chars()
            .next()
            .map(|c| self.cursor + c.len_utf8())
            .unwrap_or(self.cursor)
    }
}

impl From<String> for LineEditor {
    fn from(text: String) -> Self {
        let cursor = text.len();
        Self { text, cursor }
    }
}

impl From<&str> for LineEditor {
    fn from(s: &str) -> Self {
        Self::from(s.to_string())
    }
}

impl PartialEq<&str> for LineEditor {
    fn eq(&self, other: &&str) -> bool {
        self.text == *other
    }
}

impl std::fmt::Display for LineEditor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ed(s: &str) -> LineEditor {
        LineEditor::from(s)
    }

    #[test]
    fn from_str_places_cursor_at_end() {
        let e = ed("abc");
        assert_eq!(e.cursor(), 3);
        assert_eq!(e.as_str(), "abc");
    }

    #[test]
    fn mid_string_insert_and_backspace() {
        let mut e = ed("ac");
        e.left(); // between a and c
        e.insert_char('b');
        assert_eq!(e.as_str(), "abc");
        assert_eq!(e.cursor(), 2);
        e.backspace();
        assert_eq!(e.as_str(), "ac");
        assert_eq!(e.cursor(), 1);
    }

    #[test]
    fn delete_at_cursor_and_home_end() {
        let mut e = ed("abc");
        e.home();
        assert_eq!(e.cursor(), 0);
        e.delete(); // removes 'a'
        assert_eq!(e.as_str(), "bc");
        e.end();
        assert_eq!(e.cursor(), 2);
    }

    #[test]
    fn delete_word_removes_last_token_and_trailing_space() {
        let mut e = ed("a.com b.com ");
        e.delete_word();
        assert_eq!(e.as_str(), "a.com ");
        e.delete_word();
        assert_eq!(e.as_str(), "");
    }

    #[test]
    fn multibyte_editing_is_boundary_safe() {
        let mut e = ed("héllo"); // é is 2 bytes
        e.home();
        e.right(); // past 'h'
        e.right(); // past 'é'
        assert_eq!(e.cursor(), 3); // 1 byte 'h' + 2 bytes 'é'
        e.backspace(); // remove 'é'
        assert_eq!(e.as_str(), "hllo");
    }

    #[test]
    fn altgr_characters_are_inserted_but_ctrl_chords_are_not() {
        let altgr = KeyModifiers::CONTROL | KeyModifiers::ALT;
        let mut e = LineEditor::new();
        for c in ['@', '\\', '{', '}', '[', ']', '|', '~'] {
            e.handle_key(KeyEvent::new(KeyCode::Char(c), altgr));
        }
        assert_eq!(
            e.as_str(),
            "@\\{}[]|~",
            "AltGr (CONTROL|ALT) chars must insert"
        );
        // A plain Ctrl chord still edits instead of inserting a letter.
        e.handle_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::CONTROL));
        assert_eq!(e.as_str(), "@\\{}[]|~");
        e.handle_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::CONTROL));
        assert_eq!(e.cursor(), 0, "Ctrl-A still moves home");
    }

    #[test]
    fn with_caret_splits_at_the_cursor() {
        let mut e = ed("abc");
        assert_eq!(e.with_caret("|"), "abc|");
        e.home();
        e.right();
        assert_eq!(e.with_caret("|"), "a|bc");
    }

    #[test]
    fn boundaries_do_not_panic_when_empty() {
        let mut e = LineEditor::new();
        e.backspace();
        e.delete();
        e.left();
        e.right();
        e.delete_word();
        assert_eq!(e.as_str(), "");
        assert_eq!(e.cursor(), 0);
    }
}
