//! TLD browser component — filterable, scrollable list over the full TLD
//! catalog (~1,400 entries) plus per-TLD detail. Replaces the old fixed
//! 7-chip switcher.
use crossterm::event::{KeyCode, KeyEvent};

use crate::tui::action::{EditTarget, FetchReq};
use crate::tui::panes::PaneOutcome;

/// The full TLD catalog from seer-core (sorted, deduplicated).
pub fn catalog() -> &'static [&'static str] {
    seer_core::all_tlds()
}

/// TLD browser state: a substring filter and the selected position within the
/// currently-filtered list.
pub struct TldState {
    /// Case-insensitive substring filter over the catalog (no leading dot).
    pub filter: String,
    /// Index into the *filtered* list of the highlighted TLD.
    pub sel: usize,
}

impl Default for TldState {
    fn default() -> Self {
        // Start on `com` rather than the first alphabetical entry so the lens
        // opens on a familiar TLD.
        let sel = catalog().iter().position(|&t| t == "com").unwrap_or(0);
        Self {
            filter: String::new(),
            sel,
        }
    }
}

impl TldState {
    /// Catalog entries matching the current filter (case-insensitive substring).
    /// An empty filter matches everything.
    pub fn filtered(&self) -> Vec<&'static str> {
        filter_catalog(&self.filter)
    }

    /// The selected TLD as a dotted string (e.g. `.com`), clamped to the
    /// filtered list. Empty when nothing matches the filter.
    pub fn current(&self) -> String {
        let f = self.filtered();
        if f.is_empty() {
            return String::new();
        }
        let i = self.sel.min(f.len() - 1);
        format!(".{}", f[i])
    }

    /// Set the filter (used by live editing); clamps the selection to the new
    /// match set, keeping it in range as the list shrinks.
    pub fn set_filter(&mut self, filter: String) {
        self.filter = filter.trim().trim_start_matches('.').to_lowercase();
        let len = self.filtered().len();
        if len == 0 {
            self.sel = 0;
        } else if self.sel >= len {
            self.sel = len - 1;
        }
    }

    /// Select an exact TLD by name (tolerant of a leading dot / case). Clears the
    /// filter and points the selection at that catalog entry. Returns `false`
    /// (leaving state untouched) when the TLD is not in the catalog — used by the
    /// `:tld <name>` command, which must reject unknown TLDs.
    pub fn select(&mut self, tld: &str) -> bool {
        let want = tld.trim().trim_start_matches('.').to_lowercase();
        if let Some(i) = catalog().iter().position(|&t| t == want) {
            self.filter.clear();
            self.sel = i;
            true
        } else {
            false
        }
    }

    /// Move the selection by `delta`, clamped to the filtered list.
    fn move_sel(&mut self, delta: isize) {
        let len = self.filtered().len();
        if len == 0 {
            return;
        }
        let cur = self.sel.min(len - 1) as isize;
        self.sel = (cur + delta).clamp(0, len as isize - 1) as usize;
    }

    /// Handle a key event. Navigation (`j`/`k`/arrows, `g`/`G`), `/` to edit the
    /// filter, and `↵`/`l` to load the selected TLD's details. Returns `None`
    /// for everything else so App's normal handling (Esc, Tab, …) still runs.
    pub fn handle_key(&mut self, key: KeyEvent) -> Option<PaneOutcome> {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                self.move_sel(1);
                Some(PaneOutcome::None)
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.move_sel(-1);
                Some(PaneOutcome::None)
            }
            KeyCode::Char('g') | KeyCode::Home => {
                self.sel = 0;
                Some(PaneOutcome::None)
            }
            KeyCode::Char('G') | KeyCode::End => {
                let len = self.filtered().len();
                self.sel = len.saturating_sub(1);
                Some(PaneOutcome::None)
            }
            // Edit the filter (handled by App so the list filters live and a
            // fetch fires on commit).
            KeyCode::Char('/') | KeyCode::Char('f') => {
                Some(PaneOutcome::EditField(EditTarget::TldFilter))
            }
            // Load the selected TLD's registry details.
            KeyCode::Char('l') | KeyCode::Enter => {
                let cur = self.current();
                if cur.is_empty() {
                    Some(PaneOutcome::None)
                } else {
                    Some(PaneOutcome::Fetch(FetchReq::Tld(cur)))
                }
            }
            _ => None,
        }
    }
}

/// Filter the catalog by a case-insensitive substring (leading dot ignored).
pub fn filter_catalog(filter: &str) -> Vec<&'static str> {
    let needle = filter.trim().trim_start_matches('.').to_lowercase();
    if needle.is_empty() {
        return catalog().to_vec();
    }
    catalog()
        .iter()
        .filter(|t| t.contains(&needle))
        .copied()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn catalog_is_large() {
        assert!(
            catalog().len() > 1000,
            "catalog should expose the full TLD list, got {}",
            catalog().len()
        );
    }

    #[test]
    fn default_starts_on_com() {
        let state = TldState::default();
        assert_eq!(state.current(), ".com");
    }

    #[test]
    fn j_and_k_move_selection() {
        let mut state = TldState::default();
        let start = state.sel;
        let out = state.handle_key(press(KeyCode::Char('j')));
        assert_eq!(state.sel, start + 1);
        assert!(matches!(out, Some(PaneOutcome::None)));
        state.handle_key(press(KeyCode::Char('k')));
        assert_eq!(state.sel, start);
    }

    #[test]
    fn arrows_also_move_selection() {
        let mut state = TldState::default();
        let start = state.sel;
        state.handle_key(press(KeyCode::Down));
        assert_eq!(state.sel, start + 1);
        state.handle_key(press(KeyCode::Up));
        assert_eq!(state.sel, start);
    }

    #[test]
    fn g_jumps_to_top_and_bottom() {
        let mut state = TldState::default();
        state.handle_key(press(KeyCode::Char('G')));
        assert_eq!(state.sel, state.filtered().len() - 1);
        state.handle_key(press(KeyCode::Char('g')));
        assert_eq!(state.sel, 0);
    }

    #[test]
    fn selection_clamps_to_filtered_list() {
        let mut state = TldState::default();
        state.handle_key(press(KeyCode::Char('G'))); // last of full list
                                                     // Narrow the filter so the list shrinks below the old selection.
        state.set_filter("com".into());
        let len = state.filtered().len();
        assert!(
            state.sel < len,
            "selection must stay in range after filtering"
        );
    }

    #[test]
    fn filter_narrows_the_list() {
        let mut state = TldState::default();
        let all = state.filtered().len();
        state.set_filter("shop".into());
        let narrowed = state.filtered();
        assert!(narrowed.len() < all, "filter should reduce the list");
        assert!(
            narrowed.iter().all(|t| t.contains("shop")),
            "all matches must contain the needle"
        );
    }

    #[test]
    fn slash_and_f_open_the_filter_field() {
        let mut state = TldState::default();
        assert!(matches!(
            state.handle_key(press(KeyCode::Char('/'))),
            Some(PaneOutcome::EditField(EditTarget::TldFilter))
        ));
        assert!(matches!(
            state.handle_key(press(KeyCode::Char('f'))),
            Some(PaneOutcome::EditField(EditTarget::TldFilter))
        ));
    }

    #[test]
    fn enter_fetches_selected_tld() {
        let mut state = TldState::default();
        let out = state.handle_key(press(KeyCode::Enter));
        assert!(matches!(
            out,
            Some(PaneOutcome::Fetch(FetchReq::Tld(ref s))) if s == ".com"
        ));
    }

    #[test]
    fn enter_with_no_matches_is_noop() {
        let mut state = TldState::default();
        state.set_filter("zzzznotatld".into());
        assert_eq!(state.filtered().len(), 0);
        let out = state.handle_key(press(KeyCode::Enter));
        assert!(matches!(out, Some(PaneOutcome::None)));
    }

    #[test]
    fn select_known_tld_clears_filter_and_points_at_it() {
        let mut state = TldState::default();
        state.set_filter("io".into());
        assert!(state.select(".io"));
        assert!(state.filter.is_empty(), "select should clear the filter");
        assert_eq!(state.current(), ".io");
    }

    #[test]
    fn select_unknown_tld_returns_false() {
        let mut state = TldState::default();
        assert!(!state.select(".zzzznotatld"));
    }

    #[test]
    fn unowned_keys_return_none() {
        let mut state = TldState::default();
        assert!(state.handle_key(press(KeyCode::Esc)).is_none());
        assert!(state.handle_key(press(KeyCode::Tab)).is_none());
        assert!(state.handle_key(press(KeyCode::Char('['))).is_none());
        assert!(state.handle_key(press(KeyCode::Char(']'))).is_none());
    }
}
