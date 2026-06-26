pub mod chips;
pub mod dot;
pub mod gauge;
pub mod kv;
pub mod panel;

use ratatui::widgets::TableState;

/// Build a `TableState` that keeps `selected` in view.
///
/// The list lenses render plain `Table`s, which (rendered non-statefully) never
/// scroll — a selection past the viewport edge becomes invisible. Rendering the
/// same table via `render_stateful_widget` with this state lets ratatui scroll
/// so the selected row stays on screen. The offset starts at 0 each frame;
/// ratatui recomputes it from `selected`, so no cross-frame state is needed.
/// Pass `None` (e.g. when a pane isn't focused) to leave the list at the top.
pub fn scroll_to(selected: Option<usize>) -> TableState {
    TableState::default().with_selected(selected)
}
