pub mod chips;
pub mod dot;
pub mod gauge;
pub mod kv;
pub mod panel;

use ratatui::style::Style;
use ratatui::widgets::TableState;

use crate::tui::theme::Theme;

/// `value` as text, or an em dash (the TUI's missing-value mark) when absent.
pub fn or_dash<T: ToString>(value: Option<T>) -> String {
    value.map_or_else(|| "—".to_string(), |v| v.to_string())
}

/// Style for one row of a selectable list: body text, on the `surface0`
/// selection band when `selected`.
///
/// Applied per row rather than via `Table::row_highlight_style`: ratatui clamps
/// an out-of-range selection to the last row, so a stale `sel` (e.g. while a
/// live `/` filter narrows the list) would highlight a row the App doesn't
/// consider selected.
pub fn row_style(theme: &Theme, selected: bool) -> Style {
    let style = Style::default().fg(theme.text);
    if selected {
        style.bg(theme.surface0)
    } else {
        style
    }
}

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
