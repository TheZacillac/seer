//! Reads `&App` and draws the full frame: top bar, nav, main pane, status/cmd
//! bar, and the help overlay.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

use crate::tui::action::{EditTarget, Focus, InputMode, LensData, LensState};
use crate::tui::app::{App, SPIN};
use crate::tui::lenses::{self};
use crate::tui::line_editor::LineEditor;
use crate::tui::theme::Theme;
use crate::tui::widgets::panel;

/// The in-progress editor for `target`, if a matching field is active (the
/// editor, not just its text, so renderers can place the caret at the cursor).
fn field_buf(mode: &InputMode, target: EditTarget) -> Option<&LineEditor> {
    match mode {
        InputMode::Field { target: t, buf } if *t == target => Some(buf),
        _ => None,
    }
}

/// Status-bar prompt for edit fields that no pane draws inline. `None` means
/// the field is rendered elsewhere (top bar, its lens, or the filter line) —
/// the match is exhaustive so a new field can't silently go undrawn again.
fn status_prompt(app: &App, target: EditTarget) -> Option<String> {
    let follow = &app.panes.follow;
    match target {
        EditTarget::FollowInterval => {
            Some(format!("interval seconds (now {})> ", follow.interval_secs))
        }
        EditTarget::FollowCount => Some(format!("check count (now {})> ", follow.count)),
        EditTarget::BulkPath => Some("domains file> ".to_string()),
        EditTarget::WatchAdd => Some("watch add> ".to_string()),
        EditTarget::Target
        | EditTarget::DiffB
        | EditTarget::BulkDomains
        | EditTarget::TldFilter
        | EditTarget::LensFilter => None,
    }
}

pub fn view(f: &mut Frame, app: &App, theme: &Theme) {
    let area = f.area();
    // Paint the whole canvas before any widget: both themes must be
    // self-contained on any terminal. Cells no widget backfills otherwise
    // keep the terminal's own background, which renders Latte in a dark
    // terminal as light bars floating on a dark canvas. The mantle bars and
    // selection stripes then read as the intended contrast against base.
    f.render_widget(
        Block::default().style(Style::default().bg(theme.base).fg(theme.text)),
        area,
    );
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

    top_bar(f, rows[0], app, theme);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(26), Constraint::Min(0)])
        .split(rows[1]);

    nav(f, body[0], app, theme);
    main_pane(f, body[1], app, theme);
    status_or_command(f, rows[2], app, theme);

    if app.help {
        help_overlay(f, area, theme);
    }
}

fn top_bar(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let domain = app.domain.as_deref().unwrap_or("(no target)");
    let target = match &app.input_mode {
        InputMode::Field {
            target: EditTarget::Target,
            buf,
        } => format!("⌕ {}", buf.with_caret("▏")),
        // Other field targets are rendered inside their panes; top-bar shows current domain.
        _ => format!("⌕ {domain}"),
    };
    let ip = match app.state_of(app.lens) {
        LensState::Loading => format!("{} resolving…", SPIN[app.spin]),
        _ => String::new(),
    };
    let mode = if app.focus == Focus::Pane {
        "‹pane›"
    } else {
        "‹nav›"
    };
    let mut spans = vec![
        Span::styled(
            "🔮 seer",
            Style::default()
                .fg(theme.mauve)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("  │  ", Style::default().fg(theme.surface1)),
        Span::styled("target ", Style::default().fg(theme.overlay)),
        Span::styled(target, Style::default().fg(theme.text)),
        Span::styled(format!("  {ip}  "), Style::default().fg(theme.teal)),
    ];
    if app.format != seer_core::output::OutputFormat::Human {
        spans.push(Span::styled(
            format!(" --format {:?} ", app.format).to_lowercase(),
            Style::default().fg(theme.green),
        ));
    }
    spans.push(Span::styled(
        format!("  {mode}  "),
        Style::default().fg(theme.lavender),
    ));
    spans.push(Span::styled(
        format!("│ v{}", env!("CARGO_PKG_VERSION")),
        Style::default().fg(theme.overlay0),
    ));
    f.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(theme.mantle)),
        area,
    );
}

fn nav(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let block = Block::default()
        .borders(Borders::RIGHT)
        .border_style(Style::default().fg(theme.surface0));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut lines: Vec<Line> = Vec::new();
    let all = lenses::lenses();
    for (i, l) in all.iter().enumerate() {
        let new_group = i == 0 || all[i - 1].group != l.group;
        if new_group {
            lines.push(Line::from(Span::styled(
                l.group,
                Style::default()
                    .fg(theme.overlay0)
                    .add_modifier(Modifier::DIM),
            )));
        }
        let active = i == app.lens;
        let num = if i < 9 {
            (b'1' + i as u8) as char
        } else {
            '·'
        };
        let label_color = if active { theme.text } else { theme.subtext };
        let glyph_color = if active { theme.blue } else { theme.lavender };
        let prefix = if active { "▸ " } else { "  " };
        lines.push(Line::from(vec![
            Span::styled(
                format!("{prefix}{num} "),
                Style::default().fg(if active { theme.blue } else { theme.overlay0 }),
            ),
            Span::styled(format!("{} ", l.glyph), Style::default().fg(glyph_color)),
            Span::styled(l.label, Style::default().fg(label_color)),
            Span::styled(
                if l.tabs.is_empty() { "" } else { " ⋯" },
                Style::default().fg(theme.overlay0),
            ),
        ]));
    }
    f.render_widget(Paragraph::new(lines), inner);
}

fn main_pane(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let lens = app.current_lens();

    // Sub-tab bar (human view only) for lenses that have tabs.
    let content = if !lens.tabs.is_empty() && app.format == seer_core::output::OutputFormat::Human {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(0)])
            .split(area);
        sub_tabs(f, chunks[0], app, theme);
        chunks[1]
    } else {
        area
    };

    // Pane-driven interactive lenses render from `app.panes` state, not from a
    // fetched `LensData`, so they never reach `LensState::Loaded`. They have no
    // raw serialization either, so render them the same way in every format —
    // otherwise toggling `r` would drop them to the generic "press /" idle hint.
    match lens.key {
        "follow" => {
            lenses::follow::render(f, content, theme, &app.panes.follow, app.spin);
            return;
        }
        "diff" => {
            let domain_a = app.panes.diff.effective_a(app.domain.as_deref());
            lenses::diff::render(
                f,
                content,
                theme,
                domain_a.as_deref(),
                &app.panes.diff.b,
                field_buf(&app.input_mode, EditTarget::DiffB),
                app.focus == Focus::Pane,
                app.state_of(app.lens),
            );
            return;
        }
        "bulk" => {
            lenses::bulk::render(
                f,
                content,
                theme,
                &app.panes.bulk,
                field_buf(&app.input_mode, EditTarget::BulkDomains),
                app.spin,
            );
            return;
        }
        "tld" => {
            let (loaded, loading) = match app.state_of(app.lens) {
                LensState::Loaded(LensData::Tld(t)) => (Some(t.as_ref()), false),
                LensState::Loading => (None, true),
                _ => (None, false),
            };
            lenses::tld::render(
                f,
                content,
                theme,
                &app.panes.tld,
                loaded,
                loading,
                field_buf(&app.input_mode, EditTarget::TldFilter),
            );
            return;
        }
        _ => {}
    }

    match app.state_of(app.lens) {
        LensState::Loading => {
            // Name what is actually being queried: an explicit request
            // (`:rdap 8.8.8.8`, `:rdap AS15169`) targets something other
            // than the session domain.
            let target = app
                .pending_target(app.lens)
                .or_else(|| app.domain.clone())
                .unwrap_or_default();
            let line = Line::from(Span::styled(
                format!("{} querying {target}…", SPIN[app.spin]),
                Style::default().fg(theme.overlay),
            ));
            f.render_widget(Paragraph::new(line), content);
            return;
        }
        LensState::Error(e) => {
            let block = panel::block(theme, lens.label, theme.red, false);
            let inner = block.inner(content);
            f.render_widget(block, content);
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    e.clone(),
                    Style::default().fg(theme.red),
                ))),
                inner,
            );
            return;
        }
        LensState::Idle => {
            // Tab-specific idle hints for the RDAP lens.
            let hint_text = if lens.key == "rdap" {
                match app.tab {
                    2 => "use :rdap AS<number>  (e.g. :rdap AS15169)",
                    1 => "use :rdap <ip>  or navigate to a domain first",
                    _ => "press / to look up a domain",
                }
            } else {
                "press / to look up a domain"
            };
            let hint = Line::from(Span::styled(hint_text, Style::default().fg(theme.overlay0)));
            f.render_widget(Paragraph::new(hint), content);
            return;
        }
        LensState::Loaded(_) => {}
    }

    // Raw view takes over for non-human formats.
    if app.format != seer_core::output::OutputFormat::Human {
        if let LensState::Loaded(data) = app.state_of(app.lens) {
            let text = crate::payload::serialize(data, app.format);
            let raw_title = format!("{} · raw", lens.label);
            let block = panel::block(theme, &raw_title, theme.green, false);
            let inner = block.inner(content);
            f.render_widget(block, content);
            f.render_widget(
                Paragraph::new(text).style(Style::default().fg(theme.subtext)),
                inner,
            );
        }
        return;
    }

    // Human view: dispatch to the lens renderer. Row-based lenses are filtered
    // centrally here (same `filter::apply` used by `App::row_count`) so the
    // renderer, selection, and scroll all see the same visible subset.
    if let LensState::Loaded(data) = app.state_of(app.lens) {
        let focused = app.focus == Focus::Pane;
        let filter = app.active_filter();
        let filtered = crate::tui::filter::apply(data, &filter);
        let render_data = filtered.as_ref().unwrap_or(data);
        lenses::render(
            f,
            content,
            theme,
            lens.key,
            app.tab,
            render_data,
            &filter,
            focused,
            app.sel,
            &app.panes,
        );
    }
}

fn sub_tabs(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let lens = app.current_lens();
    let mut spans = Vec::new();
    for (i, t) in lens.tabs.iter().enumerate() {
        let on = i == app.tab;
        spans.push(Span::styled(
            format!(" {t} "),
            Style::default().fg(if on { theme.mauve } else { theme.subtext }),
        ));
        spans.push(Span::raw(" "));
    }
    spans.push(Span::styled(
        "[ ] switch tab",
        Style::default().fg(theme.overlay0),
    ));
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn status_or_command(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    if let InputMode::Field {
        target: EditTarget::LensFilter,
        buf,
    } = &app.input_mode
    {
        let matches = app.row_count();
        let line = Line::from(vec![
            Span::styled(
                "filter> ",
                Style::default()
                    .fg(theme.mauve)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(buf.with_caret("█"), Style::default().fg(theme.text)),
            Span::styled(
                format!("   {matches} match(es)  [enter apply · esc cancel]"),
                Style::default().fg(theme.overlay0),
            ),
        ]);
        f.render_widget(
            Paragraph::new(line).style(Style::default().bg(theme.mantle)),
            area,
        );
        return;
    }
    if let InputMode::Command(buf) = &app.input_mode {
        let line = Line::from(vec![
            Span::styled(
                "seer> ",
                Style::default()
                    .fg(theme.mauve)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(buf.with_caret("█"), Style::default().fg(theme.text)),
        ]);
        f.render_widget(
            Paragraph::new(line).style(Style::default().bg(theme.mantle)),
            area,
        );
        return;
    }
    // Generic fallback for edit fields no pane draws inline (Follow
    // interval/count, bulk file path, watch add): without it the typed text
    // is invisible.
    if let InputMode::Field { target, buf } = &app.input_mode {
        if let Some(prompt) = status_prompt(app, *target) {
            let line = Line::from(vec![
                Span::styled(
                    prompt,
                    Style::default()
                        .fg(theme.mauve)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(buf.with_caret("█"), Style::default().fg(theme.text)),
                Span::styled(
                    "   [enter apply · esc cancel]",
                    Style::default().fg(theme.overlay0),
                ),
            ]);
            f.render_widget(
                Paragraph::new(line).style(Style::default().bg(theme.mantle)),
                area,
            );
            return;
        }
    }
    let lens = app.current_lens();
    let mut spans = vec![Span::styled(
        format!("{} {}  ", lens.glyph, lens.label),
        Style::default().fg(theme.lavender),
    )];
    if let Some(t) = &app.toast {
        spans.push(Span::styled(
            format!("● {}", t.msg),
            Style::default().fg(theme.tone(&t.tone)),
        ));
    }
    // Show an active committed in-lens filter (press `/` on the pane to edit).
    let active_filter = app.active_filter();
    if !active_filter.is_empty() {
        spans.push(Span::styled(
            format!("filter:/{}/  ", active_filter),
            Style::default().fg(theme.mauve),
        ));
    }
    spans.push(Span::raw("   "));
    for (k, t) in [
        ("j/k", "move"),
        ("tab", "focus"),
        ("[ ]", "tab"),
        ("r", "raw"),
        ("y", "copy"),
        ("/", "lookup"),
        (":", "cmd"),
        ("?", "help"),
    ] {
        spans.push(Span::styled(
            format!(" {k}"),
            Style::default().fg(theme.crust).bg(theme.overlay),
        ));
        spans.push(Span::styled(
            format!(" {t} "),
            Style::default().fg(theme.overlay0),
        ));
    }
    f.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(theme.mantle)),
        area,
    );
}

fn help_overlay(f: &mut Frame, area: Rect, theme: &Theme) {
    let rows = [
        ("j / k  ·  ↑ ↓", "move selection (nav or pane)"),
        ("1 … 9", "jump straight to a lens"),
        ("Tab", "toggle focus: nav ⇄ pane"),
        ("[ / ]", "switch sub-tabs (RDAP, DNS)"),
        ("↵ / l", "enter the active pane"),
        ("h / Esc", "back to nav"),
        ("g / G", "jump to top / bottom"),
        ("r", "raw output ⇄ human view"),
        ("y", "copy current output to clipboard"),
        ("/", "look up a domain"),
        (":", "command (lookup · dig · ssl · set output · theme · q)"),
        ("?", "this help · Esc closes"),
    ];
    let w = 60u16.min(area.width.saturating_sub(4));
    let h = (rows.len() as u16 + 4).min(area.height.saturating_sub(2));
    let popup = Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    };
    f.render_widget(Clear, popup);
    // Clear resets the popup cells to the terminal default; re-apply the
    // theme base so the overlay stays self-contained like the main canvas.
    f.render_widget(
        Block::default().style(Style::default().bg(theme.base).fg(theme.text)),
        popup,
    );
    let block = panel::block(theme, "keybindings", theme.lavender, true);
    let inner = block.inner(popup);
    f.render_widget(block, popup);
    let lines: Vec<Line> = rows
        .iter()
        .map(|(k, t)| {
            Line::from(vec![
                Span::styled(format!("{k:<16}"), Style::default().fg(theme.peach)),
                Span::styled(*t, Style::default().fg(theme.subtext)),
            ])
        })
        .collect();
    f.render_widget(Paragraph::new(lines), inner);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::app::App;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn full_buf(app: &App, theme: &Theme) -> String {
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|f| view(f, app, theme)).unwrap();
        let buf = terminal.backend().buffer();
        let area = buf.area();
        let mut s = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                s.push_str(buf[(x, y)].symbol());
            }
        }
        s
    }

    #[test]
    fn follow_lens_renders_its_pane_not_the_generic_hint() {
        let theme = Theme::frappe();
        let mut app = App::new(None);
        app.lens = lenses::find_by_cmd_or_key("follow").unwrap();
        let s = full_buf(&app, &theme);
        assert!(s.contains("s start"), "Follow pane (hints) should render");
        assert!(
            !s.contains("press / to look up a domain"),
            "Follow must not fall back to the generic idle hint"
        );
    }

    #[test]
    fn fields_without_an_inline_editor_are_echoed_in_the_status_bar() {
        let theme = Theme::frappe();
        let mut app = App::new(None);
        app.lens = lenses::find_by_cmd_or_key("follow").unwrap();
        let mut buf: LineEditor = "60".into();
        buf.left();
        app.input_mode = InputMode::Field {
            target: EditTarget::FollowInterval,
            buf,
        };
        let s = full_buf(&app, &theme);
        assert!(
            s.contains("interval seconds (now 30)> 6█0"),
            "typed interval (with caret at the cursor) must be visible"
        );

        for (target, prompt) in [
            (EditTarget::FollowCount, "check count (now 20)> "),
            (EditTarget::BulkPath, "domains file> "),
            (EditTarget::WatchAdd, "watch add> "),
        ] {
            app.input_mode = InputMode::Field {
                target,
                buf: "abc".into(),
            };
            let s = full_buf(&app, &theme);
            assert!(s.contains(&format!("{prompt}abc█")), "{target:?}");
        }
    }

    #[test]
    fn loading_indicator_names_the_requested_target() {
        use crate::tui::action::Msg;
        use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

        let theme = Theme::frappe();
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        let press = |app: &mut App, code: KeyCode| {
            let _ = app.update(Msg::Input(Event::Key(KeyEvent::new(
                code,
                KeyModifiers::NONE,
            ))));
        };
        press(&mut app, KeyCode::Char(':'));
        for c in "rdap 8.8.8.8".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        press(&mut app, KeyCode::Enter);
        let s = full_buf(&app, &theme);
        assert!(s.contains("querying 8.8.8.8"), "not the session domain");
    }

    #[test]
    fn shell_renders_without_panicking() {
        let theme = Theme::frappe();
        let app = App::new(None);
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|f| view(f, &app, &theme)).unwrap();
        let buf = terminal.backend().buffer();
        let area = buf.area();
        let mut s = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                s.push_str(buf[(x, y)].symbol());
            }
        }
        assert!(s.contains("seer"), "top-bar brand missing");
        assert!(s.contains("Overview"), "first lens label missing");
        assert!(s.contains("LOOKUP"), "group header missing");
    }

    /// Every canvas cell must carry the theme's base background: with Latte
    /// in a dark terminal, cells no widget paints otherwise keep the
    /// terminal's own background, rendering the theme as light bars floating
    /// on a dark canvas with near-invisible dark text.
    #[test]
    fn frame_canvas_is_painted_with_theme_base() {
        let mut app = App::new(None);
        assert!(app.set_theme_by_name("latte"));
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|f| view(f, &app, app.theme())).unwrap();
        let buffer = terminal.backend().buffer();
        let latte = Theme::latte();
        // Main-pane interior and nav-column cells that no widget backfills.
        for (x, y) in [(60u16, 15u16), (2, 20)] {
            assert_eq!(buffer[(x, y)].bg, latte.base, "cell ({x},{y})");
        }
    }

    /// The help popup must stay theme-painted too: `Clear` resets its cells
    /// to the terminal default, so the overlay needs its own base fill or it
    /// renders as a hole of terminal-default color in the painted canvas.
    #[test]
    fn help_overlay_keeps_theme_base_background() {
        let mut app = App::new(None);
        assert!(app.set_theme_by_name("latte"));
        app.help = true;
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|f| view(f, &app, app.theme())).unwrap();
        let buffer = terminal.backend().buffer();
        // Popup interior on a 100x30 frame (popup is 60x16 centered).
        assert_eq!(buffer[(50, 15)].bg, Theme::latte().base);
    }

    /// Draw with the App-owned theme (the call `mod.rs` makes each frame) and
    /// verify a live `:theme latte` swap actually recolors the frame.
    #[test]
    fn live_theme_swap_recolors_the_frame() {
        let top_bar_bg = |app: &App| {
            let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
            terminal.draw(|f| view(f, app, app.theme())).unwrap();
            terminal.backend().buffer()[(0, 0)].bg
        };

        let mut app = App::new(None);
        assert_eq!(top_bar_bg(&app), Theme::frappe().mantle);

        assert!(app.set_theme_by_name("latte"));
        assert_eq!(top_bar_bg(&app), Theme::latte().mantle);
        assert_ne!(Theme::frappe().mantle, Theme::latte().mantle);
    }
}
