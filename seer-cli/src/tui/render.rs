//! Reads `&App` and draws the full frame: top bar, nav, main pane, status/cmd
//! bar, and the help overlay.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

use crate::tui::action::{EditTarget, Focus, InputMode, LensState};
use crate::tui::app::{App, SPIN};
use crate::tui::lenses::{self};
use crate::tui::theme::Theme;
use crate::tui::widgets::panel;

/// The in-progress edit buffer for `target`, if a matching field is active.
fn field_buf(mode: &InputMode, target: EditTarget) -> Option<&str> {
    match mode {
        InputMode::Field { target: t, buf } if *t == target => Some(buf.as_str()),
        _ => None,
    }
}

pub fn view(f: &mut Frame, app: &App, theme: &Theme) {
    let area = f.area();
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
        } => format!("⌕ {buf}▏"),
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
        let label_color = if !l.implemented {
            theme.overlay0
        } else if active {
            theme.text
        } else {
            theme.subtext
        };
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
            lenses::follow::render(f, content, theme, &app.panes.follow);
            return;
        }
        "diff" => {
            lenses::diff::render(
                f,
                content,
                theme,
                app.domain.as_deref(),
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
            );
            return;
        }
        _ => {}
    }

    match app.state_of(app.lens) {
        LensState::Loading => {
            let line = Line::from(Span::styled(
                format!(
                    "{} querying {}…",
                    SPIN[app.spin],
                    app.domain.as_deref().unwrap_or("")
                ),
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
            if !lens.implemented {
                lenses::placeholder::render(f, content, theme, lens.label);
            } else {
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
            }
            return;
        }
        LensState::Loaded(_) => {}
    }

    // Raw view takes over for non-human formats.
    if app.format != seer_core::output::OutputFormat::Human {
        if let LensState::Loaded(data) = app.state_of(app.lens) {
            let text = crate::tui::raw::serialize(data, app.format);
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

    // Human view: dispatch to the lens renderer.
    if let LensState::Loaded(data) = app.state_of(app.lens) {
        let focused = app.focus == Focus::Pane;
        lenses::render(
            f, content, theme, lens.key, app.tab, data, focused, app.sel, &app.panes,
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
    if let InputMode::Command(buf) = &app.input_mode {
        let line = Line::from(vec![
            Span::styled(
                "seer> ",
                Style::default()
                    .fg(theme.mauve)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("{buf}█"), Style::default().fg(theme.text)),
        ]);
        f.render_widget(
            Paragraph::new(line).style(Style::default().bg(theme.mantle)),
            area,
        );
        return;
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
        (":", "command (lookup · dig · ssl · set output · q)"),
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
        app.lens = crate::tui::lenses::find_by_cmd_or_key("follow").unwrap();
        let s = full_buf(&app, &theme);
        assert!(s.contains("s start"), "Follow pane (hints) should render");
        assert!(
            !s.contains("press / to look up a domain"),
            "Follow must not fall back to the generic idle hint"
        );
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
}
