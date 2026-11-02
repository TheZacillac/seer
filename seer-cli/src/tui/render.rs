//! Reads `&App` and draws the full frame: the four numbered sections (1 Domain,
//! 2 Function, 3 Options, 4 Details) placed by `layout`, the status/command
//! bar, and the switcher and help overlays. Narrow frames show Function as a
//! one-row line and open the list as a popup while it has focus.

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph, Wrap};
use ratatui::Frame;
use seer_core::output::sanitize_line;

use crate::tui::action::{EditTarget, InputMode, LensData, LensKey, LensState, Section};
use crate::tui::app::{App, SPIN};
use crate::tui::layout;
use crate::tui::lenses;
use crate::tui::line_editor::LineEditor;
use crate::tui::options::OptId;
use crate::tui::theme::Theme;
use crate::tui::widgets::{self, function_list, inspector, page, panel};

/// The in-progress editor for `target`, if a matching field is active (the
/// editor, not just its text, so renderers can place the caret at the cursor).
fn field_buf(mode: &InputMode, target: EditTarget) -> Option<&LineEditor> {
    match mode {
        InputMode::Field { target: t, buf } if *t == target => Some(buf),
        _ => None,
    }
}

/// Status-bar prompt for edit fields that no pane draws inline. `None` means
/// the field is rendered elsewhere (the domain box, its lens, or the filter line) —
/// the match is exhaustive so a new field can't silently go undrawn again.
fn status_prompt(target: EditTarget) -> Option<&'static str> {
    match target {
        EditTarget::WatchAdd => Some("watch add> "),
        EditTarget::Target
        | EditTarget::TldFilter
        | EditTarget::LensFilter
        | EditTarget::Switcher
        | EditTarget::Option(_) => None,
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
    let fields = option_fields(app);
    let inner_w = if area.width < layout::NARROW_W {
        area.width
    } else {
        area.width.saturating_sub(layout::LEFT_W)
    }
    .saturating_sub(2);
    let (opt_lines, cursor_row) =
        widgets::options::rows(theme, &fields, inner_w, app.section == Section::Options);
    let rows = if fields.is_empty() {
        0
    } else {
        u16::try_from(opt_lines.len()).unwrap_or(u16::MAX)
    };
    let a = layout::split(area, rows);

    domain_box(f, a.domain, app, theme);
    if a.narrow {
        function_line(f, a.function, app, theme);
    } else {
        function_list::draw(
            f,
            a.function,
            theme,
            app.lens,
            app.section == Section::Function,
        );
    }
    if let Some(r) = a.options {
        let title = Section::Options.title("Options");
        let inner = panel::render(
            f,
            r,
            theme,
            &title,
            theme.mauve,
            app.section == Section::Options,
        );
        // A capped box scrolls to keep the cursor field's row in view.
        let top = (cursor_row + 1).saturating_sub(usize::from(inner.height));
        let top = u16::try_from(top).unwrap_or(u16::MAX);
        f.render_widget(Paragraph::new(opt_lines).scroll((top, 0)), inner);
    }
    main_pane(f, a.details, app, theme);
    status_or_command(f, a.status, app, theme);

    if a.narrow && app.section == Section::Function {
        let want = u16::try_from(lenses::lenses().len() + 6).unwrap_or(u16::MAX);
        let popup = Rect {
            height: a.details.height.min(want),
            ..a.details
        };
        f.render_widget(Clear, popup);
        function_list::draw(f, popup, theme, app.lens, true);
    }
    if let Some(buf) = field_buf(&app.input_mode, EditTarget::Switcher) {
        switcher(f, area, buf, theme);
    }
    if app.help {
        help_overlay(f, area, app, theme);
    }
}

/// The current lens's visible options as Options-box fields.
fn option_fields(app: &App) -> Vec<widgets::options::Field<'_>> {
    let key = app.current_lens().key;
    app.visible_options()
        .into_iter()
        .enumerate()
        .map(|(i, spec)| {
            let (value, placeholder) = app.options.display(key, spec);
            widgets::options::Field {
                label: spec.label,
                value,
                placeholder,
                selected: i == app.opt_cursor,
                editing: field_buf(&app.input_mode, EditTarget::Option(spec.id)),
                invalid: app.opt_error == Some(spec.id),
            }
        })
        .collect()
}

fn domain_box(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let title = Section::Domain.title("Domain");
    let inner = panel::render(
        f,
        area,
        theme,
        &title,
        theme.mauve,
        app.section == Section::Domain,
    );
    let (text, style) = match field_buf(&app.input_mode, EditTarget::Target) {
        Some(buf) => (buf.with_caret("▏"), Style::default().fg(theme.text)),
        None => match app.domain.as_deref() {
            Some(d) => (d.to_string(), Style::default().fg(theme.text)),
            None => (
                "type a domain".to_string(),
                Style::default().fg(theme.overlay0),
            ),
        },
    };
    // A domain wider than the box shows its tail (and the caret).
    let room = usize::from(inner.width).saturating_sub(2);
    let line = Line::from(vec![
        Span::styled("⌕ ", Style::default().fg(theme.overlay)),
        Span::styled(widgets::fit_tail(&sanitize_line(&text), room), style),
    ]);
    f.render_widget(Paragraph::new(line), inner);
}

/// The narrow frame's one-row stand-in for the function list.
fn function_line(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let l = app.current_lens();
    let style = if app.section == Section::Function {
        Style::default().fg(theme.base).bg(theme.mauve)
    } else {
        Style::default().fg(theme.subtext)
    };
    let text = format!(
        " {} {} › {} {} ",
        Section::Function.number(),
        l.group,
        l.glyph,
        l.label
    );
    f.render_widget(Paragraph::new(Line::from(Span::styled(text, style))), area);
}

/// The Details section's title: `4 <title>`, with the spinner while loading.
fn details_title(app: &App, title: &str) -> String {
    let t = Section::Details.title(title);
    match app.state_of(app.lens) {
        LensState::Loading => format!("{t}  {} resolving…", SPIN[app.spin]),
        _ => t,
    }
}

fn main_pane(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let lens = app.current_lens();
    let focused = app.section == Section::Details;

    // Pane-driven interactive lenses render from `app.panes` state, not from a
    // fetched `LensData`, so they never reach `LensState::Loaded`. They have no
    // raw serialization either, so render them the same way in every format —
    // otherwise toggling `r` would drop them to the generic "press /" idle hint.
    let pane_page = match lens.key {
        LensKey::Follow => Some(lenses::follow::page(
            theme,
            &app.panes.follow,
            app.options.follow_run(),
            app.spin,
        )),
        LensKey::Diff => {
            let domain_a = app.panes.diff.effective_a(app.domain.as_deref());
            let b = app
                .options
                .text(LensKey::Diff, OptId::SecondDomain)
                .unwrap_or_default();
            Some(lenses::diff::page(
                theme,
                domain_a.as_deref(),
                &b,
                app.state_of(app.lens),
            ))
        }
        LensKey::Bulk => Some(lenses::bulk::page(theme, &app.panes.bulk, app.spin)),
        LensKey::Tld => {
            let (loaded, loading) = match app.state_of(app.lens) {
                LensState::Loaded(LensData::Tld(t)) => (Some(t.as_ref()), false),
                LensState::Loading => (None, true),
                _ => (None, false),
            };
            Some(lenses::tld::page(
                theme,
                &app.panes.tld,
                loaded,
                loading,
                field_buf(&app.input_mode, EditTarget::TldFilter),
            ))
        }
        _ => None,
    };
    if let Some(mut p) = pane_page {
        p.title = details_title(app, &p.title);
        page::draw(f, area, theme, p, focused);
        return;
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
            let title = details_title(app, lens.label);
            let inner = panel::render(f, area, theme, &title, theme.overlay, focused);
            f.render_widget(Paragraph::new(line), inner);
            return;
        }
        LensState::Error(e) => {
            let title = details_title(app, lens.label);
            let inner = panel::render(f, area, theme, &title, theme.red, focused);
            // Errors quote remote servers: one sanitized line, wrapped to
            // the panel rather than clipped at its edge.
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    sanitize_line(e),
                    Style::default().fg(theme.red),
                )))
                .wrap(Wrap { trim: false }),
                inner,
            );
            return;
        }
        LensState::Idle => {
            let rdap_query = app.options.choice(LensKey::Rdap, OptId::RdapQuery);
            let hint_text = match (lens.key, rdap_query, app.domain.as_deref()) {
                // Query-specific idle hints for the RDAP lens.
                (LensKey::Rdap, Some(2), _) => {
                    "use :rdap AS<number>  (e.g. :rdap AS15169)".to_string()
                }
                (LensKey::Rdap, Some(1), _) => "use :rdap <ip>  or run Records first".to_string(),
                // A heavy lens waits for ↵ rather than scanning on navigation.
                (_, _, Some(domain)) if lens.heavy => format!(
                    "press ↵ to run {} for {domain}  (active scan: CT logs + HTTP probes)",
                    lens.label
                ),
                _ => "type a domain in 1 Domain".to_string(),
            };
            let hint = Line::from(Span::styled(hint_text, Style::default().fg(theme.overlay0)));
            let title = details_title(app, lens.label);
            let inner = panel::render(f, area, theme, &title, theme.overlay, focused);
            f.render_widget(Paragraph::new(hint), inner);
            return;
        }
        LensState::Loaded(_) => {}
    }

    // Raw view takes over for non-human formats. It scrolls (PgUp/PgDn, or
    // j/k once focused); each line is sanitized, since serializers escape
    // control characters but pass other terminal sequences (U+009B CSI).
    if app.format != seer_core::output::OutputFormat::Human {
        if let LensState::Loaded(data) = app.state_of(app.lens) {
            let text = crate::payload::serialize(data, app.format);
            let lines: Vec<Line> = text.lines().map(|l| Line::from(sanitize_line(l))).collect();
            let total = lines.len();
            let raw_title = details_title(app, &format!("{} · raw", lens.label));
            let inner = panel::render(f, area, theme, &raw_title, theme.green, focused);
            // Stop once the last line reaches the panel's bottom.
            let max = total.saturating_sub(usize::from(inner.height));
            let top = usize::from(app.raw_scroll).min(max);
            let top = u16::try_from(top).unwrap_or(u16::MAX);
            f.render_widget(
                Paragraph::new(lines)
                    .style(Style::default().fg(theme.subtext))
                    .scroll((top, 0)),
                inner,
            );
        }
        return;
    }

    // Human view: dispatch to the lens renderer. Row-based lenses are filtered
    // centrally here (same `filter::apply` used by `App::row_count`) so the
    // renderer, selection, and scroll all see the same visible subset.
    if let LensState::Loaded(data) = app.state_of(app.lens) {
        let filter = app.active_filter();
        let filtered = crate::tui::filter::apply(data, &filter);
        let render_data = filtered.as_ref().unwrap_or(data);
        // The RDAP renderer's label only; other lenses ignore it.
        let rdap_query = app
            .options
            .choice(LensKey::Rdap, OptId::RdapQuery)
            .unwrap_or(0);
        if let Some(mut p) = lenses::page(
            theme,
            lens.key,
            rdap_query,
            render_data,
            &filter,
            focused,
            app.sel,
        ) {
            p.title = details_title(app, &p.title);
            page::draw(f, area, theme, p, focused);
        }
    }
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
    // Generic fallback for edit fields no pane draws inline (watch add):
    // without it the typed text is invisible.
    if let InputMode::Field { target, buf } = &app.input_mode {
        if let Some(prompt) = status_prompt(*target) {
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
    // Narrow frames drop the brand so the hints (and `? help`) fit.
    let mut spans = Vec::new();
    if area.width >= layout::NARROW_W {
        spans.push(Span::styled(
            "🔮 seer  ",
            Style::default()
                .fg(theme.mauve)
                .add_modifier(Modifier::BOLD),
        ));
    }
    if app.format != seer_core::output::OutputFormat::Human {
        spans.push(Span::styled(
            format!("--format {:?}  ", app.format).to_lowercase(),
            Style::default().fg(theme.green),
        ));
    }
    if let Some(t) = &app.toast {
        spans.push(Span::styled(
            format!("● {}", sanitize_line(&t.msg)),
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
    spans.push(Span::raw(" "));
    // The focused section lists the keys that act in it.
    let keys: Vec<(String, &str)> = match app.section {
        Section::Domain => vec![
            ("↵".into(), "apply"),
            ("esc".into(), "revert"),
            ("tab".into(), "next"),
        ],
        Section::Options => vec![
            ("j/k".into(), "field"),
            ("h/l".into(), "change"),
            ("↵".into(), "edit · run"),
            ("esc".into(), "back"),
            ("?".into(), "help"),
        ],
        Section::Details => {
            let mut keys: Vec<(String, &str)> =
                lens.keys.iter().map(|h| (h.label(), h.what)).collect();
            if lens.filterable() {
                keys.push(("/".into(), "filter"));
            }
            keys.extend([("esc".into(), "back"), ("?".into(), "help")]);
            keys
        }
        Section::Function => [
            ("j/k", "move"),
            ("tab", "section"),
            ("␣", "go to"),
            ("r", "raw"),
            ("y", "copy"),
            (":", "cmd"),
            ("?", "help"),
        ]
        .into_iter()
        .map(|(k, t)| (k.to_string(), t))
        .collect(),
    };
    // Too many hints for the row: drop from the end, keeping the closing
    // `? help` (when the section has one), so the most local keys stay.
    let used: usize = spans.iter().map(Span::width).sum();
    let hint_w =
        |(k, t): &(String, &str)| Span::raw(k.as_str()).width() + 1 + Span::raw(*t).width() + 2;
    let mut keys = keys;
    while keys.len() > 1 && used + keys.iter().map(hint_w).sum::<usize>() > usize::from(area.width)
    {
        let drop = if keys.last().is_some_and(|(k, _)| k == "?") {
            keys.len() - 2
        } else {
            keys.len() - 1
        };
        keys.remove(drop);
    }
    for (k, t) in keys {
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

/// The `Space` switcher: the query, then the lenses it matches, best first
/// (highlighted: the one `↵` goes to).
fn switcher(f: &mut Frame, area: Rect, buf: &LineEditor, theme: &Theme) {
    let all = lenses::lenses();
    let matches = lenses::switch_matches(buf.as_str());
    let mut lines = vec![Line::from(vec![
        Span::styled("> ", Style::default().fg(theme.mauve)),
        Span::styled(buf.with_caret("▏"), Style::default().fg(theme.text)),
    ])];
    if matches.is_empty() {
        lines.push(Line::from(Span::styled(
            "no lens matches",
            Style::default().fg(theme.overlay0),
        )));
    }
    for (n, &i) in matches.iter().enumerate() {
        let l = &all[i];
        lines.push(
            Line::from(vec![
                Span::styled(format!("{} ", l.glyph), Style::default().fg(theme.lavender)),
                Span::raw(format!("{:<14}", l.label)),
                Span::styled(l.group, Style::default().fg(theme.overlay0)),
            ])
            .style(widgets::row_style(theme, n == 0)),
        );
    }
    let w = 40u16.min(area.width.saturating_sub(4));
    let h = u16::try_from(lines.len() + 2)
        .unwrap_or(u16::MAX)
        .min(area.height.saturating_sub(2));
    let popup = Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 3,
        width: w,
        height: h,
    };
    f.render_widget(Clear, popup);
    f.render_widget(
        Block::default().style(Style::default().bg(theme.base).fg(theme.text)),
        popup,
    );
    let inner = panel::render(f, popup, theme, "go to", theme.mauve, true);
    f.render_widget(Paragraph::new(lines), inner);
}

/// Width of the key column in the help overlay.
const HELP_KEY_COL: usize = 16;

fn help_overlay(f: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let global = [
        ("Tab / Shift-Tab", "next / previous section"),
        ("1 2 3 4", "Domain · Function · Options · Details"),
        ("j / k  ·  ↑ ↓", "move (functions, fields, rows)"),
        ("h / l  ·  ← →", "change the selected option"),
        ("↵", "edit an option · run · open"),
        ("{ / }", "previous / next group"),
        ("Space", "go to any function by name"),
        ("Esc", "close · back to Function"),
        ("g / G", "jump to top / bottom"),
        ("r", "raw output ⇄ human view"),
        ("PgUp / PgDn", "scroll the raw view (j / k in Details)"),
        ("y", "copy current output to clipboard"),
        ("/", "edit the domain · filter rows in Details"),
        (":", "command (lookup · dig · ssl · set output · theme · q)"),
        ("?", "this help · Esc closes"),
    ];
    let lens = app.current_lens();
    let lens_rows: Vec<(String, &str)> = lens.keys.iter().map(|h| (h.label(), h.what)).collect();
    let row = |(k, t): (&str, &str)| {
        Line::from(vec![
            Span::styled(
                format!("{k:<HELP_KEY_COL$}"),
                Style::default().fg(theme.peach),
            ),
            Span::styled(t.to_string(), Style::default().fg(theme.subtext)),
        ])
    };
    // The focused lens's own keys lead, so on a short terminal the rows cut
    // off (and marked) are global ones the status bar also lists.
    let mut lines: Vec<Line> = Vec::new();
    if !lens_rows.is_empty() {
        lines.push(Line::from(Span::styled(
            format!("{} {} keys", lens.glyph, lens.label),
            Style::default().fg(theme.lavender),
        )));
        lines.extend(lens_rows.iter().map(|(k, t)| row((k.as_str(), *t))));
        lines.push(Line::default());
    }
    lines.extend(global.iter().copied().map(row));
    // Wide enough for the longest row (border + padding), never past the frame.
    let longest = lines.iter().map(Line::width).max().unwrap_or(0);
    let w = u16::try_from(longest + 4)
        .unwrap_or(u16::MAX)
        .max(60)
        .min(area.width.saturating_sub(4));
    let rows = u16::try_from(lines.len() + 4).unwrap_or(u16::MAX);
    let h = rows.min(area.height.saturating_sub(2));
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
    let inner = panel::render(f, popup, theme, "keybindings", theme.lavender, true);
    inspector::draw(f, inner, theme, lines);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::app::App;
    use crate::tui::test_util::{render_buffer, render_lines, render_text};

    fn full_buf(app: &App, theme: &Theme) -> String {
        render_text(100, 30, |f| view(f, app, theme))
    }

    #[test]
    fn the_frame_shows_four_numbered_sections() {
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        app.lens = LensKey::Dns.index();
        let s = render_lines(100, 30, |f| view(f, &app, app.theme()));
        for title in ["1 Domain", "2 Function", "3 Options", "4 Records"] {
            assert!(s.contains(title), "missing {title}:\n{s}");
        }
        assert!(s.contains("example.com"));
        assert!(s.contains("Type ‹A›"), "{s}");
    }

    const LONG_DOMAIN: &str = "aaaaaaaaaabbbbbbbbbbcccccccccc.example.com";

    #[test]
    fn a_long_domain_shows_its_tail_and_the_caret_at_80x24() {
        let mut app = App::new(Some(LONG_DOMAIN.into()));
        let _ = app.take_startup_actions();
        app.lens = LensKey::Dns.index();
        // Idle: the tail of the domain behind a `…`.
        let s = render_lines(80, 24, |f| view(f, &app, app.theme()));
        let row = s.lines().nth(1).unwrap_or_default();
        assert!(row.contains("⌕ …") && row.contains("example.com│"), "{row}");
        // Editing: the caret at the end stays visible.
        app.set_section(Section::Domain);
        let s = render_lines(80, 24, |f| view(f, &app, app.theme()));
        let row = s.lines().nth(1).unwrap_or_default();
        assert!(row.contains("…") && row.contains("example.com▏"), "{row}");
    }

    #[test]
    fn a_long_bulk_domains_editor_keeps_its_caret_in_the_options_box() {
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        app.lens = LensKey::Bulk.index();
        app.set_section(Section::Options);
        app.input_mode = InputMode::Field {
            target: EditTarget::Option(OptId::BulkDomains),
            buf: "one.example.com two.example.com three.example.com four.example.com".into(),
        };
        let s = render_lines(80, 24, |f| view(f, &app, app.theme()));
        assert!(s.contains("four.example.com▏›"), "{s}");
    }

    /// Details keeps its rows when the Options box is capped, and the box
    /// scrolls to the cursor field.
    #[test]
    fn a_capped_options_box_scrolls_to_the_cursor_field() {
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        app.lens = LensKey::Bulk.index();
        app.set_section(Section::Options);
        app.opt_cursor = app.visible_options().len() - 1;
        // 40×11: one Options row fits, but Bulk's fields wrap onto two.
        let s = render_lines(40, 11, |f| view(f, &app, app.theme()));
        assert!(s.contains("Domains"), "the last field is in view:\n{s}");
        assert!(!s.contains("Source"), "the row above scrolled away:\n{s}");
        assert!(s.contains("4 Bulk"), "Details keeps its box:\n{s}");
    }

    #[test]
    fn narrow_status_rows_drop_the_brand_to_fit_the_help_hint() {
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        app.lens = LensKey::Dns.index();
        for section in [Section::Function, Section::Options, Section::Details] {
            app.set_section(section);
            let s = render_lines(60, 24, |f| view(f, &app, app.theme()));
            let status = s.lines().last().unwrap_or_default().trim_end();
            assert!(status.ends_with("help"), "{section:?}: {status}");
            assert!(!status.contains("seer"), "{section:?}: {status}");
        }
    }

    #[test]
    fn options_collapse_for_a_function_without_any() {
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        app.lens = LensKey::Whois.index();
        let s = render_lines(100, 30, |f| view(f, &app, app.theme()));
        assert!(!s.contains("3 Options"), "{s}");
    }

    // Review Focus 4.
    #[test]
    fn tiny_and_narrow_frames_render() {
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        app.lens = LensKey::Bulk.index();
        for (w, h) in [(40, 12), (69, 20), (80, 24), (20, 5)] {
            let s = render_lines(w, h, |f| view(f, &app, app.theme()));
            assert!(
                s.lines().last().unwrap().contains("help"),
                "{w}×{h} status row:\n{s}"
            );
        }
        app.set_section(Section::Function);
        let s = render_lines(60, 24, |f| view(f, &app, app.theme()));
        assert!(s.contains("POWER › ⧉ Bulk"), "narrow function line:\n{s}");
        assert!(
            s.contains("Function") && s.contains("▸ ⧉ Bulk"),
            "narrow Function focus opens the list popup:\n{s}"
        );
    }

    #[test]
    fn the_focused_option_editor_draws_inline() {
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        app.lens = LensKey::Diff.index();
        app.set_section(Section::Options);
        app.input_mode = InputMode::Field {
            target: EditTarget::Option(OptId::SecondDomain),
            buf: "other.o".into(),
        };
        let s = render_lines(100, 30, |f| view(f, &app, app.theme()));
        assert!(s.contains("other.o▏"), "{s}");
    }

    #[test]
    fn switcher_popup_lists_matches() {
        use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
        let mut app = App::new(None);
        app.set_section(Section::Function); // past the Domain field
        for c in [' ', 's', 'u', 'b'] {
            app.update(crate::tui::action::Msg::Input(Event::Key(KeyEvent::new(
                KeyCode::Char(c),
                KeyModifiers::NONE,
            ))));
        }
        let s = render_lines(100, 30, |f| view(f, &app, app.theme()));
        assert!(s.contains("go to"), "{s}");
        assert!(s.contains("Subdomains") && s.contains("SECURITY"), "{s}");
    }

    /// At 80 columns the Function hints still end with `? help`.
    #[test]
    fn the_status_bar_fits_its_help_hint_at_80_columns() {
        let mut app = App::new(None);
        app.lens = LensKey::Audit.index();
        app.set_section(Section::Function);
        let s = render_lines(80, 24, |f| view(f, &app, app.theme()));
        let status = s.lines().last().unwrap_or_default();
        assert!(status.contains("? help"), "{status}");
        assert!(!status.contains("[ ]"), "no sub-tab hint remains: {status}");
    }

    #[test]
    fn help_overlay_rows_are_not_clipped() {
        let mut app = App::new(None);
        app.help = true;
        let s = render_lines(100, 30, |f| view(f, &app, app.theme()));
        assert!(s.contains("theme · q)"), "the : row must render whole: {s}");
    }

    /// On a short terminal the lens's own keys come first, so the cut falls
    /// on the global rows, never on the lens's keys.
    #[test]
    fn help_overlay_keeps_every_lens_key_on_a_small_terminal() {
        let mut app = App::new(None);
        app.lens = LensKey::Bulk.index();
        app.help = true;
        let s = render_lines(80, 18, |f| view(f, &app, app.theme()));
        assert!(s.contains(&format!("{:<16}export", "e")), "{s}");
        assert!(
            s.contains("more lines"),
            "the cut global rows are marked: {s}"
        );
    }

    #[test]
    fn help_overlay_lists_the_current_lens_keys() {
        let mut app = App::new(None);
        app.lens = LensKey::Follow.index();
        app.help = true;
        let s = render_lines(100, 40, |f| view(f, &app, app.theme()));
        // The overlay's own row format: the key padded to its 16-col column.
        assert!(s.contains("Follow keys"), "{s}");
        assert!(s.contains(&format!("{:<16}start", "↵")), "{s}");
        assert!(s.contains(&format!("{:<16}stop", "x")), "{s}");
    }

    #[test]
    fn status_bar_shows_lens_keys_when_the_pane_is_focused() {
        let mut app = App::new(None);
        app.lens = LensKey::Follow.index();
        // Only the status bar (last row) is checked.
        let status = |app: &App| {
            render_lines(140, 30, |f| view(f, app, app.theme()))
                .lines()
                .last()
                .unwrap_or_default()
                .to_string()
        };
        assert!(!status(&app).contains("stop"), "{}", status(&app));
        app.set_section(Section::Details);
        assert!(status(&app).contains("stop"), "{}", status(&app));
    }

    #[test]
    fn follow_lens_renders_its_pane_not_the_generic_hint() {
        let theme = Theme::frappe();
        let mut app = App::new(None);
        app.lens = lenses::find_by_cmd_or_key("follow").unwrap();
        let s = full_buf(&app, &theme);
        assert!(s.contains("waiting"), "Follow pane should render");
        assert!(
            !s.contains("type a domain in 1 Domain"),
            "Follow must not fall back to the generic idle hint"
        );
    }

    #[test]
    fn fields_without_an_inline_editor_are_echoed_in_the_status_bar() {
        let theme = Theme::frappe();
        let mut app = App::new(None);
        app.lens = lenses::find_by_cmd_or_key("watch").unwrap();
        let mut buf: LineEditor = "ab".into();
        buf.left();
        app.input_mode = InputMode::Field {
            target: EditTarget::WatchAdd,
            buf,
        };
        let s = full_buf(&app, &theme);
        assert!(
            s.contains("watch add> a█b"),
            "typed text (with caret at the cursor) must be visible: {s}"
        );
    }

    /// A lens error quotes the remote server: it was rendered raw and
    /// clipped at the panel edge.
    #[test]
    fn lens_errors_are_sanitized_and_wrapped() {
        let theme = Theme::frappe();
        let mut app = App::new(None);
        app.update(crate::tui::action::Msg::Data {
            lens: LensKey::Overview,
            gen: 0,
            result: Err(format!(
                "whois.example.test said \u{1b}[2J{} END",
                "x ".repeat(60)
            )),
        });
        let s = render_text(100, 30, |f| view(f, &app, &theme));
        assert!(!s.contains('\u{1b}'), "{s:?}");
        assert!(s.contains("END"), "the tail wraps into view: {s}");
    }

    /// Navigating onto a heavy lens says how to run it.
    #[test]
    fn a_heavy_lens_waits_for_enter() {
        let theme = Theme::frappe();
        let mut app = App::new(Some("example.com".into()));
        let _ = app.take_startup_actions();
        app.lens = LensKey::Takeover.index();
        let s = full_buf(&app, &theme);
        assert!(s.contains("press ↵ to run Takeover for example.com"), "{s}");
    }

    #[test]
    fn the_raw_view_scrolls() {
        use crate::payload::fixtures;
        use seer_core::RecordType;

        let theme = Theme::frappe();
        let mut app = App::new(None);
        app.lens = LensKey::Dns.index();
        app.update(crate::tui::action::Msg::Data {
            lens: LensKey::Dns,
            gen: 0,
            result: Ok(LensData::Dig(Box::new(fixtures::dig(
                RecordType::A,
                vec![fixtures::a("www.seer.test", "192.0.2.7")],
            )))),
        });
        app.format = seer_core::output::OutputFormat::Json;
        let top = render_text(100, 14, |f| view(f, &app, &theme));
        assert!(top.contains("\"status\": \"NOERROR\""), "{top}");
        app.raw_scroll = 6;
        let scrolled = render_text(100, 14, |f| view(f, &app, &theme));
        assert!(!scrolled.contains("\"status\": \"NOERROR\""), "{scrolled}");
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

    /// `r` swaps the DNS lens for the raw dig result: the JSON object the
    /// CLI's `seer dig --format json` prints.
    #[test]
    fn raw_view_shows_the_dig_result_object() {
        use crate::payload::fixtures;
        use seer_core::RecordType;

        let theme = Theme::frappe();
        let mut app = App::new(None);
        app.lens = lenses::find_by_cmd_or_key("dns").unwrap();
        app.update(crate::tui::action::Msg::Data {
            lens: LensKey::Dns,
            gen: 0,
            result: Ok(LensData::Dig(Box::new(fixtures::dig(
                RecordType::A,
                vec![fixtures::a("www.seer.test", "192.0.2.7")],
            )))),
        });
        let human = full_buf(&app, &theme);
        assert!(human.contains("● NOERROR"), "{human}");
        app.format = seer_core::output::OutputFormat::Json;
        let raw = full_buf(&app, &theme);
        assert!(raw.contains("Records · raw"), "{raw}");
        assert!(raw.contains("\"status\": \"NOERROR\""), "{raw}");
        assert!(raw.contains("\"address\": \"192.0.2.7\""), "{raw}");
    }

    #[test]
    fn shell_renders_without_panicking() {
        let theme = Theme::frappe();
        let app = App::new(None);
        let s = full_buf(&app, &theme);
        assert!(s.contains("seer"), "status-bar brand missing");
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
        let buffer = render_buffer(100, 30, |f| view(f, &app, app.theme()));
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
        let buffer = render_buffer(100, 30, |f| view(f, &app, app.theme()));
        // Popup interior on a 100x30 frame (popup is 60x16 centered).
        assert_eq!(buffer[(50, 15)].bg, Theme::latte().base);
    }

    /// Draw with the App-owned theme (the call `mod.rs` makes each frame) and
    /// verify a live `:theme latte` swap actually recolors the frame.
    #[test]
    fn live_theme_swap_recolors_the_frame() {
        // The status row's background is the mantle.
        let status_bg =
            |app: &App| render_buffer(100, 30, |f| view(f, app, app.theme()))[(0, 29)].bg;

        let mut app = App::new(None);
        assert_eq!(status_bg(&app), Theme::frappe().mantle);

        assert!(app.set_theme_by_name("latte"));
        assert_eq!(status_bg(&app), Theme::latte().mantle);
        assert_ne!(Theme::frappe().mantle, Theme::latte().mantle);
    }
}
