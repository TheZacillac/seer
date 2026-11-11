//! Splits the frame into the four sections and the status row. Wide
//! frames put 1 Domain over 2 Function in a fixed left column and 3 Options
//! over 4 Details on the right; under `NARROW_W` columns everything stacks
//! and Function is one row (focusing it opens the list as a popup). Boxes
//! that touch overlap by one cell, so they share that border line (see
//! `widgets::panel`). The Options box is capped so Details always keeps
//! `MIN_DETAILS` rows.
use ratatui::layout::{Constraint, Layout, Rect};

/// The left column's width: the widest label plus glyph, cursor and border.
pub const LEFT_W: u16 = 24;
/// Below this many columns the sections stack.
pub const NARROW_W: u16 = 70;
/// Rows Details keeps however tall the Options box wants to be.
pub const MIN_DETAILS: u16 = 3;

/// Where each section and the status row sit.
pub struct Areas {
    pub domain: Rect,
    pub function: Rect,
    /// `None` when the lens shows no options.
    pub options: Option<Rect>,
    pub details: Rect,
    pub status: Rect,
    pub narrow: bool,
}

/// The sections of `area` for an Options box `options_rows` rows tall
/// (0 collapses it). A taller box is capped to leave Details `MIN_DETAILS`
/// rows, and one left with no room for a row collapses.
pub fn split(area: Rect, options_rows: u16) -> Areas {
    let [body, status] = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).areas(area);
    let narrow = area.width < NARROW_W;
    // Rows the body keeps for Options and Details together.
    let room = if narrow {
        body.height.saturating_sub(3 + 1)
    } else {
        body.height
    };
    // The shared border line counts for both boxes, hence the `+ 1`.
    let opt_h = if options_rows == 0 {
        0
    } else {
        (options_rows + 2).min((room + 1).saturating_sub(MIN_DETAILS))
    };
    // Borders alone leave no row for a field.
    let opt_h = if opt_h < 3 { 0 } else { opt_h };
    // Options and Details share a border line when both are drawn.
    let seam = u16::from(opt_h > 0);
    let (domain, function, options, details) = if narrow {
        let [domain, function, right] = Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .areas(body);
        let (options, details) = stack(right, opt_h, seam);
        (domain, function, options, details)
    } else {
        let [left, right] = Layout::horizontal([Constraint::Length(LEFT_W), Constraint::Min(0)])
            .spacing(-1)
            .areas(body);
        let [domain, function] = Layout::vertical([Constraint::Length(3), Constraint::Min(0)])
            .spacing(-1)
            .areas(left);
        let (options, details) = stack(right, opt_h, seam);
        (domain, function, options, details)
    };
    Areas {
        domain,
        function,
        options: (opt_h > 0).then_some(options),
        details,
        status,
        narrow,
    }
}

/// `area` as an Options box `opt_h` rows tall over Details, the two
/// overlapping by `seam` rows.
fn stack(area: Rect, opt_h: u16, seam: u16) -> (Rect, Rect) {
    let options = Rect {
        height: opt_h.min(area.height),
        ..area
    };
    let top = options.height.saturating_sub(seam);
    let details = Rect {
        y: area.y + top,
        height: area.height - top,
        ..area
    };
    (options, details)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_frames_put_domain_and_function_left() {
        let a = split(Rect::new(0, 0, 100, 30), 1);
        assert!(!a.narrow);
        let right = LEFT_W - 1;
        assert_eq!(a.domain, Rect::new(0, 0, LEFT_W, 3));
        assert_eq!(a.function, Rect::new(0, 2, LEFT_W, 27));
        assert_eq!(a.options, Some(Rect::new(right, 0, 100 - right, 3)));
        assert_eq!(a.details, Rect::new(right, 2, 100 - right, 27));
        assert_eq!(a.status, Rect::new(0, 29, 100, 1));
    }

    #[test]
    fn no_options_gives_details_the_full_height() {
        let a = split(Rect::new(0, 0, 80, 24), 0);
        assert_eq!(a.options, None);
        assert_eq!(a.details, Rect::new(LEFT_W - 1, 0, 81 - LEFT_W, 23));
    }

    #[test]
    fn narrow_frames_stack_with_a_one_row_function_line() {
        let a = split(Rect::new(0, 0, 60, 24), 2);
        assert!(a.narrow);
        assert_eq!(a.domain, Rect::new(0, 0, 60, 3));
        assert_eq!(a.function, Rect::new(0, 3, 60, 1));
        assert_eq!(a.options, Some(Rect::new(0, 4, 60, 4)));
        assert_eq!(a.details, Rect::new(0, 7, 60, 16));
    }

    #[test]
    fn a_tall_options_box_leaves_details_three_rows() {
        for (w, h) in [(100, 20), (60, 20), (100, 11), (60, 11)] {
            let a = split(Rect::new(0, 0, w, h), 500);
            assert!(a.details.height >= MIN_DETAILS, "{w}x{h}: {:?}", a.details);
            let o = a.options.expect("room for at least one row");
            assert!(o.height >= 3, "{w}x{h}: {o:?}");
            assert_eq!(o.bottom() - 1, a.details.y, "{w}x{h}: one shared line");
        }
    }

    #[test]
    fn options_collapse_when_no_row_fits() {
        // 5 rows: status 1, body 4 -> nothing left beside 3 rows of Details.
        assert_eq!(split(Rect::new(0, 0, 100, 5), 2).options, None);
        assert_eq!(split(Rect::new(0, 0, 60, 7), 2).options, None);
    }
}
