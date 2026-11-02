//! Splits the frame into the four sections and the status row. Wide
//! frames put 1 Domain over 2 Function in a fixed left column and 3 Options
//! over 4 Details on the right; under `NARROW_W` columns everything stacks
//! and Function is one row (focusing it opens the list as a popup).
use ratatui::layout::{Constraint, Layout, Rect};

/// The left column's width: the widest label plus glyph, cursor and border.
pub const LEFT_W: u16 = 24;
/// Below this many columns the sections stack.
pub const NARROW_W: u16 = 70;

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
/// (0 collapses it).
pub fn split(area: Rect, options_rows: u16) -> Areas {
    let [body, status] = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).areas(area);
    let opt_h = if options_rows == 0 {
        0
    } else {
        options_rows + 2
    };
    let narrow = area.width < NARROW_W;
    let (domain, function, options, details) = if narrow {
        let [domain, function, options, details] = Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(opt_h),
            Constraint::Min(0),
        ])
        .areas(body);
        (domain, function, options, details)
    } else {
        let [left, right] =
            Layout::horizontal([Constraint::Length(LEFT_W), Constraint::Min(0)]).areas(body);
        let [domain, function] =
            Layout::vertical([Constraint::Length(3), Constraint::Min(0)]).areas(left);
        let [options, details] =
            Layout::vertical([Constraint::Length(opt_h), Constraint::Min(0)]).areas(right);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_frames_put_domain_and_function_left() {
        let a = split(Rect::new(0, 0, 100, 30), 1);
        assert!(!a.narrow);
        assert_eq!(a.domain, Rect::new(0, 0, LEFT_W, 3));
        assert_eq!(a.function, Rect::new(0, 3, LEFT_W, 26));
        assert_eq!(a.options, Some(Rect::new(LEFT_W, 0, 100 - LEFT_W, 3)));
        assert_eq!(a.details, Rect::new(LEFT_W, 3, 100 - LEFT_W, 26));
        assert_eq!(a.status, Rect::new(0, 29, 100, 1));
    }

    #[test]
    fn no_options_gives_details_the_full_height() {
        let a = split(Rect::new(0, 0, 80, 24), 0);
        assert_eq!(a.options, None);
        assert_eq!(a.details, Rect::new(LEFT_W, 0, 80 - LEFT_W, 23));
    }

    #[test]
    fn narrow_frames_stack_with_a_one_row_function_line() {
        let a = split(Rect::new(0, 0, 60, 24), 2);
        assert!(a.narrow);
        assert_eq!(a.domain, Rect::new(0, 0, 60, 3));
        assert_eq!(a.function, Rect::new(0, 3, 60, 1));
        assert_eq!(a.options, Some(Rect::new(0, 4, 60, 4)));
        assert_eq!(a.details.y, 8);
    }
}
