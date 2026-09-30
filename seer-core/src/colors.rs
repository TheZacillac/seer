//! Catppuccin-inspired color palette for terminal output.
//!
//! Uses standard ANSI bright colors for maximum terminal compatibility,
//! mapped to approximate Catppuccin Frappe aesthetics.
//!
//! Color palette inspired by [Catppuccin](https://github.com/catppuccin/catppuccin),
//! a community-driven pastel theme. See their repository for the full palette specification.

use colored::{ColoredString, Colorize};

/// Declares [`CatppuccinExt`] and its blanket impl from one
/// `palette_name => ansi_method` row per color, so the trait and the impl
/// can't drift apart.
macro_rules! palette {
    ($($(#[$doc:meta])* $name:ident => $ansi:ident,)+) => {
        /// Extension trait for applying Catppuccin-inspired colors to strings.
        /// Uses ANSI bright colors for maximum compatibility.
        pub trait CatppuccinExt {
            $($(#[$doc])* fn $name(&self) -> ColoredString;)+
        }

        impl<S: AsRef<str>> CatppuccinExt for S {
            $(fn $name(&self) -> ColoredString {
                self.as_ref().$ansi()
            })+
        }
    };
}

// Only the colors the CLI and the human formatter use; add a row (mapped
// to its ANSI approximation) when a new one is needed.
palette! {
    // Accent colors
    /// Red → bright red.
    ctp_red => bright_red,
    /// Yellow → bright yellow.
    ctp_yellow => bright_yellow,
    /// Green → bright green.
    ctp_green => bright_green,
    /// Sky → bright cyan.
    sky => bright_cyan,
    /// Lavender → bright purple.
    lavender => bright_purple,

    // Text colors
    /// Subtext0 → white.
    subtext0 => white,
    /// White → bright white.
    ctp_white => bright_white,

    // Overlay colors
    /// Overlay1 → bright black (gray).
    overlay1 => bright_black,
}
