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

palette! {
    // Accent colors
    /// Rosewater → bright white (closest to light pink).
    rosewater => bright_white,
    /// Flamingo → bright red (light coral).
    flamingo => bright_red,
    /// Pink → bright magenta.
    pink => bright_magenta,
    /// Mauve → bright purple.
    mauve => bright_purple,
    /// Red → bright red.
    ctp_red => bright_red,
    /// Maroon → red.
    maroon => red,
    /// Peach → bright yellow (orange-ish).
    peach => bright_yellow,
    /// Yellow → bright yellow.
    ctp_yellow => bright_yellow,
    /// Green → bright green.
    ctp_green => bright_green,
    /// Teal → cyan.
    teal => cyan,
    /// Sky → bright cyan.
    sky => bright_cyan,
    /// Sapphire → bright cyan.
    sapphire => bright_cyan,
    /// Blue → bright blue.
    ctp_blue => bright_blue,
    /// Lavender → bright purple.
    lavender => bright_purple,

    // Text colors
    /// Text → bright white.
    text => bright_white,
    /// Subtext1 → white.
    subtext1 => white,
    /// Subtext0 → white.
    subtext0 => white,
    /// White → bright white.
    ctp_white => bright_white,

    // Overlay colors
    /// Overlay2 → white (the lightest overlay).
    overlay2 => white,
    /// Overlay1 → bright black (gray).
    overlay1 => bright_black,
    /// Overlay0 → bright black (gray).
    overlay0 => bright_black,

    // Surface colors (dark grays)
    /// Surface2 → bright black.
    surface2 => bright_black,
    /// Surface1 → bright black.
    surface1 => bright_black,
    /// Surface0 → bright black.
    surface0 => bright_black,
}
