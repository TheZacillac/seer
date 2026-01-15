//! Catppuccin-inspired color palette for terminal output.
//!
//! Uses standard ANSI bright colors for maximum terminal compatibility,
//! mapped to approximate Catppuccin Frappe aesthetics.

use colored::{ColoredString, Colorize};

/// Extension trait for applying Catppuccin-inspired colors to strings.
/// Uses ANSI bright colors for maximum compatibility.
pub trait CatppuccinExt {
    // Accent colors - mapped to ANSI bright colors
    fn rosewater(&self) -> ColoredString;
    fn flamingo(&self) -> ColoredString;
    fn pink(&self) -> ColoredString;
    fn mauve(&self) -> ColoredString;
    fn ctp_red(&self) -> ColoredString;
    fn maroon(&self) -> ColoredString;
    fn peach(&self) -> ColoredString;
    fn ctp_yellow(&self) -> ColoredString;
    fn ctp_green(&self) -> ColoredString;
    fn teal(&self) -> ColoredString;
    fn sky(&self) -> ColoredString;
    fn sapphire(&self) -> ColoredString;
    fn ctp_blue(&self) -> ColoredString;
    fn lavender(&self) -> ColoredString;

    // Text colors
    fn text(&self) -> ColoredString;
    fn subtext1(&self) -> ColoredString;
    fn subtext0(&self) -> ColoredString;
    fn ctp_white(&self) -> ColoredString;

    // Overlay colors
    fn overlay2(&self) -> ColoredString;
    fn overlay1(&self) -> ColoredString;
    fn overlay0(&self) -> ColoredString;

    // Surface colors
    fn surface2(&self) -> ColoredString;
    fn surface1(&self) -> ColoredString;
    fn surface0(&self) -> ColoredString;
}

impl<S: AsRef<str>> CatppuccinExt for S {
    // Rosewater -> bright white (closest to light pink)
    fn rosewater(&self) -> ColoredString {
        self.as_ref().bright_white()
    }

    // Flamingo -> bright red (light coral)
    fn flamingo(&self) -> ColoredString {
        self.as_ref().bright_red()
    }

    // Pink -> bright magenta
    fn pink(&self) -> ColoredString {
        self.as_ref().bright_magenta()
    }

    // Mauve -> magenta (purple)
    fn mauve(&self) -> ColoredString {
        self.as_ref().bright_purple()
    }

    // Red -> bright red
    fn ctp_red(&self) -> ColoredString {
        self.as_ref().bright_red()
    }

    // Maroon -> red
    fn maroon(&self) -> ColoredString {
        self.as_ref().red()
    }

    // Peach -> bright yellow (orange-ish)
    fn peach(&self) -> ColoredString {
        self.as_ref().bright_yellow()
    }

    // Yellow -> bright yellow
    fn ctp_yellow(&self) -> ColoredString {
        self.as_ref().bright_yellow()
    }

    // Green -> bright green
    fn ctp_green(&self) -> ColoredString {
        self.as_ref().bright_green()
    }

    // Teal -> cyan
    fn teal(&self) -> ColoredString {
        self.as_ref().cyan()
    }

    // Sky -> bright cyan
    fn sky(&self) -> ColoredString {
        self.as_ref().bright_cyan()
    }

    // Sapphire -> bright cyan
    fn sapphire(&self) -> ColoredString {
        self.as_ref().bright_cyan()
    }

    // Blue -> bright blue
    fn ctp_blue(&self) -> ColoredString {
        self.as_ref().bright_blue()
    }

    // Lavender -> bright purple/magenta
    fn lavender(&self) -> ColoredString {
        self.as_ref().bright_purple()
    }

    // Text -> bright white
    fn text(&self) -> ColoredString {
        self.as_ref().bright_white()
    }

    // Subtext1 -> white
    fn subtext1(&self) -> ColoredString {
        self.as_ref().white()
    }

    // Subtext0 -> white
    fn subtext0(&self) -> ColoredString {
        self.as_ref().white()
    }

    // White -> bright white
    fn ctp_white(&self) -> ColoredString {
        self.as_ref().bright_white()
    }

    // Overlay2 -> bright black (gray)
    fn overlay2(&self) -> ColoredString {
        self.as_ref().white()
    }

    // Overlay1 -> bright black (gray)
    fn overlay1(&self) -> ColoredString {
        self.as_ref().bright_black()
    }

    // Overlay0 -> bright black (gray)
    fn overlay0(&self) -> ColoredString {
        self.as_ref().bright_black()
    }

    // Surface colors -> dark grays
    fn surface2(&self) -> ColoredString {
        self.as_ref().bright_black()
    }

    fn surface1(&self) -> ColoredString {
        self.as_ref().bright_black()
    }

    fn surface0(&self) -> ColoredString {
        self.as_ref().bright_black()
    }
}
