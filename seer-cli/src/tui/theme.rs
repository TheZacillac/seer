//! Catppuccin palettes mapped to ratatui colors. Frappé (dark, the default)
//! hex values are taken from the design mockup's `:root` block; Latte (light)
//! from the official Catppuccin palette. Fields map 1:1 between the two.

use ratatui::style::Color;

/// Full Catppuccin palette. A few accent fields are not yet read by the
/// seven wired lenses; they are consumed by the lenses added in follow-up
/// passes (e.g. sapphire for Reverse DNS, pink for Subdomains).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct Theme {
    /// Canonical palette name ("frappe" | "latte") — used by `:theme`
    /// feedback and config wiring to identify the active theme.
    pub name: &'static str,
    pub crust: Color,
    pub mantle: Color,
    pub base: Color,
    pub surface0: Color,
    pub surface1: Color,
    pub surface2: Color,
    pub overlay: Color,
    pub overlay0: Color,
    pub text: Color,
    pub subtext: Color,
    pub blue: Color,
    pub lavender: Color,
    pub sapphire: Color,
    pub sky: Color,
    pub teal: Color,
    pub green: Color,
    pub yellow: Color,
    pub peach: Color,
    pub maroon: Color,
    pub red: Color,
    pub mauve: Color,
    pub pink: Color,
}

impl Theme {
    /// Valid theme names, for command errors and config validation.
    pub const NAMES: [&'static str; 2] = ["frappe", "latte"];

    /// Look up a theme by name, case-insensitively. Accepts "frappe" (also
    /// the accented "frappé") and "latte"; anything else is None.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.trim().to_lowercase().as_str() {
            "frappe" | "frappé" => Some(Self::frappe()),
            "latte" => Some(Self::latte()),
            _ => None,
        }
    }

    pub fn frappe() -> Self {
        Self {
            name: "frappe",
            crust: Color::Rgb(0x23, 0x26, 0x34),
            mantle: Color::Rgb(0x29, 0x2c, 0x3c),
            base: Color::Rgb(0x30, 0x34, 0x46),
            surface0: Color::Rgb(0x41, 0x45, 0x59),
            surface1: Color::Rgb(0x51, 0x57, 0x6d),
            surface2: Color::Rgb(0x62, 0x68, 0x80),
            overlay: Color::Rgb(0x94, 0x9c, 0xbb),
            overlay0: Color::Rgb(0x73, 0x79, 0x94),
            text: Color::Rgb(0xc6, 0xd0, 0xf5),
            subtext: Color::Rgb(0xb5, 0xbf, 0xe2),
            blue: Color::Rgb(0x8c, 0xaa, 0xee),
            lavender: Color::Rgb(0xba, 0xbb, 0xf1),
            sapphire: Color::Rgb(0x85, 0xc1, 0xdc),
            sky: Color::Rgb(0x99, 0xd1, 0xdb),
            teal: Color::Rgb(0x81, 0xc8, 0xbe),
            green: Color::Rgb(0xa6, 0xd1, 0x89),
            yellow: Color::Rgb(0xe5, 0xc8, 0x90),
            peach: Color::Rgb(0xef, 0x9f, 0x76),
            maroon: Color::Rgb(0xea, 0x99, 0x9c),
            red: Color::Rgb(0xe7, 0x82, 0x84),
            mauve: Color::Rgb(0xca, 0x9e, 0xe6),
            pink: Color::Rgb(0xf4, 0xb8, 0xe4),
        }
    }

    /// Catppuccin Latte (light) palette, mapped field-for-field to Frappé:
    /// `overlay` is Latte overlay2, `subtext` is Latte subtext1.
    pub fn latte() -> Self {
        Self {
            name: "latte",
            crust: Color::Rgb(0xdc, 0xe0, 0xe8),
            mantle: Color::Rgb(0xe6, 0xe9, 0xef),
            base: Color::Rgb(0xef, 0xf1, 0xf5),
            surface0: Color::Rgb(0xcc, 0xd0, 0xda),
            surface1: Color::Rgb(0xbc, 0xc0, 0xcc),
            surface2: Color::Rgb(0xac, 0xb0, 0xbe),
            overlay: Color::Rgb(0x7c, 0x7f, 0x93),
            overlay0: Color::Rgb(0x9c, 0xa0, 0xb0),
            text: Color::Rgb(0x4c, 0x4f, 0x69),
            subtext: Color::Rgb(0x5c, 0x5f, 0x77),
            blue: Color::Rgb(0x1e, 0x66, 0xf5),
            lavender: Color::Rgb(0x72, 0x87, 0xfd),
            sapphire: Color::Rgb(0x20, 0x9f, 0xb5),
            sky: Color::Rgb(0x04, 0xa5, 0xe5),
            teal: Color::Rgb(0x17, 0x92, 0x99),
            green: Color::Rgb(0x40, 0xa0, 0x2b),
            yellow: Color::Rgb(0xdf, 0x8e, 0x1d),
            peach: Color::Rgb(0xfe, 0x64, 0x0b),
            maroon: Color::Rgb(0xe6, 0x45, 0x53),
            red: Color::Rgb(0xd2, 0x0f, 0x39),
            mauve: Color::Rgb(0x88, 0x39, 0xef),
            pink: Color::Rgb(0xea, 0x76, 0xcb),
        }
    }

    /// Map a status tone keyword to its color (ok/warn/fail/info/...).
    pub fn tone(&self, tone: &str) -> Color {
        match tone {
            "ok" | "healthy" | "valid" => self.green,
            "warn" | "wait" => self.yellow,
            "fail" | "crit" | "expired" => self.red,
            "info" => self.sky,
            _ => self.subtext,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::style::Color;

    #[test]
    fn frappe_core_colors_match_mockup() {
        let t = Theme::frappe();
        assert_eq!(t.base, Color::Rgb(0x30, 0x34, 0x46));
        assert_eq!(t.text, Color::Rgb(0xc6, 0xd0, 0xf5));
        assert_eq!(t.mauve, Color::Rgb(0xca, 0x9e, 0xe6));
        assert_eq!(t.green, Color::Rgb(0xa6, 0xd1, 0x89));
        assert_eq!(t.red, Color::Rgb(0xe7, 0x82, 0x84));
        assert_eq!(t.lavender, Color::Rgb(0xba, 0xbb, 0xf1));
    }

    #[test]
    fn tone_maps_states_to_colors() {
        let t = Theme::frappe();
        assert_eq!(t.tone("ok"), t.green);
        assert_eq!(t.tone("warn"), t.yellow);
        assert_eq!(t.tone("fail"), t.red);
        assert_eq!(t.tone("info"), t.sky);
        assert_eq!(t.tone("unknown"), t.subtext);
    }

    #[test]
    fn latte_core_colors_match_official_palette() {
        let t = Theme::latte();
        assert_eq!(t.base, Color::Rgb(0xef, 0xf1, 0xf5));
        assert_eq!(t.text, Color::Rgb(0x4c, 0x4f, 0x69));
        assert_eq!(t.mauve, Color::Rgb(0x88, 0x39, 0xef));
        assert_eq!(t.green, Color::Rgb(0x40, 0xa0, 0x2b));
        assert_eq!(t.red, Color::Rgb(0xd2, 0x0f, 0x39));
        assert_eq!(t.lavender, Color::Rgb(0x72, 0x87, 0xfd));
        assert_eq!(t.crust, Color::Rgb(0xdc, 0xe0, 0xe8));
    }

    #[test]
    fn from_name_accepts_known_names_case_insensitively() {
        assert_eq!(Theme::from_name("frappe").map(|t| t.name), Some("frappe"));
        assert_eq!(Theme::from_name("Frappé").map(|t| t.name), Some("frappe"));
        assert_eq!(Theme::from_name("FRAPPÉ").map(|t| t.name), Some("frappe"));
        assert_eq!(Theme::from_name("latte").map(|t| t.name), Some("latte"));
        assert_eq!(Theme::from_name("LATTE").map(|t| t.name), Some("latte"));
        assert_eq!(Theme::from_name(" latte ").map(|t| t.name), Some("latte"));
    }

    #[test]
    fn from_name_rejects_unknown_names() {
        assert!(Theme::from_name("mocha").is_none());
        assert!(Theme::from_name("macchiato").is_none());
        assert!(Theme::from_name("").is_none());
        assert!(Theme::from_name("dark").is_none());
    }

    #[test]
    fn latte_differs_from_frappe_and_names_are_canonical() {
        let f = Theme::frappe();
        let l = Theme::latte();
        assert_eq!(f.name, "frappe");
        assert_eq!(l.name, "latte");
        // Light vs dark: the background/foreground pairs must actually differ.
        assert_ne!(f.base, l.base);
        assert_ne!(f.text, l.text);
        assert_ne!(f.mantle, l.mantle);
    }
}
