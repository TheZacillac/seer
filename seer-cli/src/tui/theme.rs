//! Catppuccin Frappé palette mapped to ratatui colors. Hex values are taken
//! from the design mockup's `:root` block.

use ratatui::style::Color;

#[derive(Debug, Clone, Copy)]
pub struct Theme {
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
    pub fn frappe() -> Self {
        Self {
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
}
