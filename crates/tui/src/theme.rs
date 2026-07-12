//! Color themes for the TUI chrome (ROADMAP §6.1). A [`Theme`] carries the
//! handful of colours the shell paints — selection, the status/keybind bars,
//! panel borders and an accent — so the whole UI can be recoloured at runtime
//! by cycling through [`THEMES`] with the `t` key. Protocol accent colours
//! (see [`crate::colors::protocol_color`]) are deliberately left alone so
//! packet colouring stays recognisable across themes, matching the desktop.

use ratatui::style::Color;

/// A named palette for the shell chrome.
#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub name: &'static str,
    /// Background of the selected row.
    pub selected_bg: Color,
    /// Background of the top status bar and bottom keybinding bar.
    pub bar_bg: Color,
    /// Foreground for keybinding-bar text.
    pub bar_fg: Color,
    /// Panel border colour.
    pub border: Color,
    /// Accent colour for highlights (focused tree node, headings).
    pub accent: Color,
}

/// Built-in themes, cycled by the `t` key. `dark` first so it stays the
/// default. Names mirror the ROADMAP's list (dark, light, solarized, dracula,
/// monokai).
pub const THEMES: &[Theme] = &[
    Theme {
        name: "dark",
        selected_bg: Color::Rgb(0x1E, 0x3A, 0x5F),
        bar_bg: Color::Rgb(0x1F, 0x29, 0x37),
        bar_fg: Color::Rgb(0x8B, 0x98, 0xAB),
        border: Color::Rgb(0x37, 0x4A, 0x5C),
        accent: Color::Rgb(0x4A, 0x9E, 0xF5),
    },
    Theme {
        name: "light",
        selected_bg: Color::Rgb(0xCF, 0xE3, 0xFF),
        bar_bg: Color::Rgb(0xE6, 0xEA, 0xF0),
        bar_fg: Color::Rgb(0x3A, 0x43, 0x52),
        border: Color::Rgb(0xB6, 0xC0, 0xCE),
        accent: Color::Rgb(0x1D, 0x4E, 0xD8),
    },
    Theme {
        name: "solarized",
        selected_bg: Color::Rgb(0x07, 0x36, 0x42),
        bar_bg: Color::Rgb(0x00, 0x2B, 0x36),
        bar_fg: Color::Rgb(0x83, 0x94, 0x96),
        border: Color::Rgb(0x58, 0x6E, 0x75),
        accent: Color::Rgb(0x26, 0x8B, 0xD2),
    },
    Theme {
        name: "dracula",
        selected_bg: Color::Rgb(0x44, 0x47, 0x5A),
        bar_bg: Color::Rgb(0x28, 0x2A, 0x36),
        bar_fg: Color::Rgb(0x9A, 0xA0, 0xB5),
        border: Color::Rgb(0x62, 0x72, 0xA4),
        accent: Color::Rgb(0xBD, 0x93, 0xF9),
    },
    Theme {
        name: "monokai",
        selected_bg: Color::Rgb(0x3E, 0x3D, 0x32),
        bar_bg: Color::Rgb(0x27, 0x28, 0x22),
        bar_fg: Color::Rgb(0x9D, 0x9C, 0x8C),
        border: Color::Rgb(0x49, 0x48, 0x3E),
        accent: Color::Rgb(0xA6, 0xE2, 0x2E),
    },
];

impl Theme {
    /// Index into [`THEMES`] of the named theme (case-insensitive), if any.
    /// Used to pick the startup theme from `$NETSCOPE_THEME`.
    pub fn index_by_name(name: &str) -> Option<usize> {
        THEMES
            .iter()
            .position(|t| t.name.eq_ignore_ascii_case(name))
    }
}
