// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::path::{Path, PathBuf};

use netscope_core::filter::Filter;
use netscope_core::models::{Packet, Protocol};
use ratatui::style::Color;

/// The packet-list colour for a protocol. Registry protocols carry their own
/// colour; the two data-carrying variants fall back to a plugin amber and an
/// alarm red for undecoded traffic.
pub fn protocol_color(protocol: &Protocol) -> Color {
    match protocol.color() {
        Some((r, g, b)) => Color::Rgb(r, g, b),
        None => match protocol {
            Protocol::Plugin(_) => Color::Rgb(0xE2, 0xB0, 0x7A),
            _ => Color::Rgb(0xF8, 0x71, 0x71),
        },
    }
}

// Chrome colours (selection, bars, borders) live in [`crate::theme`] now, so
// they can be swapped at runtime. Only the protocol accent palette above is
// theme-independent, on purpose — packet colours stay recognisable.

// ---- User-defined coloring rules ------------------------------------------
//
// The TUI counterpart of the desktop's View > Coloring rules: a list of
// display-filter rules; the first rule that matches a packet colours its row,
// packets no rule matches keep their protocol colour. Two file forms are
// accepted (parsing is shared with netscope-core's layered config):
//
//     # legacy line form — a hex colour then any display filter
//     ef4444 tcp.flags.rst == 1 || info contains "Malformed"
//     f97316 http.response.code >= 400
//
//     # TOML form (coloring-rules.toml)
//     [[rule]]
//     color = "ef4444"
//     filter = 'tcp.flags.rst == 1'
//
// Lookup order: `--colors <file>` → `~/.netscope/coloring-rules.toml` (the
// layered config home, ROADMAP §2.4) → the legacy per-OS location
// (`%APPDATA%\netscope\colors` / `~/.config/netscope/colors`) → built-in
// defaults mirroring the desktop's ship rules.

/// One coloring rule: a compiled display filter and the colour it paints.
pub struct ColorRule {
    pub filter: Filter,
    pub color: Color,
}

/// The active rule list, checked top-down (first match wins).
pub struct ColorRules {
    rules: Vec<ColorRule>,
}

/// Default rules, kept in lockstep with the desktop's `DEFAULT_COLOR_RULES`
/// (app.js) so both UIs highlight the same traffic out of the box.
const DEFAULT_RULES: &[(&str, &str)] = &[
    (
        "ef4444",
        "tcp.flags.rst == 1 || info contains \"Malformed\"",
    ),
    ("f97316", "http.response.code >= 400"),
    ("94a3b8", "tcp.flags.syn == 1 || tcp.flags.fin == 1"),
    ("a78bfa", "dns || mdns"),
    ("fbbf24", "icmp"),
    ("9ca3af", "arp"),
];

impl ColorRules {
    /// Load rules from `explicit` if given (an unreadable explicit path is an
    /// error), else from the layered-config home (`~/.netscope`), else the
    /// legacy per-OS location, else the built-in defaults.
    pub fn load(explicit: Option<&Path>) -> anyhow::Result<Self> {
        if let Some(path) = explicit {
            let text = std::fs::read_to_string(path).map_err(|e| {
                anyhow::anyhow!("cannot read coloring rules file {}: {e}", path.display())
            })?;
            return Ok(Self::parse(&text));
        }
        let cfg_path = netscope_core::config::Config::load().coloring_rules_path();
        if let Ok(text) = std::fs::read_to_string(&cfg_path) {
            return Ok(Self::parse(&text));
        }
        if let Some(path) = default_path() {
            if let Ok(text) = std::fs::read_to_string(&path) {
                return Ok(Self::parse(&text));
            }
        }
        Ok(Self::defaults())
    }

    pub fn defaults() -> Self {
        let rules = DEFAULT_RULES
            .iter()
            .filter_map(|(color, filter)| {
                Some(ColorRule {
                    filter: Filter::parse(filter).ok()?,
                    color: parse_hex_color(color)?,
                })
            })
            .collect();
        Self { rules }
    }

    /// Parse either file form (shared reader in netscope-core). Entries whose
    /// colour or filter doesn't compile are skipped: comments and typos never
    /// take the TUI down.
    pub fn parse(text: &str) -> Self {
        let rules = netscope_core::config::parse_coloring_rules(text)
            .into_iter()
            .filter_map(|r| {
                Some(ColorRule {
                    color: parse_hex_color(&r.color)?,
                    filter: Filter::parse(&r.filter).ok()?,
                })
            })
            .collect();
        Self { rules }
    }

    /// Colour of the first rule matching `pkt`, if any.
    pub fn color_for(&self, pkt: &Packet) -> Option<Color> {
        self.rules
            .iter()
            .find(|r| r.filter.matches(pkt))
            .map(|r| r.color)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.rules.len()
    }
}

/// `RRGGBB` or `#RRGGBB` → Color. Comment lines fail here (`#` alone, or
/// `#` followed by a word) and are silently skipped by the parser.
fn parse_hex_color(word: &str) -> Option<Color> {
    let hex = word.strip_prefix('#').unwrap_or(word);
    if hex.len() != 6 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let v = u32::from_str_radix(hex, 16).ok()?;
    Some(Color::Rgb((v >> 16) as u8, (v >> 8) as u8, v as u8))
}

/// Platform config path: `%APPDATA%\netscope\colors` on Windows,
/// `$XDG_CONFIG_HOME/netscope/colors` (or `~/.config/netscope/colors`)
/// elsewhere.
pub fn default_path() -> Option<PathBuf> {
    #[cfg(windows)]
    let base = std::env::var_os("APPDATA").map(PathBuf::from);
    #[cfg(not(windows))]
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")));
    base.map(|d| d.join("netscope").join("colors"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn pkt(proto: Protocol, summary: &str) -> Packet {
        Packet {
            timestamp: Utc::now(),
            src_addr: "10.0.0.1".parse().ok(),
            dst_addr: "10.0.0.2".parse().ok(),
            src_port: Some(50000),
            dst_port: Some(443),
            protocol: proto,
            length: 100,
            summary: summary.into(),
            data: Default::default(),
        }
    }

    #[test]
    fn parses_rules_and_skips_comments_and_typos() {
        let rules = ColorRules::parse(
            "# a comment line\n\
             \n\
             ef4444 info contains \"reset\"\n\
             #22c55e dns\n\
             not-a-color dns\n\
             aabbcc this is not a filter\n",
        );
        // The comment, blank, bad-colour and bad-filter lines are skipped;
        // '#22c55e dns' is a rule (colours may keep their leading '#').
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn parses_toml_rule_form() {
        let rules = ColorRules::parse(
            "[[rule]]\ncolor = \"ef4444\"\nfilter = 'info contains \"reset\"'\n\n\
             [[rule]]\ncolor = \"#a78bfa\"\nfilter = 'dns'\n\n\
             [[rule]]\ncolor = \"nope\"\nfilter = 'tcp'\n",
        );
        // The invalid colour is skipped; the two good rules compile.
        assert_eq!(rules.len(), 2);
        let reset = pkt(Protocol::Tcp, "TCP Connection reset (RST)");
        assert_eq!(rules.color_for(&reset), Some(Color::Rgb(0xEF, 0x44, 0x44)));
        let dns = pkt(Protocol::Dns, "DNS Query — example.com");
        assert_eq!(rules.color_for(&dns), Some(Color::Rgb(0xA7, 0x8B, 0xFA)));
    }

    #[test]
    fn first_match_wins_and_misses_fall_through() {
        let rules = ColorRules::parse(
            "ff0000 info contains \"reset\"\n\
             00ff00 tcp\n",
        );
        let reset = pkt(Protocol::Tcp, "TCP Connection reset (RST)");
        assert_eq!(rules.color_for(&reset), Some(Color::Rgb(0xFF, 0, 0)));
        let plain = pkt(Protocol::Tcp, "TCP — 10 bytes of payload");
        assert_eq!(rules.color_for(&plain), Some(Color::Rgb(0, 0xFF, 0)));
        let dns = pkt(Protocol::Dns, "DNS Query — example.com");
        assert_eq!(rules.color_for(&dns), None);
    }

    #[test]
    fn builtin_defaults_compile_and_match() {
        let rules = ColorRules::defaults();
        assert_eq!(rules.len(), 6);
        // 'dns || mdns' rule paints DNS purple, same as the desktop default.
        let dns = pkt(Protocol::Dns, "DNS Query — example.com");
        assert_eq!(rules.color_for(&dns), Some(Color::Rgb(0xA7, 0x8B, 0xFA)));
        let tls = pkt(Protocol::Tls, "TLS — example.com (HTTPS)");
        assert_eq!(rules.color_for(&tls), None);
    }

    #[test]
    fn hex_color_forms() {
        assert_eq!(
            parse_hex_color("aabbcc"),
            Some(Color::Rgb(0xAA, 0xBB, 0xCC))
        );
        assert_eq!(
            parse_hex_color("#AABBCC"),
            Some(Color::Rgb(0xAA, 0xBB, 0xCC))
        );
        assert_eq!(parse_hex_color("#"), None);
        assert_eq!(parse_hex_color("abc"), None);
        assert_eq!(parse_hex_color("zzzzzz"), None);
    }
}
