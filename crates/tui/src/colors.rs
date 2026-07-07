use netscope_core::models::Protocol;
use ratatui::style::Color;

pub fn protocol_color(protocol: &Protocol) -> Color {
    match protocol {
        Protocol::Tcp => Color::Rgb(0x4A, 0x9E, 0xF5),
        Protocol::Udp => Color::Rgb(0x45, 0xD1, 0xC5),
        Protocol::Dns => Color::Rgb(0xA7, 0x8B, 0xFA),
        Protocol::Http => Color::Rgb(0x34, 0xD3, 0x99),
        Protocol::Tls => Color::Rgb(0x6E, 0xE7, 0xB7),
        Protocol::Icmp => Color::Rgb(0xFB, 0xB2, 0x24),
        Protocol::Arp => Color::Rgb(0x9C, 0xA3, 0xAF),
        Protocol::Dhcp => Color::Rgb(0xF9, 0xA8, 0x25),
        Protocol::Ntp => Color::Rgb(0x38, 0xBD, 0xF8),
        Protocol::Mdns => Color::Rgb(0xC0, 0x84, 0xFC),
        Protocol::Snmp => Color::Rgb(0xFA, 0xCC, 0x15),
        Protocol::Quic => Color::Rgb(0x2D, 0xD4, 0xBF),
        Protocol::Sip => Color::Rgb(0x81, 0x8C, 0xF8),
        Protocol::Unknown(_) => Color::Rgb(0xF8, 0x71, 0x71),
    }
}

pub const SELECTED_BG: Color = Color::Rgb(0x1E, 0x3A, 0x5F);
pub const STATUS_BAR_BG: Color = Color::Rgb(0x1F, 0x29, 0x37);
pub const KEYBIND_BG: Color = Color::Rgb(0x1F, 0x29, 0x37);
pub const PANEL_BORDER: Color = Color::Rgb(0x37, 0x4A, 0x5C);
