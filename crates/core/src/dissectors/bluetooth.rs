// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Bluetooth HCI dissector — host↔controller traffic captured on Linux
//! `bluetoothN` interfaces (`LINKTYPE_BLUETOOTH_HCI_H4` DLT 187 and
//! `LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR` DLT 201, which prefixes a 4-byte
//! direction word).
//!
//! HCI is the layer every Bluetooth stack speaks: Commands go down, Events
//! come back, ACL/SCO frames carry data. The summary names the packet type
//! and decodes the most common opcodes/events (LE advertising, connects…).

use super::DissectedResult;
use crate::models::Protocol;

fn result(summary: String) -> DissectedResult {
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Bluetooth,
        summary,
    }
}

/// DLT 201: 4-byte big-endian direction (0 = host→controller) before H4.
pub fn dissect_hci_with_phdr(data: &[u8]) -> DissectedResult {
    if data.len() < 5 {
        return result("Malformed Bluetooth HCI record (truncated)".into());
    }
    let sent = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) == 0;
    let mut r = dissect_hci_h4(&data[4..]);
    let arrow = if sent { "→" } else { "←" };
    r.summary = format!("{arrow} {}", r.summary);
    r
}

/// DLT 187: raw H4 — 1-byte packet type, then the HCI packet.
pub fn dissect_hci_h4(data: &[u8]) -> DissectedResult {
    let Some((&ptype, rest)) = data.split_first() else {
        return result("Malformed Bluetooth HCI record (empty)".into());
    };
    match ptype {
        0x01 => {
            // Command: opcode u16 LE (OGF high 6 bits, OCF low 10), plen u8.
            if rest.len() < 3 {
                return result("HCI Command (truncated)".into());
            }
            let opcode = u16::from_le_bytes([rest[0], rest[1]]);
            let name = command_name(opcode);
            result(format!("HCI Command: {name} (0x{opcode:04x})"))
        }
        0x02 => {
            // ACL data: handle+flags u16 LE, length u16 LE.
            if rest.len() < 4 {
                return result("HCI ACL data (truncated)".into());
            }
            let handle = u16::from_le_bytes([rest[0], rest[1]]) & 0x0FFF;
            let len = u16::from_le_bytes([rest[2], rest[3]]);
            // ACL carries L2CAP, which multiplexes ATT, SMP and the rest — so
            // hand it on rather than stopping at "ACL data".
            if data.len() > 5 {
                return super::l2cap::dissect_l2cap(&data[5..]);
            }
            result(format!("HCI ACL data: handle 0x{handle:03x}, {len} bytes"))
        }
        0x03 => {
            if rest.len() < 3 {
                return result("HCI SCO data (truncated)".into());
            }
            let handle = u16::from_le_bytes([rest[0], rest[1]]) & 0x0FFF;
            result(format!("HCI SCO data: handle 0x{handle:03x} (voice)"))
        }
        0x04 => {
            // Event: code u8, plen u8.
            if rest.len() < 2 {
                return result("HCI Event (truncated)".into());
            }
            let code = rest[0];
            // LE events share code 0x3E and branch on a sub-event byte.
            if code == 0x3e && rest.len() >= 3 {
                return result(format!("HCI Event: {}", le_meta_name(rest[2])));
            }
            result(format!("HCI Event: {} (0x{code:02x})", event_name(code)))
        }
        0x05 => result("HCI ISO data (LE audio)".into()),
        other => result(format!("Bluetooth HCI (unknown packet type 0x{other:02x})")),
    }
}

/// The commands seen constantly in real traces; anything else shows OGF/OCF.
fn command_name(opcode: u16) -> String {
    match opcode {
        0x0401 => "Inquiry".into(),
        0x0405 => "Create Connection".into(),
        0x0406 => "Disconnect".into(),
        0x0c03 => "Reset".into(),
        0x0c13 => "Write Local Name".into(),
        0x1001 => "Read Local Version".into(),
        0x2005 => "LE Set Random Address".into(),
        0x2006 => "LE Set Advertising Parameters".into(),
        0x2008 => "LE Set Advertising Data".into(),
        0x200a => "LE Set Advertise Enable".into(),
        0x200b => "LE Set Scan Parameters".into(),
        0x200c => "LE Set Scan Enable".into(),
        0x200d => "LE Create Connection".into(),
        _ => format!("OGF 0x{:02x} OCF 0x{:03x}", opcode >> 10, opcode & 0x3FF),
    }
}

fn event_name(code: u8) -> &'static str {
    match code {
        0x01 => "Inquiry Complete",
        0x02 => "Inquiry Result",
        0x03 => "Connection Complete",
        0x04 => "Connection Request",
        0x05 => "Disconnection Complete",
        0x0e => "Command Complete",
        0x0f => "Command Status",
        0x13 => "Number Of Completed Packets",
        0x2f => "Extended Inquiry Result",
        _ => "event",
    }
}

fn le_meta_name(sub: u8) -> &'static str {
    match sub {
        0x01 => "LE Connection Complete",
        0x02 => "LE Advertising Report",
        0x03 => "LE Connection Update Complete",
        0x0d => "LE Extended Advertising Report",
        _ => "LE Meta event",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_with_known_opcode() {
        // LE Set Scan Enable (0x200c), plen 2.
        let r = dissect_hci_h4(&[0x01, 0x0c, 0x20, 0x02, 0x01, 0x00]);
        assert_eq!(r.protocol, Protocol::Bluetooth);
        assert_eq!(r.summary, "HCI Command: LE Set Scan Enable (0x200c)");
    }

    #[test]
    fn event_command_complete() {
        let r = dissect_hci_h4(&[0x04, 0x0e, 0x04, 0x01, 0x0c, 0x20, 0x00]);
        assert_eq!(r.summary, "HCI Event: Command Complete (0x0e)");
    }

    #[test]
    fn le_advertising_report() {
        let r = dissect_hci_h4(&[0x04, 0x3e, 0x0c, 0x02, 0x01]);
        assert_eq!(r.summary, "HCI Event: LE Advertising Report");
    }

    #[test]
    fn acl_data_handle_and_len() {
        let r = dissect_hci_h4(&[0x02, 0x40, 0x20, 0x1b, 0x00]);
        assert_eq!(r.summary, "HCI ACL data: handle 0x040, 27 bytes");
    }

    #[test]
    fn phdr_direction_arrows() {
        let sent = dissect_hci_with_phdr(&[0, 0, 0, 0, 0x01, 0x03, 0x0c, 0x00]);
        assert!(
            sent.summary.starts_with("→ HCI Command: Reset"),
            "{}",
            sent.summary
        );
        let rcvd = dissect_hci_with_phdr(&[0, 0, 0, 1, 0x04, 0x0f, 0x01, 0x00]);
        assert!(
            rcvd.summary.starts_with("← HCI Event: Command Status"),
            "{}",
            rcvd.summary
        );
    }
}
