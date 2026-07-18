// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an ATT PDU (Bluetooth L2CAP CID 0x0004) — the Attribute Protocol,
/// where BLE devices actually exchange data: reading and writing the
/// characteristics a heart-rate strap, sensor or lock exposes. Byte 0 is the
/// opcode.
pub fn dissect_att(body: &[u8]) -> DissectedResult {
    let summary = match body.first() {
        Some(&op) => {
            let name = match op {
                0x01 => "Error Response",
                0x02 => "Exchange MTU Request",
                0x03 => "Exchange MTU Response",
                0x04 => "Find Information Request",
                0x08 => "Read By Type Request",
                0x09 => "Read By Type Response",
                0x0A => "Read Request",
                0x0B => "Read Response",
                0x10 => "Read By Group Type Request",
                0x11 => "Read By Group Type Response",
                0x12 => "Write Request",
                0x13 => "Write Response",
                0x1B => "Handle Value Notification",
                0x1D => "Handle Value Indication",
                0x52 => "Write Command",
                _ => "PDU",
            };
            // Most PDUs carry the attribute handle right after the opcode.
            match (op, body.get(1..3)) {
                (0x0A | 0x12 | 0x1B | 0x1D | 0x52, Some(h)) => {
                    let handle = u16::from_le_bytes([h[0], h[1]]);
                    format!("ATT {name} — handle 0x{handle:04x}")
                }
                _ => format!("ATT {name}"),
            }
        }
        None => "ATT (empty)".to_string(),
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Att,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notification_reports_the_handle() {
        let r = dissect_att(&[0x1B, 0x2A, 0x00, 0x50]);
        assert_eq!(r.protocol, Protocol::Att);
        assert_eq!(r.summary, "ATT Handle Value Notification — handle 0x002a");
    }

    #[test]
    fn mtu_exchange() {
        let r = dissect_att(&[0x02, 0x17, 0x00]);
        assert_eq!(r.summary, "ATT Exchange MTU Request");
    }
}
