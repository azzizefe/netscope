// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an L2CAP frame carried in a Bluetooth HCI ACL packet. L2CAP is the
/// multiplexing layer of Bluetooth: a little-endian length and channel id, then
/// the payload. Fixed channel ids select ATT (attributes) and SMP (pairing).
pub fn dissect_l2cap(body: &[u8]) -> DissectedResult {
    if body.len() < 4 {
        return DissectedResult {
            src_addr: None,
            dst_addr: None,
            src_port: None,
            dst_port: None,
            protocol: Protocol::L2cap,
            summary: "L2CAP (truncated)".into(),
        };
    }
    let len = u16::from_le_bytes([body[0], body[1]]);
    let cid = u16::from_le_bytes([body[2], body[3]]);
    let payload = &body[4..];
    match cid {
        0x0004 => return super::att::dissect_att(payload),
        0x0006 => return super::smp::dissect_smp(payload),
        _ => {}
    }
    let name = match cid {
        0x0001 => "signalling",
        0x0005 => "LE signalling",
        c if c >= 0x0040 => "dynamic channel",
        _ => "channel",
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::L2cap,
        summary: format!("L2CAP {name} (CID 0x{cid:04x}, {len} bytes)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signalling_channel() {
        let r = dissect_l2cap(&[0x08, 0x00, 0x01, 0x00, 0x02, 0x01]);
        assert_eq!(r.protocol, Protocol::L2cap);
        assert!(r.summary.contains("signalling"), "{}", r.summary);
    }

    #[test]
    fn att_channel_is_handed_off() {
        let r = dissect_l2cap(&[0x03, 0x00, 0x04, 0x00, 0x0A, 0x01, 0x00]);
        assert_eq!(r.protocol, Protocol::Att);
    }
}
