// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::{cip, DissectedResult};

/// The two encapsulation commands that carry a CIP message.
const CMD_SEND_RR_DATA: u16 = 0x006F;
const CMD_SEND_UNIT_DATA: u16 = 0x0070;

/// Common Packet Format item types that hold the CIP message itself: connected
/// data rides an established connection, unconnected data does not.
const ITEM_CONNECTED_DATA: u16 = 0x00B1;
const ITEM_UNCONNECTED_DATA: u16 = 0x00B2;

/// Find the CIP message inside an encapsulation body.
///
/// The body is a 4-byte interface handle and a 2-byte timeout, then a Common
/// Packet Format list: an item count followed by that many type/length/value
/// items. The address item comes first and is usually empty; the data item that
/// follows is what holds CIP.
fn cip_payload(body: &[u8]) -> Option<&[u8]> {
    // interface handle (4) + timeout (2) + item count (2)
    let count = u16::from_le_bytes([*body.get(6)?, *body.get(7)?]) as usize;
    // A wild count would just fail on the bounds checks below, but capping it
    // keeps the loop obviously finite.
    if count > 16 {
        return None;
    }
    let mut offset = 8;
    for _ in 0..count {
        let type_id = u16::from_le_bytes([*body.get(offset)?, *body.get(offset + 1)?]);
        let len = u16::from_le_bytes([*body.get(offset + 2)?, *body.get(offset + 3)?]) as usize;
        let from = offset + 4;
        let to = from.checked_add(len)?;
        if matches!(type_id, ITEM_CONNECTED_DATA | ITEM_UNCONNECTED_DATA) {
            let data = body.get(from..to)?;
            // A connected data item begins with a 2-byte sequence count before
            // the CIP message proper.
            return if type_id == ITEM_CONNECTED_DATA {
                data.get(2..)
            } else {
                Some(data)
            };
        }
        offset = to;
    }
    None
}

/// Dissect an EtherNet/IP encapsulation message (TCP/UDP 44818).
///
/// EtherNet/IP carries the CIP object protocol used by Rockwell/Allen-Bradley
/// PLCs. Every message starts with a 24-byte encapsulation header, all
/// little-endian: command(2), length(2), session handle(4), status(4), sender
/// context(8), options(4). We name the command — RegisterSession and
/// SendRRData being the ones you see most — and report the session handle.
pub fn dissect_enip(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let result = |summary: String| DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Enip,
        summary,
    };

    if payload.len() < 24 {
        return result("EtherNet/IP (partial)".into());
    }

    let command = u16::from_le_bytes([payload[0], payload[1]]);
    let session = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let status = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);

    let name = command_name(command);

    // SendRRData and SendUnitData exist to carry a CIP message. What CIP says
    // is the useful part — "CIP Stop" rather than "EtherNet/IP SendRRData" —
    // so hand it on and report that instead when it is recognised.
    if matches!(command, CMD_SEND_RR_DATA | CMD_SEND_UNIT_DATA) {
        if let Some(cip_data) = cip_payload(&payload[24..]) {
            if let Some((protocol, inner)) = cip::describe(cip_data) {
                return DissectedResult {
                    src_addr: src_ip,
                    dst_addr: dst_ip,
                    src_port: Some(src_port),
                    dst_port: Some(dst_port),
                    protocol,
                    summary: format!("{inner} — session 0x{session:08x}"),
                };
            }
        }
    }

    let summary = if status != 0 {
        format!("EtherNet/IP {name} — status 0x{status:08x}, session 0x{session:08x}")
    } else {
        format!("EtherNet/IP {name} — session 0x{session:08x}")
    };

    result(summary)
}

/// Whether a payload looks like an EtherNet/IP encapsulation header: a known
/// command and a length field consistent with the bytes present.
pub fn looks_like_enip(payload: &[u8]) -> bool {
    if payload.len() < 24 {
        return false;
    }
    let command = u16::from_le_bytes([payload[0], payload[1]]);
    let length = u16::from_le_bytes([payload[2], payload[3]]) as usize;
    is_known_command(command) && payload.len() >= 24 + length.min(payload.len())
}

fn is_known_command(c: u16) -> bool {
    matches!(
        c,
        0x0004 | 0x0063 | 0x0064 | 0x0065 | 0x0066 | 0x006f | 0x0070 | 0x0072 | 0x0073
    )
}

fn command_name(c: u16) -> &'static str {
    match c {
        0x0004 => "ListServices",
        0x0063 => "ListIdentity",
        0x0064 => "ListInterfaces",
        0x0065 => "RegisterSession",
        0x0066 => "UnRegisterSession",
        0x006f => "SendRRData",
        0x0070 => "SendUnitData",
        0x0072 => "IndicateStatus",
        0x0073 => "Cancel",
        _ => "command",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(command: u16, session: u32, status: u32) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&command.to_le_bytes());
        p.extend_from_slice(&0u16.to_le_bytes()); // length
        p.extend_from_slice(&session.to_le_bytes());
        p.extend_from_slice(&status.to_le_bytes());
        p.extend_from_slice(&[0u8; 8]); // sender context
        p.extend_from_slice(&0u32.to_le_bytes()); // options
        p
    }

    #[test]
    fn register_session() {
        let p = header(0x0065, 0, 0);
        let r = dissect_enip(None, None, 50000, 44818, &p);
        assert_eq!(r.protocol, Protocol::Enip);
        assert_eq!(
            r.summary,
            "EtherNet/IP RegisterSession — session 0x00000000"
        );
    }

    #[test]
    fn send_rr_data_with_session() {
        let p = header(0x006f, 0x0a0b0c0d, 0);
        let r = dissect_enip(None, None, 44818, 50000, &p);
        assert_eq!(r.summary, "EtherNet/IP SendRRData — session 0x0a0b0c0d");
    }

    #[test]
    fn detection() {
        let p = header(0x0065, 1, 0);
        assert!(looks_like_enip(&p));
        assert!(!looks_like_enip(&[0u8; 10]));
    }
}
