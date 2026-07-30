// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// The top bit marks a control message; everything else is user data.
const FLAG_CONTROL: u16 = 0x8000;
const FLAG_LENGTH: u16 = 0x4000;
const FLAG_SEQUENCE: u16 = 0x0800;
const FLAG_OFFSET: u16 = 0x0200;

/// Where the PPP frame starts in a data message.
///
/// Almost every field after the flags is optional and signalled by its own bit,
/// so the payload offset has to be computed rather than assumed. An offset
/// field, when present, then declares yet more padding to skip.
fn data_payload(payload: &[u8], flags: u16) -> Option<&[u8]> {
    let mut at = 2; // the flags themselves
    if flags & FLAG_LENGTH != 0 {
        at += 2;
    }
    at += 4; // tunnel and session ids
    if flags & FLAG_SEQUENCE != 0 {
        at += 4; // sequence numbers
    }
    if flags & FLAG_OFFSET != 0 {
        let size = u16::from_be_bytes([*payload.get(at)?, *payload.get(at + 1)?]) as usize;
        at += 2 + size;
    }
    payload.get(at..)
}

/// Dissect an L2TP message (UDP 1701) — a tunnelling protocol often paired
/// with IPsec for VPNs. The first 16 bits are flags; the top bit (T) marks a
/// control message, the low nibble is the version (RFC 2661).
pub fn dissect_l2tp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    // A data message carries a PPP frame, and that frame carries the user's
    // actual traffic. Reporting "L2TP data message" hides everything the
    // tunnel exists to move, which on a VPN is all of it.
    if payload.len() >= 2 {
        let flags = u16::from_be_bytes([payload[0], payload[1]]);
        if flags & FLAG_CONTROL == 0 {
            if let Some(inner) = data_payload(payload, flags) {
                if !inner.is_empty() {
                    let mut r = super::ppp::dissect_ppp(inner);
                    r.summary = format!("L2TP · {}", r.summary);
                    r.src_port = Some(src_port);
                    r.dst_port = Some(dst_port);
                    return r;
                }
            }
        }
    }

    let summary = if payload.len() >= 2 {
        let flags = u16::from_be_bytes([payload[0], payload[1]]);
        let version = flags & 0x000F;
        let kind = if flags & FLAG_CONTROL != 0 {
            "control message"
        } else {
            "data message"
        };
        format!("L2TPv{version} {kind}")
    } else {
        "L2TP (truncated)".to_string()
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::L2tp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A VPN's entire contents travel in data messages, so unwrapping them is
    /// the difference between seeing the traffic and seeing only the tunnel.
    #[test]
    fn a_data_message_reveals_the_ppp_frame_inside() {
        // Flags with the length and sequence bits set, version 2.
        let flags: u16 = FLAG_LENGTH | FLAG_SEQUENCE | 0x0002;
        let mut p = flags.to_be_bytes().to_vec();
        p.extend_from_slice(&0u16.to_be_bytes()); // length
        p.extend_from_slice(&[0x00, 0x01, 0x00, 0x02]); // tunnel and session
        p.extend_from_slice(&[0u8; 4]); // sequence numbers
        p.extend_from_slice(&[0xFF, 0x03, 0x00, 0x21]); // PPP: IP protocol
        p.extend_from_slice(&[0x45, 0x00]);

        let r = dissect_l2tp(None, None, 1701, 1701, &p);
        assert!(r.summary.starts_with("L2TP · "), "got {}", r.summary);
    }

    /// Almost every header field is optional, so the payload offset has to be
    /// computed. A message with no optional fields is the shortest case.
    #[test]
    fn the_payload_offset_follows_the_flags() {
        // No optional fields: flags, then tunnel and session ids only.
        let flags: u16 = 0x0002;
        let mut p = flags.to_be_bytes().to_vec();
        p.extend_from_slice(&[0x00, 0x01, 0x00, 0x02]);
        p.extend_from_slice(&[0xAA, 0xBB]);
        assert_eq!(data_payload(&p, flags), Some(&[0xAAu8, 0xBB][..]));

        // With the offset field, which declares extra padding of its own.
        let flags: u16 = FLAG_OFFSET | 0x0002;
        let mut p = flags.to_be_bytes().to_vec();
        p.extend_from_slice(&[0x00, 0x01, 0x00, 0x02]);
        p.extend_from_slice(&3u16.to_be_bytes()); // three bytes of padding
        p.extend_from_slice(&[0, 0, 0]);
        p.extend_from_slice(&[0xCC, 0xDD]);
        assert_eq!(data_payload(&p, flags), Some(&[0xCCu8, 0xDD][..]));
    }

    /// A control message is tunnel housekeeping and has no PPP frame to find.
    #[test]
    fn control_messages_are_not_unwrapped() {
        let r = dissect_l2tp(
            None,
            None,
            1701,
            1701,
            &[0xC8, 0x02, 0x00, 0x00, 0, 0, 0, 0],
        );
        assert_eq!(r.summary, "L2TPv2 control message");
    }

    #[test]
    fn control_message() {
        // T + L + S bits set, version 2 = 0xC802.
        let r = dissect_l2tp(None, None, 1701, 1701, &[0xC8, 0x02, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::L2tp);
        assert_eq!(r.summary, "L2TPv2 control message");
    }
}
