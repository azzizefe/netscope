// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an IAX2 message (UDP 4569) — Inter-Asterisk eXchange, the protocol
/// Asterisk PBXes use to trunk calls to each other. Unlike SIP it carries
/// signalling and media on one port, which makes it NAT-friendly. The top bit
/// of byte 0 distinguishes a full frame from a compact media mini-frame.
pub fn dissect_iax2(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.first() {
        Some(&b) if b & 0x80 != 0 => {
            // Full frame header: source call (2) + dest call (2) + timestamp (4)
            // + OSeqno (1) + ISeqno (1), so the frame type lands at offset 10.
            // Values per RFC 5456 §8.1.
            match payload.get(10) {
                Some(1) => "IAX2 full frame — DTMF end".to_string(),
                Some(2) => "IAX2 full frame — voice".to_string(),
                Some(3) => "IAX2 full frame — video".to_string(),
                Some(4) => "IAX2 full frame — control".to_string(),
                Some(5) => "IAX2 full frame — null".to_string(),
                Some(6) => "IAX2 full frame — IAX control".to_string(),
                Some(7) => "IAX2 full frame — text".to_string(),
                Some(8) => "IAX2 full frame — image".to_string(),
                Some(9) => "IAX2 full frame — HTML".to_string(),
                Some(10) => "IAX2 full frame — comfort noise".to_string(),
                Some(12) => "IAX2 full frame — DTMF begin".to_string(),
                Some(&t) => format!("IAX2 full frame — unknown type {t}"),
                None => "IAX2 full frame (truncated)".to_string(),
            }
        }
        Some(_) => format!(
            "IAX2 mini frame (media, {})",
            super::bytes(payload.len() as u64)
        ),
        None => "IAX2 (empty)".to_string(),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Iax2,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_frame(frame_type: u8) -> Vec<u8> {
        let mut p = vec![0x80, 0x01]; // full frame, source call 1
        p.extend_from_slice(&[0u8; 8]); // dest call, timestamp, OSeqno, ISeqno
        p.push(frame_type);
        p
    }

    #[test]
    fn full_frame_control() {
        let r = dissect_iax2(None, None, 4569, 4569, &full_frame(6));
        assert_eq!(r.protocol, Protocol::Iax2);
        assert!(r.summary.contains("IAX control"), "{}", r.summary);
    }

    /// RFC 5456 §8.1 assigns 6=IAX, 7=TEXT, 8=IMAGE, 9=HTML. An earlier table
    /// had these shifted down by one, so an IAX control frame read as "text".
    #[test]
    fn frame_types_match_rfc_5456() {
        for (ty, want) in [
            (1u8, "DTMF end"),
            (2, "voice"),
            (3, "video"),
            (4, "control"),
            (6, "IAX control"),
            (7, "text"),
            (8, "image"),
            (9, "HTML"),
            (12, "DTMF begin"),
        ] {
            let r = dissect_iax2(None, None, 4569, 4569, &full_frame(ty));
            assert!(
                r.summary.ends_with(want),
                "frame type {ty} gave {:?}, expected it to end with {want:?}",
                r.summary
            );
        }
    }

    /// The unknown-type arm used to fall back to the literal "full frame",
    /// producing the self-repeating summary "IAX2 full frame — full frame".
    #[test]
    fn unknown_frame_type_does_not_repeat_itself() {
        let r = dissect_iax2(None, None, 4569, 4569, &full_frame(0));
        assert_eq!(r.summary, "IAX2 full frame — unknown type 0");
    }

    #[test]
    fn mini_frame() {
        let r = dissect_iax2(None, None, 4569, 4569, &[0x00, 0x01, 0x02, 0x03]);
        assert!(r.summary.contains("mini frame"), "{}", r.summary);
    }
}
