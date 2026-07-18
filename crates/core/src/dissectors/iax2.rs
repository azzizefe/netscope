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
            // Full frame: the frame type sits at offset 10.
            let name = match payload.get(10) {
                Some(1) => "DTMF",
                Some(2) => "voice",
                Some(4) => "IAX control",
                Some(6) => "text",
                Some(7) => "image",
                Some(8) => "HTML",
                _ => "full frame",
            };
            format!("IAX2 full frame — {name}")
        }
        Some(_) => format!("IAX2 mini frame (media, {} bytes)", payload.len()),
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

    #[test]
    fn full_frame_control() {
        let mut p = vec![0x80, 0x01]; // full frame, source call 1
        p.extend_from_slice(&[0u8; 8]);
        p.push(4); // frame type: IAX control
        let r = dissect_iax2(None, None, 4569, 4569, &p);
        assert_eq!(r.protocol, Protocol::Iax2);
        assert!(r.summary.contains("IAX control"), "{}", r.summary);
    }

    #[test]
    fn mini_frame() {
        let r = dissect_iax2(None, None, 4569, 4569, &[0x00, 0x01, 0x02, 0x03]);
        assert!(r.summary.contains("mini frame"), "{}", r.summary);
    }
}
