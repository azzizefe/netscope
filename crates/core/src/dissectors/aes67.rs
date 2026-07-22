// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect AES67 High-performance Audio over IP (RTP audio profile / 48kHz L16/L24 over UDP 5004).
pub fn dissect_aes67(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 12 && (payload[0] >> 6) == 2 {
        let seq = u16::from_be_bytes([payload[2], payload[3]]);
        let ssrc = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
        let pt = payload[1] & 0x7F;
        format!("AES67 Audio RTP (PT {pt}, seq {seq}, SSRC 0x{ssrc:08X})")
    } else {
        format!("AES67 Audio ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Aes67,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes67_rtp() {
        let mut payload = vec![0x80, 0x60, 0x00, 0x2A, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78];
        payload.extend(vec![0u8; 48]);
        let r = dissect_aes67(None, None, 5004, 5004, &payload);
        assert_eq!(r.protocol, Protocol::Aes67);
        assert_eq!(r.summary, "AES67 Audio RTP (PT 96, seq 42, SSRC 0x12345678)");
    }
}
