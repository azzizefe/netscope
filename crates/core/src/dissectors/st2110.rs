// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect SMPTE ST 2110 Professional Media over Managed IP Networks (ST 2110-20/30/40 RTP stream).
pub fn dissect_st2110(
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
        let stream_kind = match pt {
            96 => "ST 2110-20 Video",
            97 => "ST 2110-30 Audio",
            98 => "ST 2110-40 Ancillary",
            _ => "ST 2110 Stream",
        };
        format!("SMPTE {stream_kind} (PT {pt}, seq {seq}, SSRC 0x{ssrc:08X})")
    } else {
        format!("SMPTE ST 2110 ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::St2110,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_st2110_video() {
        let payload = vec![0x80, 0x60, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD];
        let r = dissect_st2110(None, None, 50000, 50000, &payload);
        assert_eq!(r.protocol, Protocol::St2110);
        assert_eq!(r.summary, "SMPTE ST 2110-20 Video (PT 96, seq 256, SSRC 0xAABBCCDD)");
    }
}
