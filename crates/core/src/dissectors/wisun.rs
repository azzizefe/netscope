// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect Wi-SUN FAN (Field Area Network / IEEE 802.15.4g sub-GHz mesh) frame.
pub fn dissect_wisun(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 4 {
        let frame_type = payload[0] & 0x07;
        let type_name = match frame_type {
            0 => "Beacon",
            1 => "Data",
            2 => "Ack",
            3 => "MAC Command",
            4 => "LLC / 6LoWPAN",
            _ => "Frame",
        };
        let pan_id = if payload.len() >= 3 {
            u16::from_le_bytes([payload[1], payload[2]])
        } else {
            0
        };
        format!("Wi-SUN FAN {type_name} (PAN 0x{pan_id:04X})")
    } else {
        format!("Wi-SUN FAN ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Wisun,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wisun_data_frame() {
        let payload = vec![0x01, 0x34, 0x12, 0x00];
        let r = dissect_wisun(None, None, 19788, 19788, &payload);
        assert_eq!(r.protocol, Protocol::Wisun);
        assert_eq!(r.summary, "Wi-SUN FAN Data (PAN 0x1234)");
    }
}
