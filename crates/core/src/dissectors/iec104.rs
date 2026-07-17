// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an IEC 60870-5-104 message (TCP 2404) — SCADA telecontrol for power
/// grids. Each APCI starts with 0x68; the first control octet's low bits select
/// the frame format (I / S / U).
pub fn dissect_iec104(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 3 && payload[0] == 0x68 {
        let ctrl = payload[2];
        let fmt = if ctrl & 0x01 == 0 {
            "I-frame (information)"
        } else if ctrl & 0x03 == 0x01 {
            "S-frame (supervisory)"
        } else {
            "U-frame (control)"
        };
        format!("IEC 60870-5-104 {fmt}")
    } else {
        format!("IEC-104 ({} bytes)", payload.len())
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Iec104,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_frame() {
        // Start 0x68, length, control octet 0x00 (I-frame).
        let r = dissect_iec104(None, None, 40000, 2404, &[0x68, 0x04, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::Iec104);
        assert!(r.summary.contains("I-frame"), "{}", r.summary);
    }
}
