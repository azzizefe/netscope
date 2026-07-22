// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Emerson ROC Plus opcode descriptions (ROC Plus User Manual / SCADA spec).
fn opcode_name(opcode: u8) -> &'static str {
    match opcode {
        120 => "Read Configuration",
        121 => "Write Configuration",
        160 => "Read Point Data",
        161 => "Write Point Data",
        165 => "Data Transfer",
        167 => "Real Time Clock Read",
        168 => "Real Time Clock Write",
        176 => "Read Alarm Log",
        177 => "Read History Data",
        254 => "Security / Login",
        255 => "Opcode Error Response",
        _ => "Unknown Opcode",
    }
}

/// Dissect an Emerson ROC Plus message — SCADA protocol used in Emerson ROC300,
/// ROC800 and DL8000 flow computers on TCP or UDP port 4000.
pub fn dissect_roc_plus(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 5 {
        format!("ROC Plus ({})", super::bytes(payload.len() as u64))
    } else {
        let dest_unit = payload[0];
        let dest_group = payload[1];
        let opcode = payload[4];
        let op_name = opcode_name(opcode);

        if opcode == 255 {
            format!("ROC Plus Error Response — unit {dest_unit}.{dest_group}")
        } else {
            format!("ROC Plus {op_name} (Opcode {opcode}) — unit {dest_unit}.{dest_group}")
        }
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::RocPlus,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roc_plus_read_point() {
        // Unit 1, Group 2, SrcUnit 10, SrcGroup 1, Opcode 160 (0xA0)
        let payload = vec![0x01, 0x02, 0x0A, 0x01, 0xA0, 0x00];
        let res = dissect_roc_plus(None, None, 40000, 4000, &payload);
        assert_eq!(res.protocol, Protocol::RocPlus);
        assert!(res.summary.contains("Read Point Data"));
        assert!(res.summary.contains("unit 1.2"));
    }

    #[test]
    fn test_roc_plus_short_payload() {
        let payload = vec![0x01, 0x02];
        let res = dissect_roc_plus(None, None, 40000, 4000, &payload);
        assert_eq!(res.protocol, Protocol::RocPlus);
        assert!(res.summary.contains("ROC Plus (2 bytes)"));
    }
}
