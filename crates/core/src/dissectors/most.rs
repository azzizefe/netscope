// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// MOST Function Block ID (FBlock ID) names.
fn fblock_name(id: u8) -> &'static str {
    match id {
        0x00 => "NetBlock",
        0x01 => "NetworkMaster",
        0x02 => "ConnectionMaster",
        0x20 => "Audio Player / CD",
        0x22 => "Radio Tuner",
        0x24 => "Amplifier / Sound",
        0x26 => "Telephone",
        0x28 => "Navigation",
        0x30 => "Human Interface / Display",
        0x34 => "Auxiliary / Media",
        0x50 => "Diagnostics / Gateway",
        _ => "Custom FBlock",
    }
}

/// MOST Operation Type (OPType) names.
fn optype_name(optype: u8) -> &'static str {
    match optype {
        0x0 => "Set",
        0x1 => "Get",
        0x2 => "SetGet",
        0x3 => "Increment",
        0x4 => "Decrement",
        0x5 => "Status",
        0x6 => "Interface",
        0x7 => "Error",
        0x8 => "StartResult",
        0x9 => "StartResultAck",
        0xC => "Result",
        0xD => "ResultAck",
        _ => "Reserved OPType",
    }
}

/// Dissect a MOST (Media Oriented Systems Transport) control or data frame.
pub fn dissect_most(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 7 {
        format!("MOST ({})", super::bytes(payload.len() as u64))
    } else {
        let src_addr = u16::from_be_bytes([payload[0], payload[1]]);
        let dst_addr = u16::from_be_bytes([payload[2], payload[3]]);
        let fblock_id = payload[4];
        let inst_id = payload[5];
        let fkt_op = payload[6];

        let fblock_desc = fblock_name(fblock_id);
        let optype = fkt_op & 0x0F;
        let optype_desc = optype_name(optype);

        format!(
            "MOST 0x{src_addr:04X} → 0x{dst_addr:04X} | FBlock 0x{fblock_id:02X} ({fblock_desc}) Inst {inst_id} — {optype_desc}"
        )
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Most,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_most_control_frame() {
        // Src = 0x0110, Dst = 0x0100, FBlock = 0x22 (Radio Tuner), Inst = 1, OPType = 0x1 (Get)
        let payload = vec![0x01, 0x10, 0x01, 0x00, 0x22, 0x01, 0x01, 0x00];
        let res = dissect_most(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::Most);
        assert!(res.summary.contains("0x0110 → 0x0100"));
        assert!(res.summary.contains("Radio Tuner"));
        assert!(res.summary.contains("Get"));
    }

    #[test]
    fn test_most_short_payload() {
        let payload = vec![0x01, 0x02];
        let res = dissect_most(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::Most);
        assert!(res.summary.contains("MOST (2 bytes)"));
    }
}
