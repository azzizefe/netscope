// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;
use super::DissectedResult;

/// Dissect an S7comm-plus message (TCP 102) — Siemens S7-1200/1500 protocol.
pub fn dissect_s7comm_plus(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let base = DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::S7commPlus,
        summary: String::new(),
    };

    // TPKT(4) + COTP(3 for a data TPDU) puts the S7 protocol id at offset 7.
    if payload.len() < 10 {
        return DissectedResult {
            summary: format!(
                "S7comm-plus ({})",
                super::bytes(payload.len() as u64)
            ),
            ..base
        };
    }

    let version = payload[8];
    let opcode = payload[9];

    let op_name = match opcode {
        0x01 => "Request",
        0x02 => "Response",
        0x03 => "Notification",
        _ => "Message",
    };

    let mut func_suffix = String::new();
    if payload.len() >= 14 {
        let f1 = u16::from_be_bytes([payload[10], payload[11]]);
        let f2 = u16::from_be_bytes([payload[12], payload[13]]);
        let fcode = [f1, f2].into_iter().find(|&f| {
            matches!(
                f,
                0x04bb
                    | 0x04ca
                    | 0x04d4
                    | 0x04f2
                    | 0x0524
                    | 0x0542
                    | 0x054c
                    | 0x0556
                    | 0x0560
                    | 0x056b
                    | 0x0586
            )
        });
        if let Some(f) = fcode {
            let fname = match f {
                0x04bb => "Explore",
                0x04ca => "CreateObject",
                0x04d4 => "DeleteObject",
                0x04f2 => "SetVariable",
                0x0524 => "GetLink",
                0x0542 => "SetMultiVariables",
                0x054c => "GetMultiVariables",
                0x0556 => "BeginSequence",
                0x0560 => "EndSequence",
                0x056b => "Invoke",
                0x0586 => "GetVarSubStreamed",
                _ => "Unknown",
            };
            func_suffix = format!(" — {fname}");
        }
    }

    let summary = format!(
        "S7comm-plus {} (v{}){}",
        op_name, version, func_suffix
    );

    DissectedResult { summary, ..base }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s7comm_plus_request_explore() {
        // TPKT(4) + COTP(3) + S7+(0x72 01 01 04 bb ...)
        let mut p = vec![0x03, 0x00, 0x00, 0x1f, 0x02, 0xf0, 0x80];
        p.push(0x72); // S7comm-plus protocol id
        p.push(0x01); // Version 1
        p.push(0x01); // Opcode: Request
        p.push(0x04); // Func part 1
        p.push(0xbb); // Func part 2 (Explore)
        p.extend_from_slice(&[0; 10]);

        let r = dissect_s7comm_plus(None, None, 40000, 102, &p);
        assert_eq!(r.protocol, Protocol::S7commPlus);
        assert_eq!(r.summary, "S7comm-plus Request (v1) — Explore");
    }
}
