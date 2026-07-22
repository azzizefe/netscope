// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Bristol Standard Asynchronous Protocol (BSAP) function code descriptions.
fn function_name(func: u8) -> &'static str {
    match func {
        0x01 => "Read Data / Poll",
        0x02 => "Write Data",
        0x03 => "Master/Slave Transfer",
        0x04 => "Time Sync",
        0x05 => "Program Transfer",
        0x06 => "Control Command",
        0x07 => "Alarm Acknowledge",
        0x0F => "Diagnostic / Status",
        _ => "Unknown Function",
    }
}

/// Dissect a Bristol BSAP message — protocol used by Bristol Babcock (Emerson)
/// Network 3000 and ControlWave RTUs on UDP/TCP port 1234 or UDP port 4268.
pub fn dissect_bsap(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 4 {
        format!("BSAP ({})", super::bytes(payload.len() as u64))
    } else {
        let dst_node = payload[0];
        let src_node = payload[1];
        let func = payload[3];
        let fname = function_name(func);
        format!("BSAP {fname} — node {src_node} → {dst_node}")
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Bsap,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bsap_read_data() {
        // DstNode: 1, SrcNode: 10, Seq: 0x01, Func: 0x01 (Read Data)
        let payload = vec![0x01, 0x0A, 0x01, 0x01, 0x00];
        let res = dissect_bsap(None, None, 40000, 1234, &payload);
        assert_eq!(res.protocol, Protocol::Bsap);
        assert!(res.summary.contains("Read Data / Poll"));
        assert!(res.summary.contains("node 10 → 1"));
    }

    #[test]
    fn test_bsap_short_payload() {
        let payload = vec![0x01, 0x0A];
        let res = dissect_bsap(None, None, 40000, 1234, &payload);
        assert_eq!(res.protocol, Protocol::Bsap);
        assert!(res.summary.contains("BSAP (2 bytes)"));
    }
}
