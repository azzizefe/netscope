// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// SHIM6 Control Message types (RFC 5533 §5.3).
fn shim6_msg_name(kind: u8) -> &'static str {
    match kind {
        1 => "I1 (Initiator 1)",
        2 => "R1 (Responder 1)",
        3 => "I2 (Initiator 2)",
        4 => "R2 (Responder 2)",
        5 => "R1BIS",
        6 => "UPDATE",
        7 => "KEEPALIVE",
        8 => "ERROR",
        _ => "Control Message",
    }
}

/// Dissect a SHIM6 (IPv6 Multihoming Shim Protocol — RFC 5533 / IP Proto 140) message.
pub fn dissect_shim6(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 4 {
        format!("SHIM6 ({})", super::bytes(payload.len() as u64))
    } else {
        let msg_type = payload[1] & 0x7F;
        let type_name = shim6_msg_name(msg_type);

        format!("SHIM6 {type_name}")
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Shim6,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shim6_i1() {
        // Next Hdr = 59, Type = 1 (I1)
        let payload = vec![0x3B, 0x01, 0x00, 0x00];
        let res = dissect_shim6(None, None, &payload);
        assert_eq!(res.protocol, Protocol::Shim6);
        assert!(res.summary.contains("I1 (Initiator 1)"));
    }

    #[test]
    fn test_shim6_short_payload() {
        let payload = vec![0x01, 0x02];
        let res = dissect_shim6(None, None, &payload);
        assert_eq!(res.protocol, Protocol::Shim6);
        assert!(res.summary.contains("SHIM6 (2 bytes)"));
    }
}
