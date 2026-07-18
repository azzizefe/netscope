// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an RMCP message (UDP 623) — the transport for IPMI out-of-band
/// server management (BMCs / iLO / iDRAC). Byte 0 is the version (0x06) and
/// byte 3's low bits select the message class (IPMI/ASF/OEM).
pub fn dissect_rmcp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 4 && payload[0] == 0x06 {
        let class = match payload[3] & 0x1F {
            6 => "ASF",
            7 => "IPMI",
            8 => "OEM",
            _ => "message",
        };
        format!("RMCP/{class} (out-of-band management)")
    } else {
        format!("RMCP ({} bytes)", payload.len())
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Rmcp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipmi_class() {
        // version 0x06, reserved, seq, class 0x07 (IPMI).
        let r = dissect_rmcp(None, None, 40000, 623, &[0x06, 0x00, 0xFF, 0x07]);
        assert_eq!(r.protocol, Protocol::Rmcp);
        assert!(r.summary.contains("IPMI"), "{}", r.summary);
    }
}
