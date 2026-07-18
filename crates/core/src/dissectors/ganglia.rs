// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Ganglia gmond message (UDP 8649) — cluster monitoring metrics,
/// encoded as XDR. The leading 32-bit id says whether the packet carries a
/// metric's metadata or one of the typed values.
pub fn dissect_ganglia(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 4 {
        let id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let name = match id {
            128 => "metric metadata",
            129 => "ushort value",
            130 => "short value",
            131 => "int value",
            132 => "uint value",
            133 => "string value",
            134 => "float value",
            135 => "double value",
            136 => "metadata request",
            _ => "packet",
        };
        format!("Ganglia gmond — {name}")
    } else {
        format!("Ganglia gmond ({} bytes)", payload.len())
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Ganglia,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata() {
        let r = dissect_ganglia(None, None, 40000, 8649, &[0, 0, 0, 128]);
        assert_eq!(r.protocol, Protocol::Ganglia);
        assert!(r.summary.contains("metric metadata"), "{}", r.summary);
    }
}
