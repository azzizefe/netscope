// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an sFlow datagram (UDP 6343) — switches exporting sampled packets
/// and interface counters to a collector. The first four bytes are the version
/// (sFlow v5 is the common one).
pub fn dissect_sflow(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 4 {
        let version = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        format!("sFlow v{version} sample datagram")
    } else {
        "sFlow (truncated)".to_string()
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Sflow,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v5() {
        let r = dissect_sflow(None, None, 40000, 6343, &[0x00, 0x00, 0x00, 0x05]);
        assert_eq!(r.protocol, Protocol::Sflow);
        assert_eq!(r.summary, "sFlow v5 sample datagram");
    }
}
