// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect EPICS Channel Access (TCP/UDP 5064 / 5065).
pub fn dissect_epics_ca(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 16 {
        let command = u16::from_be_bytes([payload[0], payload[1]]);
        let payload_size = u16::from_be_bytes([payload[2], payload[3]]);
        format!("EPICS CA cmd 0x{:04X} ({} bytes)", command, payload_size)
    } else {
        format!("EPICS Channel Access ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::EpicsCa,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epics_ca_test() {
        let r = dissect_epics_ca(None, None, 40000, 5064, b"\x00\x06\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01");
        assert_eq!(r.protocol, Protocol::EpicsCa);
        assert!(r.summary.contains("EPICS CA cmd"));
    }
}
