// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect Voldemort custom binary protocol (TCP 6666).
pub fn dissect_voldemort(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 2 && &payload[..2] == b"pb" {
        "Voldemort Protocol Buffers wire".to_string()
    } else {
        format!("Voldemort KV protocol ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Voldemort,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn voldemort_test() {
        let r = dissect_voldemort(None, None, 40000, 6666, b"pb");
        assert_eq!(r.protocol, Protocol::Voldemort);
        assert!(r.summary.contains("Protocol Buffers"));
    }
}
