// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect Mosh Mobile Shell (UDP 60001).
pub fn dissect_mosh(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = format!("Mosh encrypted datagram ({})", super::bytes(payload.len() as u64));

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Mosh,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mosh_test() {
        let r = dissect_mosh(None, None, 40000, 60001, b"\x00\x00\x00\x01mosh");
        assert_eq!(r.protocol, Protocol::Mosh);
    }
}
