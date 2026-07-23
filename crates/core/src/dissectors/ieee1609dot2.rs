// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect an IEEE1609DOT2 packet.
pub fn dissect_ieee1609dot2(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Ieee1609dot2,
        summary: format!("IEEE1609DOT2 ({})", super::bytes(payload.len() as u64)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ieee1609dot2() {
        let r = dissect_ieee1609dot2(None, None, 0, 0, b"\x00\x01");
        assert_eq!(r.protocol, Protocol::Ieee1609dot2);
    }
}
