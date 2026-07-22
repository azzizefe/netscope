// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect SPDY Web Framing Protocol (TCP 443).
pub fn dissect_spdy(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 2 && (payload[0] & 0x80) != 0 {
        "SPDY control frame".to_string()
    } else {
        format!("SPDY data frame ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Spdy,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spdy_test() {
        let r = dissect_spdy(None, None, 40000, 443, b"\x80\x03\x00\x01");
        assert_eq!(r.protocol, Protocol::Spdy);
        assert_eq!(r.summary, "SPDY control frame");
    }
}
