// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect Vector Native Protobuf Stream Protocol (TCP 6000).
pub fn dissect_vector_native(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = format!("Vector Native ({})", super::bytes(payload.len() as u64));

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::VectorNative,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_test() {
        let r = dissect_vector_native(None, None, 40000, 6000, b"\x00\x00\x00\x04");
        assert_eq!(r.protocol, Protocol::VectorNative);
    }
}
