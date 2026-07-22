// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect Teradata DBC protocol (TCP 1025).
pub fn dissect_teradata(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = format!("Teradata DBC ({})", super::bytes(payload.len() as u64));

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Teradata,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn teradata_test() {
        let r = dissect_teradata(None, None, 40000, 1025, b"\x00\x01\x02\x03");
        assert_eq!(r.protocol, Protocol::Teradata);
    }
}
