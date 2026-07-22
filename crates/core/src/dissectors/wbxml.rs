// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect WAP Binary XML Content Format (TCP/UDP 9200).
pub fn dissect_wbxml(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = format!("WBXML document ({})", super::bytes(payload.len() as u64));

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Wbxml,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wbxml_test() {
        let r = dissect_wbxml(None, None, 40000, 9200, b"\x03\x01\x6A\x00");
        assert_eq!(r.protocol, Protocol::Wbxml);
    }
}
