// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect WAP WSP / WTP Protocol (UDP 9201).
pub fn dissect_wap_wsp_wtp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = format!("WAP WSP/WTP ({})", super::bytes(payload.len() as u64));

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::WapWspWtp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wap_test() {
        let r = dissect_wap_wsp_wtp(None, None, 40000, 9201, b"\x01\x02\x03\x04");
        assert_eq!(r.protocol, Protocol::WapWspWtp);
    }
}
