// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect IBM Informix SQLI protocol (TCP 9088 / 1526).
pub fn dissect_informix(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = format!("Informix SQLI ({})", super::bytes(payload.len() as u64));

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Informix,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn informix_test() {
        let r = dissect_informix(None, None, 40000, 9088, b"\x00\x08sqli");
        assert_eq!(r.protocol, Protocol::Informix);
    }
}
