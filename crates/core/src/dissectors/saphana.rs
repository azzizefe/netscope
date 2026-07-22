// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect SAP HANA SQLDBC binary protocol (TCP 30015 / 39015).
pub fn dissect_saphana(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = format!("SAP HANA SQLDBC ({})", super::bytes(payload.len() as u64));

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SapHana,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saphana_test() {
        let r = dissect_saphana(None, None, 40000, 30015, b"\x00\x00\x00\x10");
        assert_eq!(r.protocol, Protocol::SapHana);
    }
}
