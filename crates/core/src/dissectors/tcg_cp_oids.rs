// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect an TCG-CP-OIDS packet.
pub fn dissect_tcg_cp_oids(
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
        protocol: Protocol::TcgCpOids,
        summary: format!("TCG-CP-OIDS ({})", super::bytes(payload.len() as u64)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcg_cp_oids() {
        let r = dissect_tcg_cp_oids(None, None, 0, 0, b"\x00\x01");
        assert_eq!(r.protocol, Protocol::TcgCpOids);
    }
}
