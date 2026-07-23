// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect a DCERPC-RS-UNIX packet.
pub fn dissect_dcerpc_rs_unix(
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
        protocol: Protocol::DcerpcRsUnix,
        summary: format!("DCERPC-RS-UNIX ({})", super::bytes(payload.len() as u64)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dcerpc_rs_unix() {
        let r = dissect_dcerpc_rs_unix(None, None, 0, 0, b"\x00\x01");
        assert_eq!(r.protocol, Protocol::DcerpcRsUnix);
    }
}
