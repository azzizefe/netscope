// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect NIS / Yellow Pages ONC RPC protocol.
pub fn dissect_nis_yp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = format!("NIS/YP ONC RPC ({})", super::bytes(payload.len() as u64));

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::NisYp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nis_yp_test() {
        let r = dissect_nis_yp(None, None, 40000, 111, b"\x00\x00\x00\x00");
        assert_eq!(r.protocol, Protocol::NisYp);
    }
}
