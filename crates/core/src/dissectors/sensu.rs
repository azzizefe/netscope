// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect Sensu Go Agent Transport / HTTP API (TCP 3031 / 8080).
pub fn dissect_sensu(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = format!("Sensu Agent ({})", super::bytes(payload.len() as u64));

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Sensu,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensu_test() {
        let r = dissect_sensu(None, None, 40000, 3031, b"\x00\x00\x00\x04");
        assert_eq!(r.protocol, Protocol::Sensu);
    }
}
