// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a RIP message (UDP 520) — a classic distance-vector routing
/// protocol. Byte 0 is the command, byte 1 the version (RFC 2453).
pub fn dissect_rip(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match (payload.first(), payload.get(1)) {
        (Some(&cmd), Some(&ver)) => {
            let name = match cmd {
                1 => "Request",
                2 => "Response",
                _ => "message",
            };
            format!("RIPv{ver} {name}")
        }
        _ => "RIP (truncated)".to_string(),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Rip,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_v2() {
        let r = dissect_rip(None, None, 520, 520, &[0x02, 0x02, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::Rip);
        assert_eq!(r.summary, "RIPv2 Response");
    }
}
