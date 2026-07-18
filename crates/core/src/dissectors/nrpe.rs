// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an NRPE message (TCP 5666) — Nagios Remote Plugin Executor, how a
/// monitoring server asks a host to run a check. Bytes 0..2 are the packet
/// version and 2..4 the type (query or response).
pub fn dissect_nrpe(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 4 {
        let version = u16::from_be_bytes([payload[0], payload[1]]);
        let name = match u16::from_be_bytes([payload[2], payload[3]]) {
            1 => "query",
            2 => "response",
            _ => "packet",
        };
        format!("NRPE v{version} {name}")
    } else {
        format!("NRPE ({} bytes)", payload.len())
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Nrpe,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query() {
        let r = dissect_nrpe(None, None, 40000, 5666, &[0x00, 0x02, 0x00, 0x01]);
        assert_eq!(r.protocol, Protocol::Nrpe);
        assert_eq!(r.summary, "NRPE v2 query");
    }
}
