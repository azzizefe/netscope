// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an XCP-on-Ethernet message (UDP/TCP 5555) — the ASAM protocol for
/// measuring and calibrating ECUs. A 4-byte transport header (length + counter,
/// little-endian) precedes the packet identifier (PID).
pub fn dissect_xcp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.get(4) {
        Some(&pid) => {
            let name = match pid {
                0xFF => "CONNECT / positive response",
                0xFE => "DISCONNECT / error",
                0xFD => "event",
                0xFC => "service request",
                0xF6 => "SHORT_UPLOAD",
                0xF5 => "UPLOAD",
                _ => "packet",
            };
            format!("XCP {name}")
        }
        None => "XCP (truncated)".to_string(),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Xcp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect() {
        // len(2 LE), counter(2 LE), PID 0xFF (CONNECT).
        let r = dissect_xcp(None, None, 40000, 5555, &[0x01, 0x00, 0x00, 0x00, 0xFF]);
        assert_eq!(r.protocol, Protocol::Xcp);
        assert!(r.summary.contains("CONNECT"), "{}", r.summary);
    }
}
