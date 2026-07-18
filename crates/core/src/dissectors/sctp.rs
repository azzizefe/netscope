// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Name the SCTP chunk type in the first chunk of the packet (RFC 4960).
fn chunk_name(t: u8) -> &'static str {
    match t {
        0 => "DATA",
        1 => "INIT",
        2 => "INIT ACK",
        3 => "SACK",
        4 => "HEARTBEAT",
        5 => "HEARTBEAT ACK",
        6 => "ABORT",
        7 => "SHUTDOWN",
        8 => "SHUTDOWN ACK",
        9 => "ERROR",
        10 => "COOKIE ECHO",
        11 => "COOKIE ACK",
        14 => "SHUTDOWN COMPLETE",
        _ => "chunk",
    }
}

/// Dissect an SCTP packet (IP protocol 132). The 12-byte common header carries
/// source/destination ports and a verification tag; the first chunk's type
/// names what the packet is doing (RFC 4960).
pub fn dissect_sctp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    if payload.len() < 12 {
        return DissectedResult {
            src_addr: src_ip,
            dst_addr: dst_ip,
            src_port: None,
            dst_port: None,
            protocol: Protocol::Sctp,
            summary: "SCTP (truncated header)".into(),
        };
    }
    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
    let summary = match payload.get(12) {
        Some(&t) => format!("SCTP {} — {src_port} → {dst_port}", chunk_name(t)),
        None => format!("SCTP — {src_port} → {dst_port}"),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Sctp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_chunk() {
        let mut p = Vec::new();
        p.extend_from_slice(&1234u16.to_be_bytes()); // src port
        p.extend_from_slice(&38412u16.to_be_bytes()); // dst port
        p.extend_from_slice(&[0u8; 8]); // vtag + checksum
        p.push(1); // chunk type: INIT
        let r = dissect_sctp(None, None, &p);
        assert_eq!(r.protocol, Protocol::Sctp);
        assert_eq!(r.summary, "SCTP INIT — 1234 → 38412");
        assert_eq!(r.src_port, Some(1234));
    }
}
