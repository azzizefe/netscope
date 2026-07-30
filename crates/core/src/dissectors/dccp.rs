// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Name the DCCP packet type carried in byte 8's Type field (RFC 4340).
fn type_name(t: u8) -> &'static str {
    match t {
        0 => "Request",
        1 => "Response",
        2 => "Data",
        3 => "Ack",
        4 => "DataAck",
        5 => "CloseReq",
        6 => "Close",
        7 => "Reset",
        8 => "Sync",
        9 => "SyncAck",
        _ => "packet",
    }
}

/// Dissect a DCCP packet (IP protocol 33) — a congestion-controlled but
/// unreliable transport used for streaming media. Bytes 0..4 are the ports;
/// byte 8 carries the packet type (RFC 4340).
pub fn dissect_dccp(
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
            protocol: Protocol::Dccp,
            summary: "DCCP (truncated header)".into(),
        };
    }
    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
    let ptype = (payload[8] >> 1) & 0x0F;
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Dccp,
        summary: format!("DCCP {} — {src_port} → {dst_port}", type_name(ptype)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_packet() {
        let mut p = Vec::new();
        p.extend_from_slice(&5001u16.to_be_bytes());
        p.extend_from_slice(&5002u16.to_be_bytes());
        p.extend_from_slice(&[0u8; 4]); // offset, ccval, checksum
        p.push(0x00); // type 0 (Request) in bits 1..5
        p.extend_from_slice(&[0u8; 3]);
        let r = dissect_dccp(None, None, &p);
        assert_eq!(r.protocol, Protocol::Dccp);
        assert_eq!(r.summary, "DCCP Request — 5001 → 5002");
    }
}
