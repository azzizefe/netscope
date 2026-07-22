// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect Odette FTP (OFTP / OFTP2, RFC 2204 / RFC 5024, TCP 3305 / 6619).
pub fn dissect_oftp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 4 {
        let code = match &payload[0..4] {
            b"SSID" => "Start Session",
            b"SSRX" => "Start Session Response",
            b"SFID" => "Start File",
            b"SFPA" => "Start File Ack",
            b"DATA" => "Data Block",
            b"EFID" => "End File",
            b"EFPA" => "End File Ack",
            b"ESID" => "End Session",
            _ => "Message",
        };
        format!("OFTP {code}")
    } else {
        format!("OFTP ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Oftp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oftp_start_session() {
        let payload = b"SSID0001";
        let r = dissect_oftp(None, None, 40000, 3305, payload);
        assert_eq!(r.protocol, Protocol::Oftp);
        assert_eq!(r.summary, "OFTP Start Session");
    }
}
