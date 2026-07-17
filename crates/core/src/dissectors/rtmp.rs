// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an RTMP message (TCP 1935) — the Flash-era streaming protocol still
/// used to ingest live video. A session opens with a handshake whose first
/// byte (C0/S0) is the protocol version, usually 0x03.
pub fn dissect_rtmp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.first() {
        Some(0x03) => "RTMP handshake".to_string(),
        Some(_) => format!("RTMP chunk ({} bytes)", payload.len()),
        None => "RTMP (empty)".to_string(),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Rtmp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake() {
        let r = dissect_rtmp(None, None, 40000, 1935, &[0x03, 0x00, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::Rtmp);
        assert_eq!(r.summary, "RTMP handshake");
    }
}
