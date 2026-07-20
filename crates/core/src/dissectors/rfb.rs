// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an RFB / VNC message (TCP 5900). A session opens with a 12-byte
/// `RFB 003.008\n` protocol-version banner from each side (RFC 6143).
pub fn dissect_rfb(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"RFB ") && payload.len() >= 12 {
        format!(
            "VNC/RFB handshake — {}",
            String::from_utf8_lossy(&payload[..12]).trim()
        )
    } else {
        format!("VNC/RFB — {}", super::bytes(payload.len() as u64))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Rfb,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_banner() {
        let r = dissect_rfb(None, None, 5900, 40000, b"RFB 003.008\n");
        assert_eq!(r.protocol, Protocol::Rfb);
        assert_eq!(r.summary, "VNC/RFB handshake — RFB 003.008");
    }

    #[test]
    fn mid_session_bytes() {
        let r = dissect_rfb(None, None, 40000, 5900, &[0x00, 0x01, 0x02]);
        assert!(r.summary.contains("VNC/RFB — 3 bytes"));
    }
}
