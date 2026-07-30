// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a CAPWAP message (UDP 5246 control / 5247 data) — how a wireless
/// controller manages thin access points. Control traffic is usually
/// DTLS-encrypted (RFC 5415).
pub fn dissect_capwap(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let channel = if src_port == 5247 || dst_port == 5247 {
        "data"
    } else {
        "control"
    };
    // A CAPWAP preamble low nibble of 1 means the payload is DTLS-encrypted.
    let enc = matches!(payload.first(), Some(b) if b & 0x0F == 1);
    let summary = if enc {
        format!("CAPWAP {channel} (DTLS-encrypted)")
    } else {
        format!("CAPWAP {channel}")
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Capwap,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_channel() {
        let r = dissect_capwap(None, None, 40000, 5246, &[0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::Capwap);
        assert_eq!(r.summary, "CAPWAP control");
    }
}
