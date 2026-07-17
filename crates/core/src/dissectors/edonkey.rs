// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an eDonkey/eMule message (TCP 4662) — a peer-to-peer file-sharing
/// network. Byte 0 is the protocol marker.
pub fn dissect_edonkey(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.first() {
        Some(0xE3) => "eDonkey message".to_string(),
        Some(0xC5) => "eMule extended message".to_string(),
        Some(0xD4) => "eMule compressed message".to_string(),
        _ => format!("eDonkey/eMule ({} bytes)", payload.len()),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Edonkey,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emule() {
        let r = dissect_edonkey(None, None, 40000, 4662, &[0xC5, 0x00, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::Edonkey);
        assert_eq!(r.summary, "eMule extended message");
    }
}
