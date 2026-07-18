// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Structural check for SPICE: a link message starts with the magic "REDQ".
/// SPICE channels use varied ports, so it's recognised by this magic.
pub fn looks_like_spice(p: &[u8]) -> bool {
    p.starts_with(b"REDQ")
}

/// Dissect a SPICE message — the remote-display protocol for virtual machines
/// (Red Hat / oVirt / QEMU consoles). The link message names the channel type.
pub fn dissect_spice(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    // Link header: magic(4) major(4) minor(4) size(4) connection_id(4) channel_type(1)
    let summary = if payload.starts_with(b"REDQ") {
        // A generic "channel" would render as "SPICE link — channel channel",
        // so an unrecognised channel type reports its number instead.
        match payload.get(20) {
            Some(1) => "SPICE link — main channel".to_string(),
            Some(2) => "SPICE link — display channel".to_string(),
            Some(3) => "SPICE link — inputs channel".to_string(),
            Some(4) => "SPICE link — cursor channel".to_string(),
            Some(5) => "SPICE link — playback channel".to_string(),
            Some(6) => "SPICE link — record channel".to_string(),
            Some(other) => format!("SPICE link — channel type {other}"),
            None => "SPICE link (truncated)".to_string(),
        }
    } else {
        format!("SPICE channel data ({} bytes)", payload.len())
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Spice,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_display() {
        let mut p = b"REDQ".to_vec();
        p.extend_from_slice(&[0u8; 16]); // major, minor, size, connection id
        p.push(2); // channel type: display
        assert!(looks_like_spice(&p));
        let r = dissect_spice(None, None, 40000, 5900, &p);
        assert_eq!(r.protocol, Protocol::Spice);
        assert_eq!(r.summary, "SPICE link — display channel");
    }
}
