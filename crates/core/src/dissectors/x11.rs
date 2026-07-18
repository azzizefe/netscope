// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an X11 message (TCP 6000+) — the classic Unix display protocol
/// carrying GUI drawing between an app and an X server. A session opens with a
/// byte-order byte: 0x42 'B' (big-endian) or 0x6C 'l' (little-endian).
pub fn dissect_x11(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.first() {
        Some(0x42) if payload.get(1) == Some(&0) => "X11 connection setup (big-endian)".to_string(),
        Some(0x6C) if payload.get(1) == Some(&0) => {
            "X11 connection setup (little-endian)".to_string()
        }
        Some(_) => format!("X11 request/data ({} bytes)", payload.len()),
        None => "X11 (empty)".to_string(),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::X11,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup() {
        let r = dissect_x11(None, None, 40000, 6000, &[0x6C, 0x00, 0x0B, 0x00]);
        assert_eq!(r.protocol, Protocol::X11);
        assert_eq!(r.summary, "X11 connection setup (little-endian)");
    }
}
