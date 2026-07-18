// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Citrix ICA message (TCP 1494) — the thin-client protocol carrying
/// a published app or desktop session. A session opens with a 0x7f 0x7f
/// handshake preamble.
pub fn dissect_ica(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 2 && payload[0] == 0x7f && payload[1] == 0x7f {
        "Citrix ICA handshake".to_string()
    } else {
        format!("Citrix ICA session data ({} bytes)", payload.len())
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Ica,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake() {
        let r = dissect_ica(None, None, 40000, 1494, &[0x7f, 0x7f, 0x49, 0x43]);
        assert_eq!(r.protocol, Protocol::Ica);
        assert_eq!(r.summary, "Citrix ICA handshake");
    }
}
