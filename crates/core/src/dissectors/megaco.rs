// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Megaco / H.248 message (UDP/TCP 2944) — how a call agent controls
/// media gateways in carrier VoIP. The text encoding starts with "MEGACO/" or
/// the short form "!/"; the first keyword names the message.
pub fn dissect_megaco(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let line = super::first_text_line(payload);
    let summary = if line.starts_with("MEGACO/") || line.starts_with("!/") {
        format!("Megaco/H.248 — {}", super::truncate(&line, 40))
    } else {
        format!("Megaco/H.248 ({})", super::bytes(payload.len() as u64))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Megaco,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction() {
        let r = dissect_megaco(
            None,
            None,
            40000,
            2944,
            b"MEGACO/1 [10.0.0.1]:2944\r\nTransaction = 9998 {\r\n",
        );
        assert_eq!(r.protocol, Protocol::Megaco);
        assert!(r.summary.contains("MEGACO/1"), "{}", r.summary);
    }
}
