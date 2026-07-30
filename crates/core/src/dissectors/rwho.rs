// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an rwho broadcast (UDP 513) — the rwhod daemon periodically
/// announcing a host's uptime, load and logged-in users to the whole LAN.
/// Note the TCP side of port 513 is rlogin; these never collide.
pub fn dissect_rwho(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    // Header: version, type, pad(2), sendtime(4), recvtime(4), hostname[32].
    let summary = if payload.len() >= 44 {
        let host = String::from_utf8_lossy(&payload[12..44])
            .trim_end_matches('\0')
            .trim()
            .to_string();
        if host.is_empty() {
            format!("rwho broadcast ({})", super::bytes(payload.len() as u64))
        } else {
            format!("rwho broadcast from {}", super::truncate(&host, 24))
        }
    } else {
        format!("rwho broadcast ({})", super::bytes(payload.len() as u64))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Rwho,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_the_host() {
        let mut p = vec![1, 1, 0, 0];
        p.extend_from_slice(&[0u8; 8]); // send/recv time
        let mut host = b"bsdbox".to_vec();
        host.resize(32, 0);
        p.extend_from_slice(&host);
        let r = dissect_rwho(None, None, 513, 513, &p);
        assert_eq!(r.protocol, Protocol::Rwho);
        assert_eq!(r.summary, "rwho broadcast from bsdbox");
    }
}
