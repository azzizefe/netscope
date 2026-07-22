// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an RSVP message (IP protocol 46) — the protocol that reserves
/// bandwidth for QoS and signals MPLS traffic-engineering tunnels. Byte 1 is
/// the message type (RFC 2205 / RFC 3209).
pub fn dissect_rsvp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.get(1) {
        Some(&t) => {
            let name = match t {
                1 => "Path",
                2 => "Resv",
                3 => "PathErr",
                4 => "ResvErr",
                5 => "PathTear",
                6 => "ResvTear",
                7 => "ResvConf",
                _ => "message",
            };
            let is_te = payload.windows(2).any(|w| w[1] == 20 || w[1] == 21 || w[1] == 207);
            let te_prefix = if is_te { "RSVP-TE" } else { "RSVP" };
            format!("{te_prefix} {name}")
        }
        None => "RSVP (truncated)".to_string(),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Rsvp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_message() {
        // version 1 (0x10), message type 1 (Path).
        let r = dissect_rsvp(None, None, &[0x10, 0x01, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::Rsvp);
        assert_eq!(r.summary, "RSVP Path");
    }
}
