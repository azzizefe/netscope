// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an IGMP message (IP protocol 2) — how hosts join and leave IPv4
/// multicast groups. The first byte is the message type; bytes 4..8 (when
/// present) are the group address (RFC 2236 / RFC 3376).
pub fn dissect_igmp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.first() {
        Some(&t) => {
            let name = match t {
                0x11 => "Membership Query",
                0x12 => "v1 Membership Report",
                0x16 => "v2 Membership Report",
                0x17 => "Leave Group",
                0x22 => "v3 Membership Report",
                _ => "message",
            };
            match payload.get(4..8) {
                Some(g) if t != 0x22 && g != [0, 0, 0, 0] => {
                    format!("IGMP {name} — group {}.{}.{}.{}", g[0], g[1], g[2], g[3])
                }
                _ => format!("IGMP {name}"),
            }
        }
        None => "IGMP (empty)".to_string(),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Igmp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_report_with_group() {
        let mut p = vec![0x16, 0x00, 0x00, 0x00];
        p.extend_from_slice(&[239, 1, 2, 3]);
        let r = dissect_igmp(None, None, &p);
        assert_eq!(r.protocol, Protocol::Igmp);
        assert_eq!(r.summary, "IGMP v2 Membership Report — group 239.1.2.3");
    }

    #[test]
    fn query() {
        let r = dissect_igmp(None, None, &[0x11, 0x64, 0x00, 0x00, 0, 0, 0, 0]);
        assert_eq!(r.summary, "IGMP Membership Query");
    }
}
