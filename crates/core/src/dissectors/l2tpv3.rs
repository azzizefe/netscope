// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an L2TPv3 packet carried directly on IP (protocol 115) — the
/// pseudowire version of L2TP, which tunnels whole Ethernet or Frame Relay
/// circuits between sites rather than PPP sessions. A session id of zero marks
/// the control channel (RFC 3931).
pub fn dissect_l2tpv3(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 4 {
        let session = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        if session == 0 {
            "L2TPv3 control message".to_string()
        } else {
            format!("L2TPv3 session {session} — tunnelled circuit")
        }
    } else {
        "L2TPv3 (truncated)".to_string()
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: None,
        dst_port: None,
        protocol: Protocol::L2tpv3,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_data() {
        let r = dissect_l2tpv3(None, None, &42u32.to_be_bytes());
        assert_eq!(r.protocol, Protocol::L2tpv3);
        assert!(r.summary.contains("session 42"), "{}", r.summary);
    }

    #[test]
    fn control_channel() {
        let r = dissect_l2tpv3(None, None, &0u32.to_be_bytes());
        assert_eq!(r.summary, "L2TPv3 control message");
    }
}
