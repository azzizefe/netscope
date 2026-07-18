// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Known NSQ client commands, used to label the first line of a connection.
const COMMANDS: [&str; 10] = [
    "IDENTIFY", "SUB", "PUB", "MPUB", "RDY", "FIN", "REQ", "TOUCH", "CLS", "NOP",
];

/// Dissect an NSQ message (TCP 4150) — a realtime distributed messaging
/// platform. A connection opens with the magic "  V2", then line commands.
pub fn dissect_nsq(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"  V2") {
        "NSQ handshake (V2)".to_string()
    } else {
        let line = super::first_text_line(payload);
        let tok = line.split_whitespace().next().unwrap_or("");
        if COMMANDS.contains(&tok) {
            format!("NSQ {tok}")
        } else {
            format!("NSQ frame ({} bytes)", payload.len())
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Nsq,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake() {
        let r = dissect_nsq(None, None, 40000, 4150, b"  V2");
        assert_eq!(r.protocol, Protocol::Nsq);
        assert_eq!(r.summary, "NSQ handshake (V2)");
    }

    #[test]
    fn publish() {
        let r = dissect_nsq(None, None, 40000, 4150, b"PUB mytopic\n");
        assert_eq!(r.summary, "NSQ PUB");
    }
}
