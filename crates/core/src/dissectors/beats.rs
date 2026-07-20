// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an Elastic Beats message (TCP 5044) — how Filebeat and friends ship
/// events to Logstash. Byte 0 is the protocol version and byte 1 a frame-type
/// letter.
pub fn dissect_beats(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match (payload.first(), payload.get(1)) {
        (Some(&v @ (b'1' | b'2')), Some(&t)) => {
            let name = match t {
                b'W' => "window size",
                b'C' => "compressed batch",
                b'J' => "JSON event",
                b'D' => "data event",
                b'A' => "ack",
                _ => "frame",
            };
            format!("Beats v{} {name}", (v - b'0'))
        }
        _ => format!("Beats ({})", super::bytes(payload.len() as u64)),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Beats,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_event() {
        let r = dissect_beats(None, None, 40000, 5044, b"2J\x00\x00\x00\x01");
        assert_eq!(r.protocol, Protocol::Beats);
        assert_eq!(r.summary, "Beats v2 JSON event");
    }
}
