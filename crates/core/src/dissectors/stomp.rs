// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Known STOMP frame commands (STOMP 1.2) — used to confirm the first line is
/// really a command frame rather than arbitrary text on the port.
const COMMANDS: [&str; 12] = [
    "CONNECT",
    "STOMP",
    "CONNECTED",
    "SEND",
    "SUBSCRIBE",
    "UNSUBSCRIBE",
    "ACK",
    "NACK",
    "BEGIN",
    "MESSAGE",
    "RECEIPT",
    "ERROR",
];

/// Dissect a STOMP message (TCP 61613) — a simple text messaging protocol for
/// brokers like ActiveMQ and RabbitMQ. The first line is the frame command.
pub fn dissect_stomp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let line = super::first_text_line(payload);
    let summary = if COMMANDS.contains(&line.as_str()) {
        format!("STOMP {line}")
    } else if line.is_empty() {
        format!("STOMP ({} bytes)", payload.len())
    } else {
        format!("STOMP — {}", super::truncate(&line, 48))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Stomp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_frame() {
        let r = dissect_stomp(
            None,
            None,
            40000,
            61613,
            b"SEND\r\ndestination:/queue/a\r\n\r\nhi\0",
        );
        assert_eq!(r.protocol, Protocol::Stomp);
        assert_eq!(r.summary, "STOMP SEND");
    }
}
