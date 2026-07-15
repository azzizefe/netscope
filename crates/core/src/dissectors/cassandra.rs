// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::{truncate, DissectedResult};

/// Dissect a Cassandra CQL native-protocol frame (TCP 9042).
///
/// The CQL binary protocol frames as: version(1) + flags(1) + stream(2) +
/// opcode(1) + length(Int32) + body. The version byte's high bit marks the
/// direction (0x0x = request, 0x8x = response); the low nibble is the protocol
/// version (3, 4, 5). We name the opcode and, for a QUERY, surface the CQL text.
pub fn dissect_cassandra(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let result = |summary: String| DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Cassandra,
        summary,
    };

    if payload.len() < 9 {
        return result("Cassandra CQL (partial)".into());
    }

    let version = payload[0];
    let is_response = version & 0x80 != 0;
    let proto_ver = version & 0x7f;
    let opcode = payload[4];
    let body = &payload[9..];

    let name = opcode_name(opcode);
    let summary = match opcode {
        0x07 => {
            // QUERY: [long string] query text — 4-byte length then UTF-8.
            format!("CQL QUERY — {}", truncate(&long_string(body), 70))
        }
        0x00 => format!("CQL ERROR — {}", truncate(&error_message(body), 60)),
        _ => {
            let dir = if is_response { "response" } else { "request" };
            format!("CQL {name} ({dir}, v{proto_ver})")
        }
    };

    result(summary)
}

fn opcode_name(op: u8) -> &'static str {
    match op {
        0x00 => "ERROR",
        0x01 => "STARTUP",
        0x02 => "READY",
        0x03 => "AUTHENTICATE",
        0x05 => "OPTIONS",
        0x06 => "SUPPORTED",
        0x07 => "QUERY",
        0x08 => "RESULT",
        0x09 => "PREPARE",
        0x0a => "EXECUTE",
        0x0b => "REGISTER",
        0x0c => "EVENT",
        0x0d => "BATCH",
        0x0e => "AUTH_CHALLENGE",
        0x0f => "AUTH_RESPONSE",
        0x10 => "AUTH_SUCCESS",
        _ => "unknown",
    }
}

/// CQL `[long string]`: a 4-byte big-endian length then that many UTF-8 bytes.
fn long_string(body: &[u8]) -> String {
    if body.len() < 4 {
        return String::new();
    }
    let len = u32::from_be_bytes([body[0], body[1], body[2], body[3]]) as usize;
    let end = (4 + len).min(body.len());
    String::from_utf8_lossy(&body[4..end]).trim().to_string()
}

/// ERROR body: code(Int32) then a `[string]` (2-byte length) message.
fn error_message(body: &[u8]) -> String {
    if body.len() < 6 {
        return String::new();
    }
    let len = u16::from_be_bytes([body[4], body[5]]) as usize;
    let end = (6 + len).min(body.len());
    String::from_utf8_lossy(&body[6..end]).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(version: u8, opcode: u8, body: &[u8]) -> Vec<u8> {
        let mut p = vec![version, 0, 0, 1, opcode];
        p.extend_from_slice(&(body.len() as u32).to_be_bytes());
        p.extend_from_slice(body);
        p
    }

    #[test]
    fn query_frame() {
        let cql = b"SELECT * FROM system.local";
        let mut body = Vec::new();
        body.extend_from_slice(&(cql.len() as u32).to_be_bytes());
        body.extend_from_slice(cql);
        let p = frame(0x04, 0x07, &body);
        let r = dissect_cassandra(None, None, 50000, 9042, &p);
        assert_eq!(r.protocol, Protocol::Cassandra);
        assert_eq!(r.summary, "CQL QUERY — SELECT * FROM system.local");
    }

    #[test]
    fn startup_request() {
        let p = frame(0x04, 0x01, &[]);
        let r = dissect_cassandra(None, None, 50000, 9042, &p);
        assert_eq!(r.summary, "CQL STARTUP (request, v4)");
    }

    #[test]
    fn ready_response() {
        let p = frame(0x84, 0x02, &[]);
        let r = dissect_cassandra(None, None, 9042, 50000, &p);
        assert_eq!(r.summary, "CQL READY (response, v4)");
    }
}
