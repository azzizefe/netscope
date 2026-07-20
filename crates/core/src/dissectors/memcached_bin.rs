// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Memcached's binary protocol, which shares port 11211 with the text one.
//!
//! The two are different protocols on the same port, told apart by a magic
//! byte. The text form is what a person types at a telnet prompt; the binary
//! form is what client libraries use in production, so it is the one a real
//! capture is full of — and reading it as text produces nothing at all.
//!
//! The status field on a response carries the fact worth having: a `NOT_FOUND`
//! is a cache miss, and a capture that is mostly misses explains a slow
//! application better than any latency number.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// The magic byte, which is also what identifies the protocol.
const MAGIC_REQUEST: u8 = 0x80;
const MAGIC_RESPONSE: u8 = 0x81;

/// Magic, opcode, key length, extras length, data type, status, body length,
/// opaque and CAS — twenty-four bytes.
const HEADER: usize = 24;
const OFFSET_KEY_LEN: usize = 2;
const OFFSET_STATUS: usize = 6;

/// Opcodes (memcached binary protocol). The list covers what a client library
/// actually sends.
fn opcode_name(op: u8) -> Option<&'static str> {
    Some(match op {
        0x00 => "Get",
        0x01 => "Set",
        0x02 => "Add",
        0x03 => "Replace",
        0x04 => "Delete",
        0x05 => "Increment",
        0x06 => "Decrement",
        0x07 => "Quit",
        0x08 => "Flush",
        0x09 => "GetQ",
        0x0A => "No-op",
        0x0B => "Version",
        0x0C => "GetK",
        0x0D => "GetKQ",
        0x0E => "Append",
        0x0F => "Prepend",
        0x10 => "Stat",
        0x11 => "SetQ",
        0x12 => "AddQ",
        0x13 => "ReplaceQ",
        0x14 => "DeleteQ",
        0x1F => "SASL list mechanisms",
        0x20 => "SASL auth",
        0x21 => "SASL step",
        0x22 => "Touch",
        0x23 => "GAT (get and touch)",
        _ => return None,
    })
}

/// Response status codes. Only the ones that mean something operationally are
/// named; success is the overwhelming majority and needs no comment.
fn status_name(status: u16) -> Option<&'static str> {
    Some(match status {
        0x0000 => "success",
        0x0001 => "not found (cache miss)",
        0x0002 => "key exists",
        0x0003 => "value too large",
        0x0004 => "invalid arguments",
        0x0005 => "item not stored",
        0x0006 => "value is not numeric",
        0x0020 => "authentication required",
        0x0021 => "authentication continues",
        0x0081 => "unknown command",
        0x0082 => "out of memory",
        0x0083 => "not supported",
        0x0084 => "internal error",
        0x0085 => "busy",
        0x0086 => "temporary failure",
        _ => return None,
    })
}

/// Whether a payload is a binary-protocol message.
pub(crate) fn looks_like_binary(payload: &[u8]) -> bool {
    payload.len() >= HEADER
        && matches!(payload[0], MAGIC_REQUEST | MAGIC_RESPONSE)
        && opcode_name(payload[1]).is_some()
}

/// Read the key, which names what is being cached.
fn key(payload: &[u8]) -> Option<String> {
    let len = u16::from_be_bytes([
        *payload.get(OFFSET_KEY_LEN)?,
        *payload.get(OFFSET_KEY_LEN + 1)?,
    ]) as usize;
    if len == 0 {
        return None;
    }
    let extras = *payload.get(4)? as usize;
    let text = payload.get(HEADER + extras..HEADER + extras + len)?;
    let text = std::str::from_utf8(text).ok()?;
    if text.is_empty() || !text.chars().all(|c| c.is_ascii_graphic()) {
        return None;
    }
    Some(text.to_string())
}

/// Dissect a binary memcached message.
pub fn dissect_memcached_bin(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < HEADER {
        format!("Memcached ({})", super::bytes(payload.len() as u64))
    } else {
        let opcode = payload[1];
        let name = match opcode_name(opcode) {
            Some(n) => n.to_string(),
            None => format!("opcode 0x{opcode:02x}"),
        };
        if payload[0] == MAGIC_RESPONSE {
            let status = u16::from_be_bytes([payload[OFFSET_STATUS], payload[OFFSET_STATUS + 1]]);
            match status_name(status) {
                Some("success") => format!("Memcached {name} response"),
                Some(text) => format!("Memcached {name} response — {text}"),
                None => format!("Memcached {name} response — status 0x{status:04x}"),
            }
        } else {
            match key(payload) {
                Some(k) => format!("Memcached {name} — {}", super::truncate(&k, 40)),
                None => format!("Memcached {name}"),
            }
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::MemcachedBin,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a request carrying the given key.
    fn request(opcode: u8, key: &str) -> Vec<u8> {
        let mut p = vec![MAGIC_REQUEST, opcode];
        p.extend_from_slice(&(key.len() as u16).to_be_bytes());
        p.push(0); // extras length
        p.push(0); // data type
        p.extend_from_slice(&0u16.to_be_bytes()); // vbucket
        p.extend_from_slice(&(key.len() as u32).to_be_bytes()); // total body
        p.extend_from_slice(&[0u8; 4]); // opaque
        p.extend_from_slice(&[0u8; 8]); // CAS
        p.extend_from_slice(key.as_bytes());
        p
    }

    /// Build a response with the given status.
    fn response(opcode: u8, status: u16) -> Vec<u8> {
        let mut p = vec![MAGIC_RESPONSE, opcode];
        p.extend_from_slice(&0u16.to_be_bytes()); // key length
        p.push(0);
        p.push(0);
        p.extend_from_slice(&status.to_be_bytes());
        p.extend_from_slice(&0u32.to_be_bytes()); // total body
        p.extend_from_slice(&[0u8; 4]); // opaque
        p.extend_from_slice(&[0u8; 8]); // CAS
        debug_assert_eq!(p.len(), HEADER);
        p
    }

    /// The key names what is being cached, which is the whole point of a
    /// capture taken to work out what an application is asking for.
    #[test]
    fn a_request_names_its_key() {
        let r = dissect_memcached_bin(None, None, 40000, 11211, &request(0x00, "user:42:profile"));
        assert_eq!(r.protocol, Protocol::MemcachedBin);
        assert_eq!(r.summary, "Memcached Get — user:42:profile");
    }

    /// A capture that is mostly misses explains a slow application better than
    /// any latency figure.
    #[test]
    fn a_cache_miss_is_named() {
        let r = dissect_memcached_bin(None, None, 11211, 1, &response(0x00, 0x0001));
        assert_eq!(r.summary, "Memcached Get response — not found (cache miss)");
        let r = dissect_memcached_bin(None, None, 11211, 1, &response(0x00, 0x0000));
        assert_eq!(r.summary, "Memcached Get response");
    }

    /// A server out of memory is evicting things, which looks like a miss
    /// storm from the client's side and has a different fix.
    #[test]
    fn server_side_failures_are_named() {
        assert_eq!(
            dissect_memcached_bin(None, None, 11211, 1, &response(0x01, 0x0082)).summary,
            "Memcached Set response — out of memory"
        );
        assert_eq!(
            dissect_memcached_bin(None, None, 11211, 1, &response(0x00, 0x0020)).summary,
            "Memcached Get response — authentication required"
        );
    }

    /// The magic byte is what separates this from the text protocol sharing
    /// the port, so it has to be checked rather than assumed.
    #[test]
    fn the_text_protocol_is_not_claimed() {
        assert!(!looks_like_binary(b"get user:42\r\n"));
        assert!(!looks_like_binary(b"STORED\r\n"));
        assert!(!looks_like_binary(&[]));
        assert!(looks_like_binary(&request(0x00, "k")));
        assert!(looks_like_binary(&response(0x00, 0)));
    }

    /// An opcode that does not exist means the magic matched by coincidence.
    #[test]
    fn an_unknown_opcode_is_not_claimed_structurally() {
        let mut p = request(0x00, "k");
        p[1] = 0xEE;
        assert!(!looks_like_binary(&p));
        // It still decodes when the port says memcached, reporting the number.
        let r = dissect_memcached_bin(None, None, 1, 11211, &p);
        assert!(r.summary.contains("opcode 0xee"));
    }

    /// The extras field sits between the header and the key, so the key is not
    /// at a fixed offset.
    #[test]
    fn the_key_is_found_past_the_extras() {
        let mut p = vec![MAGIC_REQUEST, 0x01];
        p.extend_from_slice(&3u16.to_be_bytes()); // key length
        p.push(8); // eight bytes of extras
        p.push(0);
        p.extend_from_slice(&0u16.to_be_bytes());
        p.extend_from_slice(&11u32.to_be_bytes());
        p.extend_from_slice(&[0u8; 12]);
        p.extend_from_slice(&[0xAA; 8]); // the extras
        p.extend_from_slice(b"abc");
        assert_eq!(
            dissect_memcached_bin(None, None, 1, 11211, &p).summary,
            "Memcached Set — abc"
        );
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_memcached_bin(None, None, 1, 11211, &[MAGIC_REQUEST, 0x00]);
        assert_eq!(r.summary, "Memcached (2 bytes)");
    }
}
