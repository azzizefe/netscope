// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Every segment starts with one of these two markers — the second is the
/// extended form that carries additional fields.
const MAGIC: &[u8; 4] = b"TSH ";
const MAGIC_EXTENDED: &[u8; 4] = b"TSHM";

/// Magic, length, byte order, segment type, control flags, reserved.
const HEADER: usize = 12;

/// Segment types. The low range is channel housekeeping; the 0xF0 range is the
/// API calls an application actually made.
fn segment_name(t: u8) -> Option<&'static str> {
    Some(match t {
        0x01 => "initial data",
        0x02 => "resync",
        0x03 => "reset",
        0x04 => "message",
        0x05 => "status",
        0x06 => "security",
        0x07 => "ping",
        0x08 => "user id",
        0x09 => "heartbeat",
        0x0A => "connection auth",
        0x81 => "renegotiate",
        0x82 => "socket action",
        0x83 => "async message",
        0x84 => "request messages",
        0x85 => "notification",
        0xF1 => "MQCONN (connect)",
        0xF2 => "MQDISC (disconnect)",
        0xF3 => "MQOPEN (open queue)",
        0xF4 => "MQCLOSE (close queue)",
        0xF5 => "MQGET (read a message)",
        0xF6 => "MQPUT (send a message)",
        0xF7 => "MQPUT1 (send one message)",
        0xF8 => "MQSET",
        0xF9 => "MQINQ (inquire)",
        0xFA => "MQCMIT (commit)",
        0xFB => "MQBACK (roll back)",
        0xFC => "SPI",
        0xFD => "MQSTAT",
        0xFE => "MQSUB (subscribe)",
        0xFF => "MQSUBRQ",
        _ => return None,
    })
}

/// Whether a payload is an IBM MQ channel segment.
pub(crate) fn looks_like_ibmmq(payload: &[u8]) -> bool {
    payload.len() >= HEADER && (payload.starts_with(MAGIC) || payload.starts_with(MAGIC_EXTENDED))
}

/// Dissect an IBM MQ channel segment — the message queue that a great deal of
/// banking, insurance and retail back-office traffic runs through, on TCP 1414.
///
/// MQ's promise is that a message handed to it will be delivered exactly once
/// even if the receiving system is down for a week. That makes it the backbone
/// of systems that cannot lose a transaction, and it means the API calls are
/// what matter in a capture: an MQPUT is a message being handed over, an MQGET
/// is one being collected, and a rollback is work being undone.
pub fn dissect_ibmmq(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if !looks_like_ibmmq(payload) {
        format!("IBM MQ ({})", super::bytes(payload.len() as u64))
    } else {
        let extended = payload.starts_with(MAGIC_EXTENDED);
        let length = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let segment_type = payload[9];
        let form = if extended { " (extended)" } else { "" };
        match segment_name(segment_type) {
            Some(name) => format!("IBM MQ {name}{form} — {length} bytes"),
            None => format!("IBM MQ segment 0x{segment_type:02x}{form} — {length} bytes"),
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::IbmMq,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a channel segment of the given type.
    fn mq(magic: &[u8; 4], segment_type: u8, length: u32) -> Vec<u8> {
        let mut p = magic.to_vec();
        p.extend_from_slice(&length.to_be_bytes());
        p.push(0x11); // byte order: big endian
        p.push(segment_type);
        p.push(0x00); // control flags
        p.push(0x00); // reserved
        p
    }

    #[test]
    fn message_put_is_named() {
        let r = dissect_ibmmq(None, None, 40000, 1414, &mq(MAGIC, 0xF6, 512));
        assert_eq!(r.protocol, Protocol::IbmMq);
        assert_eq!(r.summary, "IBM MQ MQPUT (send a message) — 512 bytes");
    }

    /// The API calls are what say what the application is doing.
    #[test]
    fn the_common_api_calls_are_named() {
        assert!(dissect_ibmmq(None, None, 1, 1414, &mq(MAGIC, 0xF5, 64))
            .summary
            .contains("MQGET (read a message)"));
        assert!(dissect_ibmmq(None, None, 1, 1414, &mq(MAGIC, 0xF3, 64))
            .summary
            .contains("MQOPEN (open queue)"));
        assert!(dissect_ibmmq(None, None, 1, 1414, &mq(MAGIC, 0xF1, 64))
            .summary
            .contains("MQCONN (connect)"));
    }

    /// A rollback means work is being undone, which is worth spotting in a
    /// system whose whole point is not losing transactions.
    #[test]
    fn commit_and_rollback_are_distinguished() {
        assert!(dissect_ibmmq(None, None, 1, 1414, &mq(MAGIC, 0xFA, 32))
            .summary
            .contains("MQCMIT (commit)"));
        assert!(dissect_ibmmq(None, None, 1, 1414, &mq(MAGIC, 0xFB, 32))
            .summary
            .contains("MQBACK (roll back)"));
    }

    /// Both header forms are in use, and the extended one is worth naming
    /// because it changes what follows the fixed part.
    #[test]
    fn both_magic_forms_decode() {
        let plain = dissect_ibmmq(None, None, 1, 1414, &mq(MAGIC, 0x09, 16));
        let extended = dissect_ibmmq(None, None, 1, 1414, &mq(MAGIC_EXTENDED, 0x09, 16));
        assert_eq!(plain.summary, "IBM MQ heartbeat — 16 bytes");
        assert_eq!(extended.summary, "IBM MQ heartbeat (extended) — 16 bytes");
    }

    /// The magic is what identifies the protocol; without it there is nothing
    /// distinctive to key on.
    #[test]
    fn foreign_payloads_are_not_claimed() {
        assert!(!looks_like_ibmmq(b"GET / HTTP/1.1\r\n\r\n"));
        assert!(!looks_like_ibmmq(b"TSH"));
        assert!(!looks_like_ibmmq(&[]));
        assert!(looks_like_ibmmq(&mq(MAGIC, 0xF6, 1)));
        assert!(looks_like_ibmmq(&mq(MAGIC_EXTENDED, 0xF6, 1)));
    }

    #[test]
    fn unknown_segment_type_reports_its_byte() {
        let r = dissect_ibmmq(None, None, 1, 1414, &mq(MAGIC, 0x7E, 8));
        assert_eq!(r.summary, "IBM MQ segment 0x7e — 8 bytes");
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_ibmmq(None, None, 1, 1414, b"TSH ");
        assert_eq!(r.summary, "IBM MQ (4 bytes)");
    }
}
