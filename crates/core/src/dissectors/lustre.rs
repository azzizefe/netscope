// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// The magic that opens an LNet connection over TCP, little-endian on the wire.
const LNET_TCP_MAGIC: u32 = 0x0BD0_0BD0;
/// LNet's own message magic (little-endian `0xeb c0 cd 0f`).
const LNET_MSG_MAGIC: u32 = 0x0FCD_C0EB;

/// LNet message types (`lnet/include/lnet/lib-types.h`).
fn message_name(t: u32) -> Option<&'static str> {
    Some(match t {
        1 => "ACK",
        2 => "PUT (write)",
        3 => "GET (read)",
        4 => "REPLY",
        5 => "HELLO",
        _ => return None,
    })
}

/// Magic and version occupy the first eight bytes of a connection request;
/// a message header is longer but starts the same way.
const HEADER: usize = 8;

/// Whether a payload is Lustre LNet traffic.
pub(crate) fn looks_like_lustre(payload: &[u8]) -> bool {
    magic(payload)
        .map(|m| m == LNET_TCP_MAGIC || m == LNET_MSG_MAGIC)
        .unwrap_or(false)
}

fn magic(payload: &[u8]) -> Option<u32> {
    if payload.len() < HEADER {
        return None;
    }
    Some(u32::from_le_bytes([
        payload[0], payload[1], payload[2], payload[3],
    ]))
}

/// Dissect a Lustre LNet message — the network layer of the parallel filesystem
/// that most supercomputers store their data on, on TCP 988.
///
/// Lustre spreads one filesystem across hundreds of storage servers so that a
/// cluster of thousands of compute nodes can read and write at once. LNet is
/// the transport beneath it, and it is deliberately one-sided: a PUT writes
/// into a remote node's memory and a GET reads from it, without the far side
/// taking part in each transfer. That is what keeps the storage servers from
/// becoming the bottleneck.
pub fn dissect_lustre(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match magic(payload) {
        Some(LNET_TCP_MAGIC) => {
            let version = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
            format!("Lustre LNet connection request — version {version}")
        }
        Some(LNET_MSG_MAGIC) => {
            // After the magic and version comes the message type.
            match payload.get(8..12) {
                Some(t) => {
                    let msg_type = u32::from_le_bytes([t[0], t[1], t[2], t[3]]);
                    match message_name(msg_type) {
                        Some(name) => format!("Lustre LNet {name}"),
                        None => format!("Lustre LNet message type {msg_type}"),
                    }
                }
                None => "Lustre LNet message".to_string(),
            }
        }
        _ => format!("Lustre ({})", super::bytes(payload.len() as u64)),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Lustre,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an LNet message of the given type.
    fn lnet(msg_type: u32) -> Vec<u8> {
        let mut p = LNET_MSG_MAGIC.to_le_bytes().to_vec();
        p.extend_from_slice(&1u32.to_le_bytes()); // version
        p.extend_from_slice(&msg_type.to_le_bytes());
        p.extend_from_slice(&[0u8; 16]);
        p
    }

    /// Build a connection request.
    fn connect(version: u32) -> Vec<u8> {
        let mut p = LNET_TCP_MAGIC.to_le_bytes().to_vec();
        p.extend_from_slice(&version.to_le_bytes());
        p
    }

    #[test]
    fn connection_request_reports_its_version() {
        let r = dissect_lustre(None, None, 40000, 988, &connect(4));
        assert_eq!(r.protocol, Protocol::Lustre);
        assert_eq!(r.summary, "Lustre LNet connection request — version 4");
    }

    /// The one-sided transfers are the interesting part: a PUT writes into the
    /// far node's memory, a GET reads out of it.
    #[test]
    fn one_sided_transfers_are_named() {
        assert_eq!(
            dissect_lustre(None, None, 1, 988, &lnet(2)).summary,
            "Lustre LNet PUT (write)"
        );
        assert_eq!(
            dissect_lustre(None, None, 1, 988, &lnet(3)).summary,
            "Lustre LNet GET (read)"
        );
    }

    #[test]
    fn acknowledgements_and_replies_are_named() {
        assert_eq!(
            dissect_lustre(None, None, 1, 988, &lnet(1)).summary,
            "Lustre LNet ACK"
        );
        assert_eq!(
            dissect_lustre(None, None, 1, 988, &lnet(4)).summary,
            "Lustre LNet REPLY"
        );
        assert_eq!(
            dissect_lustre(None, None, 1, 988, &lnet(5)).summary,
            "Lustre LNet HELLO"
        );
    }

    /// The two magics mean different things and must not be confused: one opens
    /// a connection, the other frames a message on an open one.
    #[test]
    fn the_two_magics_are_distinguished() {
        assert!(dissect_lustre(None, None, 1, 988, &connect(4))
            .summary
            .contains("connection request"));
        assert!(!dissect_lustre(None, None, 1, 988, &lnet(2))
            .summary
            .contains("connection request"));
    }

    #[test]
    fn foreign_payloads_are_not_claimed() {
        assert!(!looks_like_lustre(b"GET / HTTP/1.1\r\n\r\n"));
        assert!(!looks_like_lustre(&[0u8; 16]));
        assert!(!looks_like_lustre(&[]));
        assert!(looks_like_lustre(&lnet(2)));
        assert!(looks_like_lustre(&connect(4)));
    }

    #[test]
    fn unknown_message_type_reports_its_number() {
        let r = dissect_lustre(None, None, 1, 988, &lnet(99));
        assert_eq!(r.summary, "Lustre LNet message type 99");
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_lustre(None, None, 1, 988, &[0xEB, 0xC0]);
        assert_eq!(r.summary, "Lustre (2 bytes)");
        // Magic present but the type field cut off.
        let mut short = LNET_MSG_MAGIC.to_le_bytes().to_vec();
        short.extend_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            dissect_lustre(None, None, 1, 988, &short).summary,
            "Lustre LNet message"
        );
    }
}
