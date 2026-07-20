// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! RX — the RPC transport underneath AFS (UDP 7000–7009).
//!
//! AFS predates and is unrelated to NFS, and it is still what several
//! universities and research sites run their home directories on. Every AFS
//! service is one of ten UDP ports, so the port says which server is being
//! talked to; the header says whether data is moving or the transfer has stalled
//! into acknowledgements.
//!
//! An `ABORT` is the one to look for: an RPC has failed outright, and its code
//! travels in the first four bytes of the body.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Epoch, connection id, call number, sequence and serial (four bytes each),
/// then type, flags, user status and security index, a spare, and the service
/// id — twenty-eight bytes.
const HEADER: usize = 28;
const OFFSET_TYPE: usize = 20;
const OFFSET_FLAGS: usize = 21;

/// The packet was sent by the side that opened the connection.
const FLAG_CLIENT_INITIATED: u8 = 0x01;

/// Packet types (`rx.h`).
fn packet_name(kind: u8) -> Option<&'static str> {
    Some(match kind {
        1 => "data",
        2 => "ack",
        3 => "busy",
        4 => "abort",
        5 => "ack-all",
        6 => "challenge",
        7 => "response",
        8 => "debug",
        9 => "parameters",
        13 => "version",
        _ => return None,
    })
}

/// Which AFS server a port belongs to.
///
/// The port is the reliable way to name the service: the header carries a
/// service id too, but its meaning is assigned per-server rather than globally,
/// so the port is what can be stated without guessing.
fn service_for_port(port: u16) -> Option<&'static str> {
    Some(match port {
        7000 => "fileserver",
        7001 => "cache manager callback",
        7002 => "protection server",
        7003 => "volume location server",
        7004 => "authentication server",
        7005 => "volume server",
        7006 => "error interpreter",
        7007 => "BOS server",
        7008 => "update server",
        7009 => "remote executor",
        _ => return None,
    })
}

/// The abort code, which says why an RPC failed. The codes come from whichever
/// service produced them rather than one shared table, so the number is
/// reported as it stands.
fn abort_code(payload: &[u8]) -> Option<i32> {
    let body = payload.get(HEADER..HEADER + 4)?;
    Some(i32::from_be_bytes([body[0], body[1], body[2], body[3]]))
}

/// Dissect an RX packet.
pub fn dissect_rx(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < HEADER {
        format!("RX/AFS ({})", super::bytes(payload.len() as u64))
    } else {
        let kind = payload[OFFSET_TYPE];
        let name = match packet_name(kind) {
            Some(n) => n.to_string(),
            None => format!("type {kind}"),
        };
        // The client-initiated flag says which end sent this, which is what
        // decides whether the well-known port is the source or the destination.
        let service = if payload[OFFSET_FLAGS] & FLAG_CLIENT_INITIATED != 0 {
            service_for_port(dst_port)
        } else {
            service_for_port(src_port)
        }
        .or_else(|| service_for_port(dst_port))
        .or_else(|| service_for_port(src_port));

        let detail = match (kind, abort_code(payload)) {
            (4, Some(code)) => format!("abort — code {code}"),
            _ => name,
        };
        match service {
            Some(s) => format!("RX/AFS {detail} ({s})"),
            None => format!("RX/AFS {detail}"),
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Rx,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an RX packet of the given type.
    fn packet(kind: u8, flags: u8, body: &[u8]) -> Vec<u8> {
        let mut p = Vec::with_capacity(HEADER + body.len());
        p.extend_from_slice(&1u32.to_be_bytes()); // epoch
        p.extend_from_slice(&2u32.to_be_bytes()); // connection id
        p.extend_from_slice(&3u32.to_be_bytes()); // call number
        p.extend_from_slice(&4u32.to_be_bytes()); // sequence
        p.extend_from_slice(&5u32.to_be_bytes()); // serial
        p.push(kind);
        p.push(flags);
        p.push(0); // user status
        p.push(0); // security index
        p.extend_from_slice(&0u16.to_be_bytes()); // spare
        p.extend_from_slice(&1u16.to_be_bytes()); // service id
        p.extend_from_slice(body);
        p
    }

    /// The port names the server, which is what a reader needs to know before
    /// anything else: a fileserver problem and a volume location problem look
    /// identical otherwise.
    #[test]
    fn the_port_names_the_server() {
        let r = dissect_rx(
            None,
            None,
            40000,
            7000,
            &packet(1, FLAG_CLIENT_INITIATED, &[]),
        );
        assert_eq!(r.protocol, Protocol::Rx);
        assert_eq!(r.summary, "RX/AFS data (fileserver)");
        assert_eq!(
            dissect_rx(
                None,
                None,
                40000,
                7003,
                &packet(1, FLAG_CLIENT_INITIATED, &[])
            )
            .summary,
            "RX/AFS data (volume location server)"
        );
    }

    /// A reply comes from the well-known port rather than to it, so direction
    /// has to be read from the flag rather than assumed.
    #[test]
    fn a_reply_is_attributed_to_the_same_server() {
        let r = dissect_rx(None, None, 7002, 40000, &packet(1, 0, &[]));
        assert_eq!(r.summary, "RX/AFS data (protection server)");
    }

    /// An abort is an RPC failing outright, and its code is the reason.
    #[test]
    fn an_abort_reports_its_code() {
        let r = dissect_rx(None, None, 7000, 1, &packet(4, 0, &(-102i32).to_be_bytes()));
        assert_eq!(r.summary, "RX/AFS abort — code -102 (fileserver)");
    }

    /// A transfer that has stalled shows as acknowledgements without data, so
    /// the two have to be told apart.
    #[test]
    fn acknowledgements_are_distinguished_from_data() {
        assert!(dissect_rx(None, None, 7000, 1, &packet(2, 0, &[]))
            .summary
            .starts_with("RX/AFS ack "));
        assert!(dissect_rx(None, None, 7000, 1, &packet(3, 0, &[]))
            .summary
            .starts_with("RX/AFS busy"));
    }

    /// Authentication happens over the same transport, and a challenge that is
    /// never answered explains a session that never starts.
    #[test]
    fn the_security_exchange_is_named() {
        assert!(dissect_rx(None, None, 7004, 1, &packet(6, 0, &[]))
            .summary
            .contains("challenge"));
        assert!(
            dissect_rx(None, None, 1, 7004, &packet(7, FLAG_CLIENT_INITIATED, &[]))
                .summary
                .contains("response")
        );
    }

    /// A type that does not exist is reported as a number rather than given
    /// the name of whichever type happened to be nearby in the table.
    #[test]
    fn an_unknown_type_is_reported_as_a_number() {
        let r = dissect_rx(None, None, 7000, 1, &packet(99, 0, &[]));
        assert_eq!(r.summary, "RX/AFS type 99 (fileserver)");
    }

    /// Traffic on one of these ports that is not RX at all still has to come
    /// back with something truthful rather than an invented packet type.
    #[test]
    fn a_foreign_payload_is_not_given_a_packet_name() {
        let r = dissect_rx(
            None,
            None,
            7000,
            1,
            b"GET / HTTP/1.1\r\n\r\nHost: x\r\n\r\n",
        );
        assert!(
            r.summary.starts_with("RX/AFS type "),
            "invented a packet name: {}",
            r.summary
        );
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_rx(None, None, 1, 7000, &[0u8; 8]);
        assert_eq!(r.summary, "RX/AFS (8 bytes)");
    }
}
