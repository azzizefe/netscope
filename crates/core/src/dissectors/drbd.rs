// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! DRBD — block devices mirrored between two machines.
//!
//! DRBD replicates a disk over the network: every write to the primary is sent
//! to the peer before (or as) it is acknowledged locally. When it breaks, a
//! filesystem stalls or a failover brings up stale data, and neither symptom
//! points at the replication link.
//!
//! The packets that explain those symptoms are the negative acknowledgements.
//! `NegAck`, `NegDReply` and `NegRSDReply` are the peer saying its own disk
//! could not serve the request — the local node is healthy and the mirror is
//! not. A run of `OutOfSync` or `RSDataRequest` is a resynchronisation working
//! through the blocks that diverged, which is what a node does after it rejoins.
//!
//! Resources are configured on whatever port the administrator picked, starting
//! near 7788 and climbing one per resource, so DRBD is identified by its magic
//! rather than by port. There are three header layouts and each has its own
//! magic, so the version in use is read rather than assumed.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Original header: u32 magic, u16 command, u16 length.
const MAGIC_80: u32 = 0x8374_0267;
/// Header for payloads exceeding 64 KiB: u16 magic, u16 command, u32 length.
const MAGIC_BIG: u16 = 0x835a;
/// DRBD 8.4 and later: u32 magic, u16 volume, u16 command, u32 length, u32 pad.
const MAGIC_100: u32 = 0x8620_ec20;

/// What a DRBD packet does. Values are fixed by the protocol version.
fn command_name(command: u16) -> Option<&'static str> {
    Some(match command {
        0x00 => "Data — a replicated write",
        0x01 => "DataReply",
        0x02 => "RSDataReply — resync data",
        0x03 => "Barrier",
        0x04 => "Bitmap — comparing which blocks differ",
        0x05 => "BecomeSyncTarget",
        0x06 => "BecomeSyncSource",
        0x07 => "UnplugRemote",
        0x08 => "DataRequest",
        0x09 => "RSDataRequest — resync in progress",
        0x0a => "SyncParam",
        0x0b => "Protocol",
        0x0c => "UUIDs — comparing generation identifiers",
        0x0d => "Sizes",
        0x0e => "State",
        0x0f => "SyncUUID",
        0x10 => "AuthChallenge",
        0x11 => "AuthResponse",
        0x12 => "StateChgRequest",
        0x13 => "Ping",
        0x14 => "PingAck",
        0x15 => "RecvAck",
        0x16 => "WriteAck",
        0x17 => "RSWriteAck",
        0x18 => "Superseded — a write conflict between two primaries",
        0x19 => "NegAck — the peer could not write it",
        0x1a => "NegDReply — the peer's disk is unusable",
        0x1b => "NegRSDReply — the peer cannot serve resync data",
        0x1c => "BarrierAck",
        0x1d => "StateChgReply",
        0x1e => "OVRequest — online verify",
        0x1f => "OVReply",
        0x20 => "OVResult",
        0x21 => "CsumRSRequest",
        0x22 => "RSIsInSync",
        0x23 => "SyncParam89",
        0x24 => "CompressedBitmap",
        0x27 => "DelayProbe",
        0x28 => "OutOfSync — blocks diverged and must be resynced",
        0x29 => "RSCancel",
        0x2a => "ConnStateChgRequest",
        0x2b => "ConnStateChgReply",
        0x2c => "RetryWrite",
        0x2d => "ProtocolUpdate",
        0x31 => "Trim",
        0x32 => "RSThinRequest",
        0x33 => "RSDeallocated",
        0x34 => "WriteSame",
        0x36 => "Zeroes",
        0xfff1 => "InitialMeta — the metadata connection opening",
        0xfff2 => "InitialData — the data connection opening",
        0xfffe => "ConnectionFeatures — the two nodes agreeing a protocol version",
        _ => return None,
    })
}

/// A parsed DRBD header: the command, and the volume if the layout carries one.
struct Header {
    command: u16,
    volume: Option<u16>,
}

/// Read whichever of the three header layouts is present.
fn parse_header(b: &[u8]) -> Option<Header> {
    let u16_at =
        |i: usize| -> Option<u16> { Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?])) };
    let u32_at = |i: usize| -> Option<u32> {
        Some(u32::from_be_bytes([
            *b.get(i)?,
            *b.get(i + 1)?,
            *b.get(i + 2)?,
            *b.get(i + 3)?,
        ]))
    };

    // The short magic cannot be confused with the leading half of either long
    // one (0x835a against 0x8374 and 0x8620), so the order here is arbitrary.
    // `the_magics_cannot_be_confused_for_each_other` holds that to be true.
    match u32_at(0) {
        Some(MAGIC_100) => {
            return Some(Header {
                volume: u16_at(4),
                command: u16_at(6)?,
            })
        }
        Some(MAGIC_80) => {
            return Some(Header {
                volume: None,
                command: u16_at(4)?,
            })
        }
        _ => {}
    }
    if u16_at(0) == Some(MAGIC_BIG) {
        return Some(Header {
            volume: None,
            command: u16_at(2)?,
        });
    }
    None
}

/// Whether a payload is DRBD, by magic.
///
/// DRBD resources are put on whatever port the administrator configured, so
/// the magic is the only reliable identification — but it is a genuine
/// constant, which makes content recognition safe here.
pub(crate) fn looks_like_drbd(payload: &[u8]) -> bool {
    parse_header(payload).is_some_and(|h| command_name(h.command).is_some())
}

/// Dissect a DRBD packet.
pub fn dissect_drbd(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Drbd,
        summary: describe(payload),
    }
}

fn describe(payload: &[u8]) -> String {
    let Some(header) = parse_header(payload) else {
        return "DRBD".to_string();
    };
    let Some(name) = command_name(header.command) else {
        return format!("DRBD (command 0x{:04x})", header.command);
    };
    // Only the newest header carries a volume, and a node with one resource
    // always reports zero, so it is only worth saying when it is not zero.
    match header.volume {
        Some(volume) if volume != 0 => format!("DRBD {name} [volume {volume}]"),
        _ => format!("DRBD {name}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an 8.4+ header, the layout in current use.
    fn v84(command: u16, volume: u16) -> Vec<u8> {
        let mut p = MAGIC_100.to_be_bytes().to_vec();
        p.extend_from_slice(&volume.to_be_bytes());
        p.extend_from_slice(&command.to_be_bytes());
        p.extend_from_slice(&0u32.to_be_bytes());
        p.extend_from_slice(&0u32.to_be_bytes());
        p
    }

    /// The reason this dissector exists: the peer, not the local node, is the
    /// one that could not complete the write.
    #[test]
    fn a_peer_side_disk_failure_is_spelled_out() {
        let r = dissect_drbd(None, None, 7788, 40000, &v84(0x19, 0));
        assert_eq!(r.protocol, Protocol::Drbd);
        assert!(
            r.summary.contains("the peer could not write it"),
            "{}",
            r.summary
        );
    }

    /// The three negative acknowledgements each say something different about
    /// where the mirror is broken.
    #[test]
    fn the_negative_acknowledgements_are_distinguished() {
        assert!(describe(&v84(0x1a, 0)).contains("peer's disk is unusable"));
        assert!(describe(&v84(0x1b, 0)).contains("cannot serve resync data"));
        assert!(describe(&v84(0x18, 0)).contains("conflict between two primaries"));
    }

    /// A resync is the normal aftermath of a node rejoining, and looks quite
    /// different from a failure.
    #[test]
    fn a_resync_is_readable_as_progress() {
        assert!(describe(&v84(0x28, 0)).contains("blocks diverged"));
        assert!(describe(&v84(0x09, 0)).contains("resync in progress"));
        assert!(describe(&v84(0x04, 0)).contains("which blocks differ"));
    }

    /// All three header layouts appear on the wire depending on version and
    /// payload size, and each carries the command in a different place.
    #[test]
    fn every_header_layout_is_read() {
        let mut v80 = MAGIC_80.to_be_bytes().to_vec();
        v80.extend_from_slice(&0x0019u16.to_be_bytes());
        v80.extend_from_slice(&0u16.to_be_bytes());
        assert!(
            describe(&v80).contains("peer could not write"),
            "{}",
            describe(&v80)
        );

        let mut big = MAGIC_BIG.to_be_bytes().to_vec();
        big.extend_from_slice(&0x0019u16.to_be_bytes());
        big.extend_from_slice(&0u32.to_be_bytes());
        assert!(
            describe(&big).contains("peer could not write"),
            "{}",
            describe(&big)
        );

        assert!(describe(&v84(0x19, 0)).contains("peer could not write"));
    }

    /// The volume tells apart which mirrored device is affected on a node
    /// replicating several, but saying "volume 0" on the common single-resource
    /// setup would be noise.
    #[test]
    fn the_volume_is_reported_only_when_it_disambiguates() {
        assert_eq!(describe(&v84(0x13, 0)), "DRBD Ping");
        assert_eq!(describe(&v84(0x13, 2)), "DRBD Ping [volume 2]");
    }

    /// The handshake is where a version mismatch between the two nodes shows.
    #[test]
    fn the_handshake_commands_are_named() {
        assert!(describe(&v84(0xfffe, 0)).contains("agreeing a protocol version"));
        assert!(describe(&v84(0xfff1, 0)).contains("metadata connection"));
    }

    /// Reading the short magic means looking at the first two bytes of a header
    /// that might be a longer layout, so the three constants have to stay
    /// mutually exclusive for the parse order not to matter.
    #[test]
    fn the_magics_cannot_be_confused_for_each_other() {
        assert_ne!((MAGIC_80 >> 16) as u16, MAGIC_BIG);
        assert_ne!((MAGIC_100 >> 16) as u16, MAGIC_BIG);
        assert_ne!(MAGIC_80, MAGIC_100);
    }

    /// The magic is a genuine constant, which is what makes recognising DRBD
    /// off its configured port safe.
    #[test]
    fn recognition_rests_on_the_magic() {
        assert!(looks_like_drbd(&v84(0x00, 0)));
        assert!(!looks_like_drbd(b"GET / HTTP/1.1\r\n\r\n"));
        assert!(!looks_like_drbd(&[]));
        // Right magic, but no command that DRBD defines.
        assert!(!looks_like_drbd(&v84(0x00ff, 0)));
        // One bit off the magic is not DRBD.
        let mut wrong = v84(0x00, 0);
        wrong[0] ^= 0x01;
        assert!(!looks_like_drbd(&wrong));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "DRBD");
        assert_eq!(describe(&MAGIC_100.to_be_bytes()), "DRBD");
        assert_eq!(describe(&[0x86, 0x20]), "DRBD");
        // Magic present, command truncated away.
        assert_eq!(
            describe(&[0x86, 0x20, 0xec, 0x20, 0x00, 0x00, 0x00]),
            "DRBD"
        );
    }
}
