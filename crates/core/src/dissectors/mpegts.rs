// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! MPEG-TS — the container broadcast television travels in (ISO/IEC 13818-1).
//!
//! Every packet is exactly 188 bytes and begins with the sync byte 0x47, which
//! makes it one of the easiest formats to recognise on the wire and is why this
//! dissector identifies it structurally rather than by port: IPTV and broadcast
//! contribution feeds use whatever multicast port the operator picked.
//!
//! A UDP datagram normally carries seven of these packets, which is how the
//! familiar 1316-byte payload size arises.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Every transport packet is this long, and starts with the sync byte.
const PACKET: usize = 188;
const SYNC: u8 = 0x47;

/// Well-known packet identifiers (ISO/IEC 13818-1 table 2-3). Most PIDs are
/// assigned per stream, but these fixed ones carry the tables that say what the
/// stream contains.
fn well_known_pid(pid: u16) -> Option<&'static str> {
    Some(match pid {
        0x0000 => "PAT (program association)",
        0x0001 => "CAT (conditional access)",
        0x0002 => "TSDT",
        0x0010 => "NIT (network information)",
        0x0011 => "SDT/BAT (service description)",
        0x0012 => "EIT (event information)",
        0x0013 => "RST (running status)",
        0x0014 => "TDT/TOT (time and date)",
        0x1FFF => "null padding",
        _ => return None,
    })
}

/// Whether a payload is a run of MPEG transport packets.
///
/// Checking a single sync byte would match far too much, so this requires the
/// payload to be a whole number of 188-byte packets and every one of them to
/// start with the sync byte. That is a strong enough signal to claim traffic on
/// an arbitrary port.
pub(crate) fn looks_like_mpegts(payload: &[u8]) -> bool {
    if payload.is_empty() || !payload.len().is_multiple_of(PACKET) {
        return false;
    }
    payload.chunks(PACKET).all(|p| p[0] == SYNC)
}

/// Dissect an MPEG-TS datagram.
pub fn dissect_mpegts(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let packets = payload.len() / PACKET;
    let summary = if packets == 0 {
        format!("MPEG-TS ({})", super::bytes(payload.len() as u64))
    } else {
        // The PID sits in the 13 bits after the three flag bits of byte 1.
        let pid = u16::from_be_bytes([payload[1] & 0x1F, payload[2]]);
        // The transport error indicator is the top bit of byte 1: the sender is
        // telling us this packet arrived corrupted, which is worth surfacing.
        let errored = payload[1] & 0x80 != 0;
        let label = match well_known_pid(pid) {
            Some(name) => format!("PID 0x{pid:04x} {name}"),
            None => format!("PID 0x{pid:04x}"),
        };
        let plural = if packets == 1 { "packet" } else { "packets" };
        if errored {
            format!("MPEG-TS {label} — {packets} {plural}, transport error")
        } else {
            format!("MPEG-TS {label} — {packets} {plural}")
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::MpegTs,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build `count` transport packets carrying the given PID.
    fn ts(pid: u16, count: usize, error: bool) -> Vec<u8> {
        let mut out = Vec::new();
        for _ in 0..count {
            let mut p = vec![0u8; PACKET];
            p[0] = SYNC;
            p[1] = ((pid >> 8) as u8 & 0x1F) | if error { 0x80 } else { 0 };
            p[2] = (pid & 0xFF) as u8;
            p[3] = 0x10; // payload only, continuity counter 0
            out.extend_from_slice(&p);
        }
        out
    }

    #[test]
    fn program_association_table_is_named() {
        let r = dissect_mpegts(None, None, 40000, 1234, &ts(0x0000, 7, false));
        assert_eq!(r.protocol, Protocol::MpegTs);
        assert_eq!(
            r.summary,
            "MPEG-TS PID 0x0000 PAT (program association) — 7 packets"
        );
    }

    /// The usual datagram carries seven packets; one should still read well.
    #[test]
    fn single_packet_is_singular() {
        let r = dissect_mpegts(None, None, 1, 1234, &ts(0x1FFF, 1, false));
        assert_eq!(r.summary, "MPEG-TS PID 0x1fff null padding — 1 packet");
    }

    /// The PID spans two bytes with three flag bits in front of it; including
    /// those flags would report a wildly wrong stream identifier.
    #[test]
    fn pid_is_read_past_the_flag_bits() {
        let r = dissect_mpegts(None, None, 1, 1234, &ts(0x0100, 1, false));
        assert!(r.summary.starts_with("MPEG-TS PID 0x0100"));
        // Setting the error flag must not change the PID that is reported.
        let r = dissect_mpegts(None, None, 1, 1234, &ts(0x0100, 1, true));
        assert!(r.summary.starts_with("MPEG-TS PID 0x0100"));
    }

    /// The sender flagging a corrupt packet is worth showing.
    #[test]
    fn transport_error_is_surfaced() {
        let r = dissect_mpegts(None, None, 1, 1234, &ts(0x0064, 7, true));
        assert_eq!(r.summary, "MPEG-TS PID 0x0064 — 7 packets, transport error");
    }

    /// Recognition has to be strong enough to claim an arbitrary port, so every
    /// 188-byte boundary must carry the sync byte.
    #[test]
    fn recognition_requires_every_packet_to_sync() {
        assert!(looks_like_mpegts(&ts(0x0100, 7, false)));
        assert!(looks_like_mpegts(&ts(0x0100, 1, false)));

        // One byte short of a whole packet.
        let mut short = ts(0x0100, 1, false);
        short.pop();
        assert!(!looks_like_mpegts(&short));

        // Right length, but the second packet has lost sync.
        let mut broken = ts(0x0100, 2, false);
        broken[PACKET] = 0x00;
        assert!(!looks_like_mpegts(&broken));

        assert!(!looks_like_mpegts(&[]));
        assert!(!looks_like_mpegts(&[SYNC; 4]));
    }

    #[test]
    fn short_payload_does_not_panic() {
        let r = dissect_mpegts(None, None, 1, 1234, &[SYNC, 0x00]);
        assert_eq!(r.summary, "MPEG-TS (2 bytes)");
    }
}
