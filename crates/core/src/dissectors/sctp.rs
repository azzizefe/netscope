// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::{bindings, DissectedResult};

/// Name the SCTP chunk type in the first chunk of the packet (RFC 4960).
fn chunk_name(t: u8) -> &'static str {
    match t {
        0 => "DATA",
        1 => "INIT",
        2 => "INIT ACK",
        3 => "SACK",
        4 => "HEARTBEAT",
        5 => "HEARTBEAT ACK",
        6 => "ABORT",
        7 => "SHUTDOWN",
        8 => "SHUTDOWN ACK",
        9 => "ERROR",
        10 => "COOKIE ECHO",
        11 => "COOKIE ACK",
        14 => "SHUTDOWN COMPLETE",
        _ => "chunk",
    }
}

/// The 12-byte SCTP common header (RFC 4960 §3.1).
const COMMON_HEADER: usize = 12;
/// A DATA chunk's own header: type/flags/length, TSN, stream id, stream seq,
/// then the payload protocol identifier (RFC 4960 §3.3.1).
const DATA_CHUNK_HEADER: usize = 16;
const CHUNK_TYPE_DATA: u8 = 0;

/// The user data carried by one SCTP DATA chunk, with the payload protocol
/// identifier that says which upper-layer protocol it is.
pub(crate) struct DataChunk<'a> {
    pub ppid: u32,
    pub payload: &'a [u8],
}

/// Find the first DATA chunk in an SCTP packet.
///
/// Chunks are laid out back to back after the common header, each padded to a
/// 4-byte boundary. A packet may bundle several — control chunks (SACK,
/// HEARTBEAT) commonly ride alongside data — so walk the list rather than
/// assuming the first chunk carries the payload.
pub(crate) fn first_data_chunk(payload: &[u8]) -> Option<DataChunk<'_>> {
    let mut offset = COMMON_HEADER;
    // A malformed length could otherwise spin here; every chunk is at least 4
    // bytes, so the packet length bounds the iteration count anyway.
    while offset + 4 <= payload.len() {
        let chunk_type = payload[offset];
        let len = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;
        // A chunk shorter than its own header, or longer than what is left, is
        // malformed — stop rather than reading past it.
        if len < 4 || offset + len > payload.len() {
            return None;
        }
        if chunk_type == CHUNK_TYPE_DATA && len >= DATA_CHUNK_HEADER {
            let ppid = u32::from_be_bytes([
                payload[offset + 12],
                payload[offset + 13],
                payload[offset + 14],
                payload[offset + 15],
            ]);
            return Some(DataChunk {
                ppid,
                payload: &payload[offset + DATA_CHUNK_HEADER..offset + len],
            });
        }
        // Chunks are padded out to the next 4-byte boundary.
        offset += len.div_ceil(4) * 4;
    }
    None
}

/// Dissect an SCTP packet (IP protocol 132). The 12-byte common header carries
/// source/destination ports and a verification tag; the first chunk's type
/// names what the packet is doing (RFC 4960).
///
/// When the packet carries a DATA chunk, its payload protocol identifier
/// selects the upper-layer dissector — this is how the 3GPP signalling
/// protocols (NGAP, S1AP, F1AP…) and the SIGTRAN adaptation layers are
/// recognised, since they share SCTP ports and are told apart by PPID alone.
pub fn dissect_sctp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    if payload.len() < COMMON_HEADER {
        return DissectedResult {
            src_addr: src_ip,
            dst_addr: dst_ip,
            src_port: None,
            dst_port: None,
            protocol: Protocol::Sctp,
            summary: "SCTP (truncated header)".into(),
        };
    }
    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);

    if let Some(data) = first_data_chunk(payload) {
        if let Some(dissect) = bindings::sctp_ppid(data.ppid) {
            if !data.payload.is_empty() {
                return dissect(src_ip, dst_ip, src_port, dst_port, data.payload);
            }
        }
    }

    let summary = match payload.get(COMMON_HEADER) {
        Some(&t) => format!("SCTP {} — {src_port} → {dst_port}", chunk_name(t)),
        None => format!("SCTP — {src_port} → {dst_port}"),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Sctp,
        summary,
    }
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::*;

    /// Build an SCTP packet carrying one DATA chunk with the given PPID.
    pub fn sctp_data(src_port: u16, dst_port: u16, ppid: u32, body: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&src_port.to_be_bytes());
        p.extend_from_slice(&dst_port.to_be_bytes());
        p.extend_from_slice(&[0u8; 8]); // verification tag + checksum
        p.push(CHUNK_TYPE_DATA);
        p.push(0x03); // B/E bits: a complete, unfragmented message
        p.extend_from_slice(&((DATA_CHUNK_HEADER + body.len()) as u16).to_be_bytes());
        p.extend_from_slice(&[0u8; 4]); // TSN
        p.extend_from_slice(&[0u8; 4]); // stream id + stream sequence
        p.extend_from_slice(&ppid.to_be_bytes());
        p.extend_from_slice(body);
        while p.len() % 4 != 0 {
            p.push(0); // chunk padding
        }
        p
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::sctp_data;
    use super::*;

    #[test]
    fn init_chunk() {
        let mut p = Vec::new();
        p.extend_from_slice(&1234u16.to_be_bytes()); // src port
        p.extend_from_slice(&38412u16.to_be_bytes()); // dst port
        p.extend_from_slice(&[0u8; 8]); // vtag + checksum
        p.push(1); // chunk type: INIT
        let r = dissect_sctp(None, None, &p);
        assert_eq!(r.protocol, Protocol::Sctp);
        assert_eq!(r.summary, "SCTP INIT — 1234 → 38412");
        assert_eq!(r.src_port, Some(1234));
    }

    #[test]
    fn data_chunk_exposes_ppid_and_payload() {
        let pkt = sctp_data(38412, 38412, 60, b"hello");
        let data = first_data_chunk(&pkt).expect("DATA chunk should parse");
        assert_eq!(data.ppid, 60);
        assert_eq!(data.payload, b"hello");
    }

    /// Control chunks are routinely bundled ahead of the data, so the walk has
    /// to skip them instead of giving up on the first non-DATA chunk.
    #[test]
    fn data_chunk_found_after_a_bundled_control_chunk() {
        let mut p = Vec::new();
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&2u16.to_be_bytes());
        p.extend_from_slice(&[0u8; 8]);
        // A SACK chunk first...
        p.push(3);
        p.push(0);
        p.extend_from_slice(&8u16.to_be_bytes());
        p.extend_from_slice(&[0u8; 4]);
        // ...then the DATA chunk.
        let data = sctp_data(1, 2, 18, b"payload");
        p.extend_from_slice(&data[COMMON_HEADER..]);

        let found = first_data_chunk(&p).expect("should skip the SACK");
        assert_eq!(found.ppid, 18);
        assert_eq!(found.payload, b"payload");
    }

    #[test]
    fn unknown_ppid_falls_back_to_a_plain_sctp_summary() {
        let pkt = sctp_data(1234, 5678, 0xDEAD_BEEF, b"xxxx");
        let r = dissect_sctp(None, None, &pkt);
        assert_eq!(r.protocol, Protocol::Sctp);
        assert_eq!(r.summary, "SCTP DATA — 1234 → 5678");
    }

    #[test]
    fn malformed_chunk_length_does_not_run_off_the_end() {
        let mut p = Vec::new();
        p.extend_from_slice(&[0u8; COMMON_HEADER]);
        p.push(CHUNK_TYPE_DATA);
        p.push(0);
        p.extend_from_slice(&9999u16.to_be_bytes()); // length past the buffer
        p.extend_from_slice(&[0u8; 4]);
        assert!(first_data_chunk(&p).is_none());
        // And the top-level dissector still produces a result rather than panicking.
        let _ = dissect_sctp(None, None, &p);
    }

    #[test]
    fn zero_length_chunk_terminates_the_walk() {
        let mut p = Vec::new();
        p.extend_from_slice(&[0u8; COMMON_HEADER]);
        p.push(CHUNK_TYPE_DATA);
        p.push(0);
        p.extend_from_slice(&0u16.to_be_bytes()); // a length of 0 would not advance
        p.extend_from_slice(&[0u8; 16]);
        assert!(first_data_chunk(&p).is_none());
    }
}
