// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// PGM packet types (RFC 3208 §8). The protocol splits neatly into data
/// flowing down and repair requests flowing back up.
fn packet_name(t: u8) -> Option<&'static str> {
    Some(match t {
        0x00 => "SPM (source path message)",
        0x01 => "POLL",
        0x02 => "POLR (poll response)",
        0x04 => "ODATA (original data)",
        0x05 => "RDATA (repair data)",
        0x08 => "NAK (negative acknowledgement)",
        0x09 => "NNAK (null NAK)",
        0x0A => "NCF (NAK confirmation)",
        0x0C => "SPMR (SPM request)",
        _ => return None,
    })
}

/// The common header (RFC 3208 §8.1): source and destination port, type,
/// options, checksum, a six-byte globally unique source id, then the length of
/// the transport data unit.
const HEADER: usize = 16;
/// The type field's low six bits carry the type; the top two are flags.
const TYPE_MASK: u8 = 0x0F;

/// Format the globally unique source identifier that names the sender.
fn gsi(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Dissect a PGM packet — Pragmatic General Multicast, which adds reliable
/// delivery on top of IP multicast, on IP protocol 113 (RFC 3208).
///
/// Multicast on its own has no retransmission: a lost packet is simply lost.
/// PGM fixes that by having receivers send NAKs for the sequence numbers they
/// missed, so a capture full of NAKs is the signature of a lossy multicast
/// path — which is exactly what makes this protocol worth decoding.
pub fn dissect_pgm(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    if payload.len() < HEADER {
        return DissectedResult {
            src_addr: src_ip,
            dst_addr: dst_ip,
            src_port: None,
            dst_port: None,
            protocol: Protocol::Pgm,
            summary: format!("PGM ({})", super::bytes(payload.len() as u64)),
        };
    }
    let src_port = u16::from_be_bytes([payload[0], payload[1]]);
    let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
    let packet_type = payload[4] & TYPE_MASK;
    let source = gsi(&payload[6..12]);

    let summary = match packet_name(packet_type) {
        Some(name) => format!("PGM {name} — source {source}"),
        None => format!("PGM type 0x{packet_type:02x} — source {source}"),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Pgm,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a PGM header of the given type.
    fn pgm(packet_type: u8) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&1234u16.to_be_bytes()); // source port
        p.extend_from_slice(&5678u16.to_be_bytes()); // destination port
        p.push(packet_type);
        p.push(0); // options
        p.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // GSI
        p.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
        p.extend_from_slice(&0u16.to_be_bytes()); // TSDU length
        p
    }

    #[test]
    fn original_data_names_the_source() {
        let r = dissect_pgm(None, None, &pgm(0x04));
        assert_eq!(r.protocol, Protocol::Pgm);
        assert_eq!(
            r.summary,
            "PGM ODATA (original data) — source aa:bb:cc:dd:ee:ff"
        );
        assert_eq!(r.src_port, Some(1234));
        assert_eq!(r.dst_port, Some(5678));
    }

    /// NAKs and repair data are the reliability machinery — a burst of them is
    /// the signature of a lossy multicast path.
    #[test]
    fn repair_traffic_is_named() {
        assert!(dissect_pgm(None, None, &pgm(0x08))
            .summary
            .contains("NAK (negative acknowledgement)"));
        assert!(dissect_pgm(None, None, &pgm(0x05))
            .summary
            .contains("RDATA (repair data)"));
        assert!(dissect_pgm(None, None, &pgm(0x0A))
            .summary
            .contains("NCF (NAK confirmation)"));
    }

    /// The top bits of the type byte are flags; not masking them would make
    /// every packet that sets one unrecognisable.
    #[test]
    fn flag_bits_are_masked_off_the_type() {
        let plain = dissect_pgm(None, None, &pgm(0x04));
        let flagged = dissect_pgm(None, None, &pgm(0x04 | 0xF0));
        assert_eq!(plain.summary, flagged.summary);
    }

    #[test]
    fn unknown_type_reports_its_number() {
        let r = dissect_pgm(None, None, &pgm(0x07));
        assert_eq!(r.summary, "PGM type 0x07 — source aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_pgm(None, None, &[0x00, 0x01, 0x02]);
        assert_eq!(r.summary, "PGM (3 bytes)");
        assert_eq!(r.src_port, None);
    }
}
