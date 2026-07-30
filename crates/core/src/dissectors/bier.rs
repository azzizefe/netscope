// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! BIER — multicast with no per-flow state anywhere (RFC 8296).
//!
//! Traditional multicast asks every router on the path to remember a tree per
//! group. That state is the thing that breaks: it has to be built before
//! traffic flows, it has to be torn down afterwards, and when it goes stale
//! nothing forwards. BIER removes it entirely. The ingress router writes a
//! **bit string** into the packet — one bit per egress router that should
//! receive a copy — and every hop simply replicates towards whichever bits are
//! still set. No router in the middle holds anything.
//!
//! That makes the bit string the whole diagnosis, and it is directly readable:
//! the number of bits set is the number of destinations this copy is still
//! headed for. A packet arriving at a hop with fewer bits set than it left the
//! ingress with has already been replicated and split — which is correct. A
//! packet whose bit string is *empty* should not exist at all, and one that
//! never loses bits along a path is being carried further than it needs to be.
//!
//! BIER has no EtherType of its own. It rides under an MPLS label stack and is
//! identified by the first nibble below that stack being 5 — where 4 and 6
//! would mean IPv4 and IPv6. That nibble is the only thing separating it from
//! an ordinary labelled IP packet.

use crate::models::Protocol;

use super::DissectedResult;

/// The nibble below an MPLS label stack that selects BIER.
pub(crate) const MPLS_NIBBLE: u8 = 5;

/// Nibble/version, BSL/entropy, OAM/DSCP/proto, BFIR-id.
const HEADER_LEN: usize = 8;

/// What BIER is carrying, from the six-bit next-protocol field.
fn next_protocol(proto: u8) -> Option<&'static str> {
    Some(match proto {
        1 => "MPLS (downstream-assigned)",
        2 => "MPLS (upstream-assigned)",
        3 => "Ethernet",
        4 => "IPv4",
        5 => "OAM",
        6 => "IPv6",
        7 => "VXLAN",
        8 => "NVGRE",
        9 => "GENEVE",
        _ => return None,
    })
}

/// How many bytes of bit string follow the header.
///
/// The length is encoded as an exponent, not a count: 1 means 64 bits and 7
/// means 4096. Zero and anything above 7 are undefined, and treating one of
/// those as a length would read the payload as part of the bit string.
fn bitstring_len(bsl: u8) -> Option<usize> {
    (1..=7).contains(&bsl).then(|| 1usize << (bsl + 2))
}

/// Whether the bytes below an MPLS stack are a BIER header.
pub(crate) fn looks_like_bier(payload: &[u8]) -> bool {
    let Some(&first) = payload.first() else {
        return false;
    };
    if first >> 4 != MPLS_NIBBLE {
        return false;
    }
    // A defined bit-string length, and enough packet to hold it.
    let Some(bsl) = payload.get(1).map(|b| b >> 4).and_then(bitstring_len) else {
        return false;
    };
    payload.len() >= HEADER_LEN + bsl
}

/// Dissect a BIER packet, from the first byte below the MPLS label stack.
pub fn dissect_bier(payload: &[u8]) -> DissectedResult {
    let base = DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Bier,
        summary: String::new(),
    };

    let Some(head) = payload.get(..HEADER_LEN) else {
        return DissectedResult {
            summary: "BIER (truncated)".into(),
            ..base
        };
    };
    let Some(bits) = bitstring_len(head[1] >> 4) else {
        return DissectedResult {
            summary: format!("BIER (undefined bit-string length {})", head[1] >> 4),
            ..base
        };
    };
    // The next protocol is six bits, not eight — the two above it are OAM.
    let proto = head[5] & 0x3F;
    let ingress = u16::from_be_bytes([head[6], head[7]]);

    let Some(bitstring) = payload.get(HEADER_LEN..HEADER_LEN + bits) else {
        return DissectedResult {
            summary: format!("BIER from ingress {ingress} (bit string truncated)"),
            ..base
        };
    };
    let destinations: u32 = bitstring.iter().map(|b| b.count_ones()).sum();
    let total = bits * 8;

    // An empty bit string means nobody is left to deliver to, so the packet
    // should have been dropped rather than forwarded.
    let fan_out = if destinations == 0 {
        "no destinations left — this copy should not have been forwarded".to_string()
    } else {
        format!("{destinations} of {total} destinations")
    };

    let carried = match next_protocol(proto) {
        Some(name) => name.to_string(),
        // A next-protocol value the standard has not assigned keeps its number.
        None => format!("protocol {proto}"),
    };

    // What is inside is the answer; BIER is the delivery mechanism. Only the
    // IP payloads can be handed on directly — the rest need a header this
    // dissector is not positioned to supply.
    let inner = match proto {
        4 => Some(super::ETHERTYPE_IPV4),
        6 => Some(super::ETHERTYPE_IPV6),
        _ => None,
    }
    .map(|et| super::dispatch_l3(et, &payload[HEADER_LEN + bits..], 0))
    .filter(|r| !matches!(r.protocol, Protocol::Unknown(_)));

    match inner {
        Some(inner) => DissectedResult {
            summary: format!("BIER {fan_out}, from ingress {ingress} · {}", inner.summary),
            protocol: Protocol::Bier,
            ..inner
        },
        None => DissectedResult {
            summary: format!("BIER {fan_out}, from ingress {ingress}, carrying {carried}"),
            ..base
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a BIER packet: `bsl` selects the bit-string size, `bits` are the
    /// byte values of the bit string itself.
    fn bier(bsl: u8, proto: u8, ingress: u16, bits: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut p = vec![
            MPLS_NIBBLE << 4, // nibble, with version 0 in the low half
            bsl << 4,         // bit-string length, entropy high bits
            0x00,
            0x00,
            0x00,  // OAM, reserved, DSCP
            proto, // next protocol, six bits
        ];
        p.extend_from_slice(&ingress.to_be_bytes());
        let mut bitstring = bits.to_vec();
        bitstring.resize(bitstring_len(bsl).unwrap_or(8), 0);
        p.extend_from_slice(&bitstring);
        p.extend_from_slice(payload);
        p
    }

    /// The reason this dissector exists: the bit string is the delivery list,
    /// and its population is how many receivers this copy is still for.
    #[test]
    fn the_number_of_destinations_is_reported() {
        // Three bits set in a 64-bit string.
        let p = bier(1, 0, 42, &[0b0000_0111], &[]);
        let r = dissect_bier(&p);
        assert_eq!(r.protocol, Protocol::Bier);
        assert!(r.summary.contains("3 of 64 destinations"), "{}", r.summary);
        assert!(r.summary.contains("from ingress 42"), "{}", r.summary);
    }

    /// A copy with nothing left to deliver to should not be on the wire.
    #[test]
    fn an_empty_bit_string_is_called_out() {
        let p = bier(1, 0, 7, &[0x00], &[]);
        let summary = dissect_bier(&p).summary;
        assert!(summary.contains("no destinations left"), "{summary}");
        assert!(!summary.contains("0 of 64"), "{summary}");
    }

    /// The length is an exponent, not a count — reading it as a count would
    /// take 8 bytes where the packet has 512.
    #[test]
    fn the_bit_string_length_is_an_exponent() {
        assert_eq!(bitstring_len(1), Some(8)); // 64 bits
        assert_eq!(bitstring_len(3), Some(32)); // 256 bits
        assert_eq!(bitstring_len(7), Some(512)); // 4096 bits
                                                 // Undefined values must not be treated as a length.
        assert_eq!(bitstring_len(0), None);
        assert_eq!(bitstring_len(8), None);
        assert_eq!(bitstring_len(15), None);

        let wide = bier(3, 0, 1, &[0xFF, 0xFF], &[]);
        assert!(
            dissect_bier(&wide)
                .summary
                .contains("16 of 256 destinations"),
            "{}",
            dissect_bier(&wide).summary
        );
    }

    /// BIER is the delivery mechanism; what it carries is the answer.
    #[test]
    fn the_carried_packet_is_dissected() {
        // A minimal IPv4/UDP packet to a multicast group.
        let mut inner = vec![
            0x45, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 10, 0, 0, 1,
            239, 1, 1, 1,
        ];
        inner.extend_from_slice(&[0x30, 0x39, 0x30, 0x39, 0x00, 0x0c, 0x00, 0x00]);
        inner.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let p = bier(1, 4, 9, &[0b0000_0011], &inner);
        let summary = dissect_bier(&p).summary;
        assert!(summary.contains("2 of 64 destinations"), "{summary}");
        assert!(summary.contains(" · "), "{summary}");
    }

    /// A payload BIER names but this layer cannot hand on still reports what
    /// is being carried.
    #[test]
    fn an_undispatchable_payload_still_names_itself() {
        let p = bier(1, 3, 5, &[0b0000_0001], &[0xFF; 8]);
        let summary = dissect_bier(&p).summary;
        assert!(summary.contains("carrying Ethernet"), "{summary}");
        // A next-protocol value outside the standard keeps its number.
        let unknown = bier(1, 33, 5, &[0b0000_0001], &[]);
        assert!(
            dissect_bier(&unknown).summary.contains("protocol 33"),
            "{}",
            dissect_bier(&unknown).summary
        );
    }

    /// The nibble is the only thing separating BIER from a labelled IP packet,
    /// so it has to be exact — and the declared length has to fit.
    #[test]
    fn recognition_rests_on_the_nibble_and_a_usable_length() {
        assert!(looks_like_bier(&bier(1, 0, 1, &[0x01], &[])));
        // Nibble 4 and 6 are IPv4 and IPv6, not BIER.
        let mut ipv4ish = bier(1, 0, 1, &[0x01], &[]);
        ipv4ish[0] = 0x45;
        assert!(!looks_like_bier(&ipv4ish));
        // Right nibble, undefined bit-string length.
        let mut bad_len = bier(1, 0, 1, &[0x01], &[]);
        bad_len[1] = 0x00;
        assert!(!looks_like_bier(&bad_len));
        // Right nibble and length, but the packet cannot hold the bit string.
        assert!(!looks_like_bier(&[0x50, 0x70, 0, 0, 0, 0, 0, 0]));
        assert!(!looks_like_bier(&[]));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(dissect_bier(&[]).summary, "BIER (truncated)");
        assert_eq!(dissect_bier(&[0x50; 7]).summary, "BIER (truncated)");
        // Header present, bit string cut off.
        let summary = dissect_bier(&[0x50, 0x70, 0, 0, 0, 0, 0, 3]).summary;
        assert!(summary.contains("bit string truncated"), "{summary}");
        // An undefined length is reported rather than guessed at.
        let summary = dissect_bier(&[0x50, 0x00, 0, 0, 0, 0, 0, 1]).summary;
        assert!(summary.contains("undefined bit-string length"), "{summary}");
    }
}
