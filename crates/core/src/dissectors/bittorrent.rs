// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! BitTorrent's peer wire protocol (BEP 3).
//!
//! Two fields make a capture readable. The handshake carries an info hash,
//! which identifies *which* torrent is being shared — the same hash appears in
//! every peer's handshake for that torrent, so it is what groups a swarm
//! together. After that, the message type says whether a peer is actually
//! transferring or only negotiating: a run of `have` and `interested` with no
//! `piece` is a peer that wants data and is not getting any.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// The fixed peer-handshake preamble: a length byte 19 followed by the string
/// "BitTorrent protocol" (BEP 3).
const HANDSHAKE: &[u8] = b"BitTorrent protocol";
/// Preamble, eight reserved bytes, then the twenty-byte info hash.
const INFO_HASH_OFFSET: usize = 20 + 8;
const INFO_HASH_LEN: usize = 20;

/// Peer message types (BEP 3 §Peer wire protocol, extended by BEP 5 and 6).
fn message_name(id: u8) -> Option<&'static str> {
    Some(match id {
        0 => "choke (stopping uploads)",
        1 => "unchoke (willing to upload)",
        2 => "interested",
        3 => "not interested",
        4 => "have",
        5 => "bitfield (what it holds)",
        6 => "request",
        7 => "piece (data)",
        8 => "cancel",
        9 => "port (DHT)",
        13 => "suggest piece",
        14 => "have all",
        15 => "have none",
        16 => "reject request",
        17 => "allowed fast",
        20 => "extended",
        _ => return None,
    })
}

/// Dissect a BitTorrent peer-wire message (TCP, commonly 6881-6889).
pub fn dissect_bittorrent(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(HANDSHAKE) {
        // The info hash is the torrent's identity: every peer sharing the same
        // content sends the same hash, so it is what ties a swarm together.
        match payload.get(INFO_HASH_OFFSET..INFO_HASH_OFFSET + INFO_HASH_LEN) {
            Some(hash) => {
                let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
                format!("BitTorrent handshake — torrent {}", &hex[..16])
            }
            None => "BitTorrent handshake".to_string(),
        }
    } else {
        // A peer message is a four-byte length then a type. A length of zero is
        // a keepalive and carries no type at all.
        match peer_message(payload) {
            Some(None) => "BitTorrent keepalive".to_string(),
            Some(Some((id, len))) => match message_name(id) {
                Some(name) => format!("BitTorrent {name}"),
                None => format!("BitTorrent message type {id} ({})", super::bytes(len)),
            },
            None => format!(
                "BitTorrent peer message ({})",
                super::bytes(payload.len() as u64)
            ),
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::BitTorrent,
        summary,
    }
}

/// Read a peer message's type and length.
///
/// Returns `Some(None)` for a keepalive, which is a length of zero and no type
/// byte — distinct from a message that could not be parsed at all.
fn peer_message(payload: &[u8]) -> Option<Option<(u8, u64)>> {
    let len = u32::from_be_bytes([
        *payload.first()?,
        *payload.get(1)?,
        *payload.get(2)?,
        *payload.get(3)?,
    ]);
    if len == 0 {
        return Some(None);
    }
    // A peer message is never anywhere near this large; a bigger value means
    // this is not a message boundary.
    if len > 1 << 20 {
        return None;
    }
    Some(Some((*payload.get(4)?, u64::from(len))))
}

/// Structural check for the BitTorrent handshake, so it can be recognised on
/// the dynamic ports peers actually use, not just the well-known range.
pub fn looks_like_bittorrent(payload: &[u8]) -> bool {
    payload.starts_with(HANDSHAKE)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a peer message of the given type.
    fn peer(id: u8, body: &[u8]) -> Vec<u8> {
        let mut p = ((body.len() + 1) as u32).to_be_bytes().to_vec();
        p.push(id);
        p.extend_from_slice(body);
        p
    }

    /// The info hash identifies the torrent, and every peer sharing the same
    /// content sends the same one — so it is what groups a swarm.
    #[test]
    fn the_handshake_names_the_torrent() {
        let mut p = HANDSHAKE.to_vec();
        p.extend_from_slice(&[0u8; 8]); // reserved
        p.extend_from_slice(&[0xAB; INFO_HASH_LEN]); // info hash
        p.extend_from_slice(&[0xCD; 20]); // peer id
        let r = dissect_bittorrent(None, None, 6881, 6881, &p);
        assert_eq!(r.protocol, Protocol::BitTorrent);
        assert_eq!(r.summary, "BitTorrent handshake — torrent abababababababab");
    }

    /// Whether a peer is transferring or only negotiating is the question a
    /// capture is read to answer.
    #[test]
    fn transfer_and_negotiation_are_distinguished() {
        assert_eq!(
            dissect_bittorrent(None, None, 1, 6881, &peer(7, &[0u8; 32])).summary,
            "BitTorrent piece (data)"
        );
        assert_eq!(
            dissect_bittorrent(None, None, 1, 6881, &peer(6, &[0u8; 12])).summary,
            "BitTorrent request"
        );
        assert_eq!(
            dissect_bittorrent(None, None, 1, 6881, &peer(2, &[])).summary,
            "BitTorrent interested"
        );
    }

    /// Choking is how a peer refuses to upload, so a swarm full of chokes
    /// explains a download that is not progressing.
    #[test]
    fn choking_is_visible() {
        assert_eq!(
            dissect_bittorrent(None, None, 1, 6881, &peer(0, &[])).summary,
            "BitTorrent choke (stopping uploads)"
        );
        assert_eq!(
            dissect_bittorrent(None, None, 1, 6881, &peer(1, &[])).summary,
            "BitTorrent unchoke (willing to upload)"
        );
    }

    /// A keepalive is a length of zero with no type byte, which is different
    /// from a message that failed to parse.
    #[test]
    fn a_keepalive_is_not_a_parse_failure() {
        let r = dissect_bittorrent(None, None, 1, 6881, &0u32.to_be_bytes());
        assert_eq!(r.summary, "BitTorrent keepalive");
    }

    /// An implausible length means this is not a message boundary, so the
    /// fallback reports the size rather than inventing a type.
    #[test]
    fn an_implausible_length_falls_back() {
        let r = dissect_bittorrent(None, None, 1, 6881, &[0xFF, 0xFF, 0xFF, 0xFF, 0x07]);
        assert_eq!(r.summary, "BitTorrent peer message (5 bytes)");
    }

    /// Extensions add message types over time, so an unknown one reports its
    /// number rather than being dropped.
    #[test]
    fn an_unknown_message_type_reports_its_number() {
        let r = dissect_bittorrent(None, None, 1, 6881, &peer(99, &[0u8; 4]));
        assert_eq!(r.summary, "BitTorrent message type 99 (5 bytes)");
    }

    #[test]
    fn handshake() {
        let mut p = HANDSHAKE.to_vec();
        p.extend_from_slice(&[0u8; 8]); // reserved
        let r = dissect_bittorrent(None, None, 6881, 40000, &p);
        assert_eq!(r.protocol, Protocol::BitTorrent);
        assert_eq!(r.summary, "BitTorrent handshake");
        assert!(looks_like_bittorrent(&p));
    }
}
