// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Packet id, destination address, source address, flags, then the message
/// authentication code — the payload after that is encrypted.
const HEADER: usize = 27;
const OFFSET_DESTINATION: usize = 8;
const OFFSET_SOURCE: usize = 13;
const OFFSET_FLAGS: usize = 18;
/// A ZeroTier address is five bytes, written as ten hex digits.
const ADDRESS_LEN: usize = 5;

/// The cipher suite occupies three bits of the flags byte.
fn cipher_name(cipher: u8) -> &'static str {
    match cipher {
        0 => "unencrypted (authenticated only)",
        1 => "Salsa20/12 + Poly1305",
        2 => "no cipher, no authentication",
        3 => "AES-GMAC-SIV",
        _ => "unknown cipher",
    }
}

/// Format a ZeroTier node address, which is how nodes are named on the network
/// — an identifier of its own, unrelated to any IP address.
fn address(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Whether a payload is a ZeroTier packet.
///
/// The check is deliberately weak on its own — there is no magic number — so
/// this is only consulted for traffic already on ZeroTier's port.
fn plausible(payload: &[u8]) -> bool {
    payload.len() >= HEADER
}

/// Dissect a ZeroTier packet (UDP 9993).
///
/// ZeroTier builds a virtual Ethernet network across the internet, so machines
/// in different places behave as though they share a switch. The payload is
/// encrypted, but the header is not: it names the two nodes by their ZeroTier
/// addresses, says which cipher is in use and how many relays the packet has
/// crossed. That is enough to see who is talking to whom and whether traffic is
/// going peer-to-peer or being relayed, which is the usual question.
pub fn dissect_zerotier(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if !plausible(payload) {
        format!("ZeroTier ({})", super::bytes(payload.len() as u64))
    } else {
        let destination = address(&payload[OFFSET_DESTINATION..OFFSET_DESTINATION + ADDRESS_LEN]);
        let source = address(&payload[OFFSET_SOURCE..OFFSET_SOURCE + ADDRESS_LEN]);
        let flags = payload[OFFSET_FLAGS];
        let hops = flags & 0x07;
        let cipher = (flags >> 3) & 0x07;

        // Hops above zero mean the packet was relayed rather than going
        // directly, which is the difference between a fast path and a slow one.
        if hops > 0 {
            format!(
                "ZeroTier {source} → {destination} — {} hops, {}",
                hops,
                cipher_name(cipher)
            )
        } else {
            format!(
                "ZeroTier {source} → {destination} — direct, {}",
                cipher_name(cipher)
            )
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::ZeroTier,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a ZeroTier packet header.
    fn zerotier(source: [u8; 5], destination: [u8; 5], hops: u8, cipher: u8) -> Vec<u8> {
        let mut p = vec![0u8; HEADER];
        p[OFFSET_DESTINATION..OFFSET_DESTINATION + ADDRESS_LEN].copy_from_slice(&destination);
        p[OFFSET_SOURCE..OFFSET_SOURCE + ADDRESS_LEN].copy_from_slice(&source);
        p[OFFSET_FLAGS] = (cipher << 3) | hops;
        p
    }

    #[test]
    fn a_direct_packet_names_both_nodes() {
        let p = zerotier(
            [0xDE, 0xAD, 0xBE, 0xEF, 0x01],
            [0xCA, 0xFE, 0xBA, 0xBE, 0x02],
            0,
            1,
        );
        let r = dissect_zerotier(None, None, 9993, 9993, &p);
        assert_eq!(r.protocol, Protocol::ZeroTier);
        assert_eq!(
            r.summary,
            "ZeroTier deadbeef01 → cafebabe02 — direct, Salsa20/12 + Poly1305"
        );
    }

    /// Whether a packet went straight there or was relayed is the usual
    /// question when a ZeroTier link feels slow.
    #[test]
    fn relayed_packets_report_their_hop_count() {
        let p = zerotier([1, 2, 3, 4, 5], [6, 7, 8, 9, 10], 2, 1);
        let r = dissect_zerotier(None, None, 9993, 9993, &p);
        assert!(r.summary.contains("2 hops"), "got {}", r.summary);
    }

    /// The hop count and cipher share one byte; not masking them apart would
    /// report a nonsensical hop count for every encrypted packet.
    #[test]
    fn hops_and_cipher_are_separated() {
        let direct_aes = zerotier([1; 5], [2; 5], 0, 3);
        let r = dissect_zerotier(None, None, 1, 9993, &direct_aes);
        assert!(r.summary.contains("direct"), "got {}", r.summary);
        assert!(r.summary.contains("AES-GMAC-SIV"), "got {}", r.summary);
    }

    /// An unencrypted packet is worth reading differently from an encrypted
    /// one, since ZeroTier can be configured either way.
    #[test]
    fn the_cipher_in_use_is_named() {
        let r = dissect_zerotier(None, None, 1, 9993, &zerotier([1; 5], [2; 5], 0, 0));
        assert!(r.summary.contains("unencrypted (authenticated only)"));
        let r = dissect_zerotier(None, None, 1, 9993, &zerotier([1; 5], [2; 5], 0, 2));
        assert!(r.summary.contains("no cipher, no authentication"));
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_zerotier(None, None, 1, 9993, &[0u8; 10]);
        assert_eq!(r.summary, "ZeroTier (10 bytes)");
    }
}
