// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// MSDP TLV types (RFC 3618 §12).
fn tlv_name(t: u8) -> Option<&'static str> {
    Some(match t {
        1 => "Source-Active",
        2 => "Source-Active Request",
        3 => "Source-Active Response",
        4 => "KeepAlive",
        5 => "Notification",
        _ => return None,
    })
}

/// Every TLV is a one-byte type and a two-byte length that includes those three
/// bytes (RFC 3618 §12).
const TLV_HEADER: usize = 3;

/// Dissect an MSDP message — how multicast sources are announced between
/// separate routing domains, on TCP 639 (RFC 3618).
///
/// Multicast normally stops at a domain boundary because each domain has its
/// own rendezvous point. MSDP is what lets a receiver in one provider's network
/// find a source in another's, so a Source-Active message is the moment one
/// network tells another "this source exists".
pub fn dissect_msdp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary =
        parse(payload).unwrap_or_else(|| format!("MSDP ({})", super::bytes(payload.len() as u64)));
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Msdp,
        summary,
    }
}

fn parse(payload: &[u8]) -> Option<String> {
    let tlv_type = *payload.first()?;
    let length = u16::from_be_bytes([*payload.get(1)?, *payload.get(2)?]) as usize;
    let name = tlv_name(tlv_type)?;
    // A length that cannot hold its own header means this is not MSDP.
    if length < TLV_HEADER {
        return None;
    }

    // A Source-Active message carries an entry count and the RP that is
    // announcing them — the two facts that say what is being advertised.
    if tlv_type == 1 {
        let count = *payload.get(TLV_HEADER)?;
        let rp = payload.get(TLV_HEADER + 1..TLV_HEADER + 5)?;
        return Some(format!(
            "MSDP Source-Active — {count} source{} from RP {}.{}.{}.{}",
            if count == 1 { "" } else { "s" },
            rp[0],
            rp[1],
            rp[2],
            rp[3]
        ));
    }
    Some(format!("MSDP {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a Source-Active message announcing `count` sources from an RP.
    fn source_active(count: u8, rp: [u8; 4]) -> Vec<u8> {
        let mut p = vec![1u8];
        p.extend_from_slice(&(8u16 + 12 * count as u16).to_be_bytes());
        p.push(count);
        p.extend_from_slice(&rp);
        p
    }

    #[test]
    fn source_active_names_count_and_rendezvous_point() {
        let r = dissect_msdp(None, None, 40000, 639, &source_active(3, [10, 0, 0, 1]));
        assert_eq!(r.protocol, Protocol::Msdp);
        assert_eq!(r.summary, "MSDP Source-Active — 3 sources from RP 10.0.0.1");
    }

    /// A single source should read naturally, not "1 sources".
    #[test]
    fn one_source_is_singular() {
        let r = dissect_msdp(None, None, 1, 639, &source_active(1, [192, 168, 1, 1]));
        assert_eq!(
            r.summary,
            "MSDP Source-Active — 1 source from RP 192.168.1.1"
        );
    }

    #[test]
    fn keepalive_and_notification_are_named() {
        let r = dissect_msdp(None, None, 1, 639, &[4, 0x00, 0x03]);
        assert_eq!(r.summary, "MSDP KeepAlive");
        let r = dissect_msdp(None, None, 1, 639, &[5, 0x00, 0x08, 0x00, 0x00]);
        assert_eq!(r.summary, "MSDP Notification");
    }

    #[test]
    fn unknown_tlv_type_is_not_claimed() {
        let r = dissect_msdp(None, None, 1, 639, &[9, 0x00, 0x03]);
        assert_eq!(r.summary, "MSDP (3 bytes)");
    }

    /// A length shorter than the TLV header is malformed, not MSDP.
    #[test]
    fn implausible_length_is_rejected() {
        let r = dissect_msdp(None, None, 1, 639, &[4, 0x00, 0x01]);
        assert_eq!(r.summary, "MSDP (3 bytes)");
    }

    #[test]
    fn truncated_source_active_falls_back() {
        let r = dissect_msdp(None, None, 1, 639, &[1, 0x00, 0x14, 0x02]);
        assert_eq!(r.summary, "MSDP (4 bytes)");
    }

    #[test]
    fn empty_input_does_not_panic() {
        let r = dissect_msdp(None, None, 1, 639, &[]);
        assert_eq!(r.summary, "MSDP (0 bytes)");
    }
}
