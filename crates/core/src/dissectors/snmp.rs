// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an SNMP message (UDP 161/162). SNMP is BER/ASN.1-encoded; this does
/// a lightweight parse of the outer `SEQUENCE { version, community, … }` to
/// name the version and community string without decoding the full PDU.
pub fn dissect_snmp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let result = |summary: String| DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Snmp,
        summary,
    };

    let summary = parse_snmp(payload).unwrap_or_else(|| "SNMP message".into());
    result(summary)
}

fn parse_snmp(payload: &[u8]) -> Option<String> {
    // Outer SEQUENCE (0x30).
    let (tag, seq) = read_tlv(payload)?;
    if tag != 0x30 {
        return None;
    }
    // version INTEGER (0x02).
    let (vtag, vval) = read_tlv(seq)?;
    if vtag != 0x02 {
        return None;
    }
    let version = *vval.first()?;
    let vname = match version {
        0 => "SNMPv1",
        1 => "SNMPv2c",
        3 => return Some("SNMPv3".into()), // v3 has no plaintext community here
        _ => "SNMP",
    };

    // community OCTET STRING (0x04) follows the version.
    let rest = &seq[tlv_total_len(seq)?..];
    if let Some((ctag, cval)) = read_tlv(rest) {
        if ctag == 0x04 {
            let community = String::from_utf8_lossy(cval);
            return Some(format!("{vname} — community '{community}'"));
        }
    }
    Some(vname.into())
}

/// Read one BER TLV, returning its tag and value slice. Supports short-form
/// and long-form lengths.
fn read_tlv(data: &[u8]) -> Option<(u8, &[u8])> {
    let tag = *data.first()?;
    let (len, header) = read_len(&data[1..])?;
    let start = 1 + header;
    let value = data.get(start..start + len)?;
    Some((tag, value))
}

/// Total on-wire length of the first TLV in `data` (tag + length header + value).
fn tlv_total_len(data: &[u8]) -> Option<usize> {
    let (len, header) = read_len(data.get(1..)?)?;
    Some(1 + header + len)
}

/// Decode a BER length, returning (length, number-of-length-bytes-consumed).
fn read_len(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()?;
    if first & 0x80 == 0 {
        return Some((first as usize, 1)); // short form
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 {
        return None; // indefinite / oversized — not expected for SNMP here
    }
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | *data.get(1 + i)? as usize;
    }
    Some((len, 1 + n))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal SNMP GetRequest-ish message: SEQUENCE { version,
    /// community, ... }. We only need the version + community to be parseable.
    fn snmp_packet(version: u8, community: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x02, 0x01, version]); // INTEGER version
        body.push(0x04); // OCTET STRING
        body.push(community.len() as u8);
        body.extend_from_slice(community);
        // A trailing dummy PDU so the message looks complete.
        body.extend_from_slice(&[0xa0, 0x00]);

        let mut pkt = vec![0x30, body.len() as u8];
        pkt.extend_from_slice(&body);
        pkt
    }

    #[test]
    fn v2c_community_extracted() {
        let pkt = snmp_packet(1, b"public");
        let r = dissect_snmp(None, None, 40000, 161, &pkt);
        assert_eq!(r.protocol, Protocol::Snmp);
        assert_eq!(r.summary, "SNMPv2c — community 'public'");
    }

    #[test]
    fn v1_community_extracted() {
        let pkt = snmp_packet(0, b"private");
        let r = dissect_snmp(None, None, 161, 40000, &pkt);
        assert_eq!(r.summary, "SNMPv1 — community 'private'");
    }

    #[test]
    fn v3_reported_without_community() {
        let pkt = snmp_packet(3, b"ignored");
        let r = dissect_snmp(None, None, 161, 40000, &pkt);
        assert_eq!(r.summary, "SNMPv3");
    }

    #[test]
    fn garbage_falls_back() {
        let r = dissect_snmp(None, None, 161, 40000, &[0xff, 0xff, 0xff]);
        assert_eq!(r.protocol, Protocol::Snmp);
        assert_eq!(r.summary, "SNMP message");
    }
}
