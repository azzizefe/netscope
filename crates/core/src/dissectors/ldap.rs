// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::{truncate, DissectedResult};

/// Dissect an LDAP message (TCP 389).
///
/// LDAP queries the directory that underpins corporate logins (Active Directory,
/// OpenLDAP). Each message is BER-encoded: an outer SEQUENCE (0x30), an INTEGER
/// message id, then a `[APPLICATION n]` protocol-op tag naming the operation.
/// A simple bindRequest carries the DN and password in clear text — a classic
/// credential-capture opportunity — so we surface the bind DN when we see one.
pub fn dissect_ldap(
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
        protocol: Protocol::Ldap,
        summary,
    };

    // Outer SEQUENCE.
    if payload.first() != Some(&0x30) {
        return result("LDAP (continuation)".into());
    }
    // Skip the SEQUENCE length, then the messageID INTEGER, to reach the op tag.
    let after_len = match ber_skip_len(&payload[1..]) {
        Some(n) => 1 + n,
        None => return result("LDAP".into()),
    };
    let Some(op_off) = skip_integer(&payload[after_len..]).map(|n| after_len + n) else {
        return result("LDAP".into());
    };
    let Some(&op_tag) = payload.get(op_off) else {
        return result("LDAP".into());
    };

    let name = op_name(op_tag);
    // bindRequest: version INTEGER then the bind DN as an OCTET STRING.
    if op_tag == 0x60 {
        if let Some(dn) = bind_dn(&payload[op_off..]) {
            let who = if dn.is_empty() {
                "anonymous".into()
            } else {
                dn
            };
            return result(format!("LDAP bindRequest — {}", truncate(&who, 60)));
        }
    }
    result(format!("LDAP {name}"))
}

fn op_name(tag: u8) -> &'static str {
    match tag {
        0x60 => "bindRequest",
        0x61 => "bindResponse",
        0x42 => "unbindRequest",
        0x63 => "searchRequest",
        0x64 => "searchResEntry",
        0x65 => "searchResDone",
        0x66 => "modifyRequest",
        0x67 => "modifyResponse",
        0x68 => "addRequest",
        0x69 => "addResponse",
        0x6a => "delRequest",
        0x6b => "delResponse",
        0x6e => "modDNRequest",
        0x73 => "searchResRef",
        0x77 => "extendedReq",
        0x78 => "extendedResp",
        _ => "message",
    }
}

/// From a bindRequest op (tag+len already at index 0): skip the tag+length and
/// the version INTEGER, then read the bind-DN OCTET STRING.
fn bind_dn(op: &[u8]) -> Option<String> {
    let inner = 1 + ber_skip_len(&op[1..])?; // past op tag + length
    let after_version = inner + skip_integer(&op[inner..])?; // past version INTEGER
    let dn_field = op.get(after_version..)?;
    if dn_field.first() != Some(&0x04) {
        return None;
    }
    let len_bytes = ber_len(&dn_field[1..])?;
    let (len, len_size) = len_bytes;
    let start = 1 + len_size;
    let end = start.checked_add(len)?;
    let bytes = dn_field.get(start..end)?;
    Some(String::from_utf8_lossy(bytes).to_string())
}

/// Skip a BER length field, returning the number of bytes it occupied.
fn ber_skip_len(buf: &[u8]) -> Option<usize> {
    let (_, size) = ber_len(buf)?;
    Some(size)
}

/// Parse a BER length: returns (length value, bytes the length field occupied).
fn ber_len(buf: &[u8]) -> Option<(usize, usize)> {
    let first = *buf.first()?;
    if first & 0x80 == 0 {
        Some((first as usize, 1))
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || buf.len() < 1 + n {
            return None;
        }
        let mut len = 0usize;
        for &b in &buf[1..1 + n] {
            len = (len << 8) | b as usize;
        }
        Some((len, 1 + n))
    }
}

/// Skip a whole INTEGER TLV (0x02), returning bytes consumed.
fn skip_integer(buf: &[u8]) -> Option<usize> {
    if buf.first() != Some(&0x02) {
        return None;
    }
    let (len, size) = ber_len(&buf[1..])?;
    Some(1 + size + len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_request_with_dn() {
        // SEQ { INTEGER msgid=1, [APP 0] bindRequest { INTEGER version=3,
        //       OCTET STRING "cn=admin" } }
        let dn = b"cn=admin,dc=example";
        let mut bind = vec![0x60];
        let mut bind_body = vec![0x02, 0x01, 0x03]; // version = 3
        bind_body.push(0x04);
        bind_body.push(dn.len() as u8);
        bind_body.extend_from_slice(dn);
        bind.push(bind_body.len() as u8);
        bind.extend_from_slice(&bind_body);

        let mut msg = vec![0x30];
        let mut body = vec![0x02, 0x01, 0x01]; // messageID = 1
        body.extend_from_slice(&bind);
        msg.push(body.len() as u8);
        msg.extend_from_slice(&body);

        let r = dissect_ldap(None, None, 50000, 389, &msg);
        assert_eq!(r.protocol, Protocol::Ldap);
        assert_eq!(r.summary, "LDAP bindRequest — cn=admin,dc=example");
    }

    #[test]
    fn search_request() {
        // SEQ { INTEGER msgid=2, [APP 3] searchRequest {...} }
        let mut msg = vec![0x30];
        let mut body = vec![0x02, 0x01, 0x02];
        body.push(0x63); // searchRequest
        body.push(0x00);
        msg.push(body.len() as u8);
        msg.extend_from_slice(&body);
        let r = dissect_ldap(None, None, 50000, 389, &msg);
        assert_eq!(r.summary, "LDAP searchRequest");
    }

    #[test]
    fn non_sequence_is_safe() {
        let r = dissect_ldap(None, None, 389, 50000, &[0x99, 0x00]);
        assert!(r.summary.contains("continuation"));
    }
}
