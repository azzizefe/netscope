// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Walk the BER header of an LDAPMessage and return the protocolOp tag.
/// Layout: SEQUENCE { messageID INTEGER, protocolOp [APPLICATION n] }.
fn protocol_op(p: &[u8]) -> Option<u8> {
    if *p.first()? != 0x30 {
        return None;
    }
    let mut i = 1;
    // Sequence length: short form, or long form with a leading byte count.
    let len_byte = *p.get(i)?;
    i += 1;
    if len_byte & 0x80 != 0 {
        i += (len_byte & 0x7f) as usize;
    }
    // messageID
    if *p.get(i)? != 0x02 {
        return None;
    }
    i += 1;
    let id_len = *p.get(i)? as usize;
    i += 1 + id_len;
    p.get(i).copied()
}

/// Dissect a CLDAP message (UDP 389) — connectionless LDAP, used by Windows
/// clients to locate domain controllers. Its large replies to small queries
/// also make it a favourite DDoS amplification vector.
pub fn dissect_cldap(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match protocol_op(payload) {
        Some(op) => {
            let name = match op {
                0x60 => "bindRequest",
                0x61 => "bindResponse",
                0x63 => "searchRequest",
                0x64 => "searchResEntry",
                0x65 => "searchResDone",
                0x77 => "extendedRequest",
                0x78 => "extendedResponse",
                _ => "message",
            };
            format!("CLDAP {name}")
        }
        None => format!("CLDAP ({} bytes)", payload.len()),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Cldap,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_request() {
        // SEQUENCE, len, INTEGER messageID=1, then APPLICATION 3 (searchRequest).
        let p = [0x30, 0x0c, 0x02, 0x01, 0x01, 0x63, 0x07];
        let r = dissect_cldap(None, None, 40000, 389, &p);
        assert_eq!(r.protocol, Protocol::Cldap);
        assert_eq!(r.summary, "CLDAP searchRequest");
    }
}
