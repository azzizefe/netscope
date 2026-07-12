use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Kerberos message (TCP/UDP 88).
///
/// Kerberos is the authentication backbone of Active Directory. Its messages are
/// ASN.1 DER, each wrapped in an `[APPLICATION n]` tag that names the message
/// type: AS-REQ/AS-REP get you a ticket-granting ticket, TGS-REQ/TGS-REP get a
/// service ticket, AP-REQ/AP-REP present it. Over UDP the payload starts at the
/// tag; over TCP a 4-byte length prefixes it. We name the message — the AS-REQ,
/// especially, is where pre-auth attacks (AS-REP roasting) show up.
pub fn dissect_kerberos(
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
        protocol: Protocol::Kerberos,
        summary,
    };

    // UDP framing: tag at offset 0. TCP framing: 4-byte length, tag at offset 4.
    let tag = if is_krb_tag(payload.first().copied()) {
        payload.first().copied()
    } else if payload.len() >= 5 && is_krb_tag(payload.get(4).copied()) {
        payload.get(4).copied()
    } else {
        None
    };

    match tag {
        Some(t) => result(format!("Kerberos {}", message_name(t))),
        None => result("Kerberos (encrypted/continuation)".into()),
    }
}

fn is_krb_tag(b: Option<u8>) -> bool {
    matches!(
        b,
        Some(0x6a | 0x6b | 0x6c | 0x6d | 0x6e | 0x6f | 0x74 | 0x75 | 0x76 | 0x7e)
    )
}

fn message_name(tag: u8) -> &'static str {
    match tag {
        0x6a => "AS-REQ",
        0x6b => "AS-REP",
        0x6c => "TGS-REQ",
        0x6d => "TGS-REP",
        0x6e => "AP-REQ",
        0x6f => "AP-REP",
        0x74 => "KRB-SAFE",
        0x75 => "KRB-PRIV",
        0x76 => "KRB-CRED",
        0x7e => "KRB-ERROR",
        _ => "message",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_req_over_udp() {
        // APPLICATION 10 (AS-REQ) then a DER length + body we don't parse.
        let p = [0x6a, 0x81, 0x10, 0x30, 0x00];
        let r = dissect_kerberos(None, None, 50000, 88, &p);
        assert_eq!(r.protocol, Protocol::Kerberos);
        assert_eq!(r.summary, "Kerberos AS-REQ");
    }

    #[test]
    fn tgs_rep_over_tcp() {
        // 4-byte length prefix, then APPLICATION 13 (TGS-REP).
        let mut p = vec![0x00, 0x00, 0x01, 0x00];
        p.push(0x6d);
        p.extend_from_slice(&[0x81, 0x10]);
        let r = dissect_kerberos(None, None, 88, 50000, &p);
        assert_eq!(r.summary, "Kerberos TGS-REP");
    }

    #[test]
    fn krb_error() {
        let p = [0x7e, 0x30];
        let r = dissect_kerberos(None, None, 88, 50000, &p);
        assert_eq!(r.summary, "Kerberos KRB-ERROR");
    }
}
