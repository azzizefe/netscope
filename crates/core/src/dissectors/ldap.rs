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
    // Every response type opens with an LDAPResult, whose first field says
    // whether the operation worked. Without it a failed bind and a successful
    // one are the same line.
    if is_response(op_tag) {
        if let Some(code) = result_code(&payload[op_off..]) {
            if code == 0 {
                return result(format!("LDAP {name} — success"));
            }
            let detail = match directory_reason(&payload[op_off..]) {
                Some(reason) => format!("{} ({reason})", result_name_text(code)),
                None => result_name_text(code),
            };
            return result(format!("LDAP {name} — {detail}"));
        }
    }
    result(format!("LDAP {name}"))
}

/// Whether an operation tag is a response carrying an LDAPResult.
fn is_response(tag: u8) -> bool {
    matches!(tag, 0x61 | 0x65 | 0x67 | 0x69 | 0x6b | 0x6d | 0x6f | 0x78)
}

/// The `resultCode`, which is the first field of an LDAPResult.
fn result_code(op: &[u8]) -> Option<u32> {
    // Skip the operation's own tag and length to reach the first field.
    let at = 1 + ber_skip_len(op.get(1..)?)?;
    // resultCode is an ENUMERATED.
    if *op.get(at)? != 0x0A {
        return None;
    }
    let (len, size) = ber_len(op.get(at + 1..)?)?;
    let digits = op.get(at + 1 + size..at + 1 + size + len)?;
    let mut value = 0u32;
    for &b in digits {
        value = (value << 8) | b as u32;
    }
    Some(value)
}

/// Active Directory puts a sub-code in the diagnostic message, and it is the
/// part that matters: `invalidCredentials` on its own does not distinguish a
/// mistyped password from a locked-out account, which need different responses.
fn directory_reason(op: &[u8]) -> Option<&'static str> {
    // resultCode, then matchedDN, then the diagnostic message.
    let at = skip_tlv(op, skip_tlv(op, 1 + ber_skip_len(op.get(1..)?)?)?)?;
    let (len, size) = ber_len(op.get(at + 1..)?)?;
    let text = op.get(at + 1 + size..at + 1 + size + len)?;
    let text = std::str::from_utf8(text).ok()?;

    // The message reads "80090308: LdapErr: ..., data 52e, v...".
    let code = text.split("data ").nth(1)?.split(',').next()?.trim();
    Some(match code {
        "525" => "no such user",
        "52e" => "wrong password",
        "530" => "not permitted at this time",
        "531" => "not permitted at this workstation",
        "532" => "password expired",
        "533" => "account disabled",
        "701" => "account expired",
        "773" => "the user must change their password",
        "775" => "account locked out",
        _ => return None,
    })
}

/// Step over the tag-length-value starting at `at`, returning where the next
/// one begins.
fn skip_tlv(buf: &[u8], at: usize) -> Option<usize> {
    let (len, size) = ber_len(buf.get(at + 1..)?)?;
    Some(at + 1 + size + len)
}

/// What an LDAP result code means.
fn result_name(code: u32) -> Option<&'static str> {
    Some(match code {
        0 => "success",
        1 => "operations error",
        2 => "protocol error",
        3 => "time limit exceeded",
        4 => "size limit exceeded",
        7 => "authentication method not supported",
        8 => "stronger authentication required",
        10 => "referral",
        11 => "administrative limit exceeded",
        13 => "confidentiality required",
        14 => "SASL bind in progress",
        16 => "no such attribute",
        17 => "undefined attribute type",
        19 => "constraint violation",
        20 => "attribute or value already exists",
        21 => "invalid attribute syntax",
        32 => "no such object",
        34 => "invalid distinguished name",
        48 => "inappropriate authentication",
        49 => "invalid credentials",
        50 => "insufficient access rights",
        51 => "busy",
        52 => "unavailable",
        53 => "unwilling to perform",
        64 => "naming violation",
        65 => "object class violation",
        68 => "entry already exists",
        80 => "other",
        _ => return None,
    })
}

fn result_name_text(code: u32) -> String {
    match result_name(code) {
        Some(text) => text.to_string(),
        None => format!("result code {code}"),
    }
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

    /// Build a response of the given op type carrying an LDAPResult.
    fn response(op_tag: u8, code: u8, diagnostic: &str) -> Vec<u8> {
        let mut op = vec![0x0A, 0x01, code]; // resultCode
        op.extend_from_slice(&[0x04, 0x00]); // matchedDN, empty
        op.push(0x04); // diagnosticMessage
        op.push(diagnostic.len() as u8);
        op.extend_from_slice(diagnostic.as_bytes());

        let mut body = vec![0x02, 0x01, 0x01]; // messageID
        body.push(op_tag);
        body.push(op.len() as u8);
        body.extend_from_slice(&op);

        let mut out = vec![0x30, body.len() as u8];
        out.extend_from_slice(&body);
        out
    }

    /// Without the result code, a bind that failed and one that worked are the
    /// same line.
    #[test]
    fn a_bind_says_whether_it_worked() {
        assert_eq!(
            dissect_ldap(None, None, 389, 50000, &response(0x61, 0, "")).summary,
            "LDAP bindResponse — success"
        );
        assert_eq!(
            dissect_ldap(None, None, 389, 50000, &response(0x61, 49, "")).summary,
            "LDAP bindResponse — invalid credentials"
        );
    }

    /// "Invalid credentials" does not distinguish a mistyped password from a
    /// locked-out account, and the two need completely different responses.
    /// Active Directory puts the difference in the diagnostic message.
    #[test]
    fn the_directory_sub_code_separates_the_causes() {
        let locked = response(
            0x61,
            49,
            "80090308: LdapErr: DSID-0C09042A, data 775, v4563",
        );
        assert_eq!(
            dissect_ldap(None, None, 389, 50000, &locked).summary,
            "LDAP bindResponse — invalid credentials (account locked out)"
        );
        let wrong = response(
            0x61,
            49,
            "80090308: LdapErr: DSID-0C09042A, data 52e, v4563",
        );
        assert!(dissect_ldap(None, None, 389, 50000, &wrong)
            .summary
            .contains("wrong password"));
        let disabled = response(
            0x61,
            49,
            "80090308: LdapErr: DSID-0C09042A, data 533, v4563",
        );
        assert!(dissect_ldap(None, None, 389, 50000, &disabled)
            .summary
            .contains("account disabled"));
    }

    /// A directory that sends no sub-code still reports the result code, rather
    /// than the whole line being dropped.
    #[test]
    fn a_missing_sub_code_still_leaves_the_result() {
        let r = response(0x61, 49, "invalid credentials");
        assert_eq!(
            dissect_ldap(None, None, 389, 50000, &r).summary,
            "LDAP bindResponse — invalid credentials"
        );
    }

    /// Searches and modifications carry the same structure, and their failures
    /// matter just as much — an access denial looks like an empty result set.
    #[test]
    fn other_responses_report_their_result_too() {
        assert_eq!(
            dissect_ldap(None, None, 389, 50000, &response(0x65, 50, "")).summary,
            "LDAP searchResDone — insufficient access rights"
        );
        assert_eq!(
            dissect_ldap(None, None, 389, 50000, &response(0x67, 53, "")).summary,
            "LDAP modifyResponse — unwilling to perform"
        );
        assert_eq!(
            dissect_ldap(None, None, 389, 50000, &response(0x65, 4, "")).summary,
            "LDAP searchResDone — size limit exceeded"
        );
    }

    /// A request is not a response and has no result code to read.
    #[test]
    fn a_request_is_not_given_a_result() {
        let r = dissect_ldap(None, None, 50000, 389, &response(0x63, 0, ""));
        assert_eq!(r.summary, "LDAP searchRequest");
    }

    /// A code outside the table keeps its number.
    #[test]
    fn an_unknown_result_code_keeps_its_number() {
        assert_eq!(
            dissect_ldap(None, None, 389, 50000, &response(0x61, 123, "")).summary,
            "LDAP bindResponse — result code 123"
        );
    }

    /// A truncated response must fall back rather than panic.
    #[test]
    fn a_truncated_response_does_not_panic() {
        let full = response(0x61, 49, "data 775");
        for cut in 3..full.len() {
            let r = dissect_ldap(None, None, 389, 50000, &full[..cut]);
            assert!(r.summary.starts_with("LDAP"), "{}", r.summary);
        }
    }
}
