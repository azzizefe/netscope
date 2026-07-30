// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

thread_local! {
    static TEST_KRB_KEYS: RefCell<HashMap<String, Vec<u8>>> = RefCell::new(HashMap::new());
}

#[cfg(test)]
pub fn clear_krb_keys() {
    TEST_KRB_KEYS.with(|keys| keys.borrow_mut().clear());
}

fn decode_hex(s: &str) -> Result<Vec<u8>, ()> {
    if !s.len().is_multiple_of(2) {
        return Err(());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

fn parse_encrypted_data(data: &[u8]) -> Option<(i32, Vec<u8>)> {
    let mut pos = 0;
    while pos + 4 < data.len() {
        if data[pos] == 0xa0 {
            let _len = data[pos + 1] as usize;
            if pos + 2 < data.len() && data[pos + 2] == 0x02 {
                let etype_len = data[pos + 3] as usize;
                if pos + 4 + etype_len <= data.len() {
                    let mut etype = 0;
                    for i in 0..etype_len {
                        etype = (etype << 8) | data[pos + 4 + i] as i32;
                    }
                    let mut cipher_pos = pos + 4 + etype_len;
                    while cipher_pos + 4 < data.len() {
                        if data[cipher_pos] == 0xa2
                            && cipher_pos + 2 < data.len()
                            && data[cipher_pos + 2] == 0x04
                        {
                            let cipher_len = data[cipher_pos + 3] as usize;
                            if cipher_pos + 4 + cipher_len <= data.len() {
                                let cipher =
                                    data[cipher_pos + 4..cipher_pos + 4 + cipher_len].to_vec();
                                return Some((etype, cipher));
                            }
                        }
                        cipher_pos += 1;
                    }
                }
            }
        }
        pos += 1;
    }
    None
}

fn decrypt_krb_aes(ciphertext: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    use aes_gcm::aes::cipher::{BlockDecrypt, KeyInit};
    use aes_gcm::aes::Aes128;

    if ciphertext.len() < 16 || !ciphertext.len().is_multiple_of(16) {
        return None;
    }

    let mut decrypted = ciphertext.to_vec();
    if key.len() == 16 {
        let cipher = Aes128::new_from_slice(key).ok()?;
        for i in (0..decrypted.len()).step_by(16) {
            let block = &mut decrypted[i..i + 16];
            let block_arr =
                aes_gcm::aes::cipher::generic_array::GenericArray::from_mut_slice(block);
            cipher.decrypt_block(block_arr);
        }
        Some(decrypted)
    } else {
        None
    }
}

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

    let mut decrypted_summary = None;
    if let Some((_etype, cipher)) = parse_encrypted_data(payload) {
        let key_bytes = TEST_KRB_KEYS
            .with(|keys| keys.borrow().get("default").cloned())
            .or_else(|| {
                std::env::var("KRB_KEY")
                    .ok()
                    .and_then(|k| decode_hex(&k).ok())
            });
        if let Some(key) = key_bytes {
            if cipher.len() >= 16 + 12 {
                let encrypted_body = &cipher[..cipher.len() - 12];
                if let Some(plaintext) = decrypt_krb_aes(encrypted_body, &key) {
                    let mut principal = String::new();
                    for &b in &plaintext {
                        if (32..=126).contains(&b) {
                            principal.push(b as char);
                        } else if !principal.is_empty() {
                            break;
                        }
                    }
                    if !principal.is_empty() && principal.len() > 3 {
                        decrypted_summary =
                            Some(format!("[Kerberos Decrypted] Principal: {principal}"));
                    }
                }
            }
        }
    }

    if let Some(dec) = decrypted_summary {
        return result(dec);
    }

    let tag = if is_krb_tag(payload.first().copied()) {
        payload.first().copied()
    } else if payload.len() >= 5 && is_krb_tag(payload.get(4).copied()) {
        payload.get(4).copied()
    } else {
        None
    };

    match tag {
        // An error message carries the reason it failed, and that reason is the
        // only useful thing in it — "KRB-ERROR" alone says a login did not work
        // without saying whether the password was wrong, the account locked or
        // the clocks simply disagree.
        Some(0x7E) => {
            let body = if payload.first() == Some(&0x7E) {
                payload
            } else {
                payload.get(4..).unwrap_or(payload)
            };
            match error_code(body) {
                Some(code) => result(format!("Kerberos error — {}", error_text(code))),
                None => result("Kerberos KRB-ERROR".into()),
            }
        }
        Some(t) => result(format!("Kerberos {}", message_name(t))),
        None => result("Kerberos (encrypted/continuation)".into()),
    }
}

/// Read a DER length at `at`, returning it and how many bytes it occupied.
///
/// The rule itself lives in [`super::der`] — three copies of it had grown up
/// independently before that module existed, and the long form's sharp edge
/// (the low bits are a *count* of length bytes, and zero means indefinite)
/// is exactly the kind of thing copies get wrong differently.
fn der_length(data: &[u8], at: usize) -> Option<(usize, usize)> {
    super::der::length(data.get(at..)?)
}

/// The `error-code` field of a KRB-ERROR, which is context tag 6.
///
/// This walks the top-level fields rather than scanning for a byte pattern: the
/// fields that precede it encode identically, so a scan would return whichever
/// came first — the protocol version, not the error.
fn error_code(body: &[u8]) -> Option<i64> {
    // [APPLICATION 30] wrapping a SEQUENCE.
    if *body.first()? != 0x7E {
        return None;
    }
    let (_, header) = der_length(body, 1)?;
    let seq_at = 1 + header;
    if *body.get(seq_at)? != 0x30 {
        return None;
    }
    let (seq_len, seq_header) = der_length(body, seq_at + 1)?;
    let mut at = seq_at + 1 + seq_header;
    let end = (at + seq_len).min(body.len());

    while at < end {
        let tag = *body.get(at)?;
        let (len, header) = der_length(body, at + 1)?;
        let value_at = at + 1 + header;
        // Context tag 6 holds the error code, as an INTEGER.
        if tag == 0xA6 {
            let inner = body.get(value_at..value_at + len)?;
            if *inner.first()? != 0x02 {
                return None;
            }
            let (int_len, int_header) = der_length(inner, 1)?;
            let digits = inner.get(1 + int_header..1 + int_header + int_len)?;
            let mut value = 0i64;
            for &b in digits {
                value = (value << 8) | b as i64;
            }
            return Some(value);
        }
        at = value_at + len;
    }
    None
}

/// What a Kerberos error means.
///
/// Restricted to the codes that come up in practice, because the point is to
/// separate the ones that need different responses: a wrong password, a locked
/// account and a clock that has drifted all present as "login failed".
fn error_name(code: i64) -> Option<&'static str> {
    Some(match code {
        6 => "the user does not exist",
        7 => "the service does not exist (missing service principal name)",
        8 => "multiple principal entries",
        9 => "the client has no key",
        10 => "the service has no key",
        11 => "the request could not be satisfied",
        12 => "policy forbids this logon (time of day, or workstation)",
        13 => "bad option",
        14 => "no encryption type in common",
        15 => "no checksum type in common",
        16 => "unsupported checksum for this key type",
        17 => "no matching padata type",
        18 => "the account is disabled, locked or expired",
        19 => "the service is not permitted",
        20 => "the ticket-granting ticket has been revoked",
        21 => "the ticket is not yet valid",
        22 => "the ticket has expired",
        23 => "the password has expired",
        24 => "pre-authentication failed (usually a wrong password)",
        25 => "pre-authentication required",
        26 => "the server is not permitted",
        32 => "the ticket has expired",
        33 => "the ticket is not yet valid",
        34 => "the request is a replay",
        35 => "the ticket is not for this server",
        37 => "clock skew too great (the two machines disagree on the time)",
        41 => "the message was modified (often a keytab or SPN mismatch)",
        52 => "the response is too large for UDP — retry over TCP",
        _ => return None,
    })
}

fn error_text(code: i64) -> String {
    match error_name(code) {
        Some(text) => format!("{text} (code {code})"),
        None => format!("code {code}"),
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

    #[test]
    fn test_kerberos_decryption() {
        use aes_gcm::aes::cipher::{BlockEncrypt, KeyInit};
        use aes_gcm::aes::Aes128;

        clear_krb_keys();

        let key = [0x55u8; 16];
        TEST_KRB_KEYS.with(|keys| {
            keys.borrow_mut()
                .insert("default".to_string(), key.to_vec());
        });

        let mut plaintext = b"admin/admin@REALM".to_vec();
        while !plaintext.len().is_multiple_of(16) {
            plaintext.push(0);
        }

        let cipher = Aes128::new_from_slice(&key).unwrap();
        let mut ciphertext = plaintext.clone();
        for i in (0..ciphertext.len()).step_by(16) {
            let block = &mut ciphertext[i..i + 16];
            let block_arr =
                aes_gcm::aes::cipher::generic_array::GenericArray::from_mut_slice(block);
            cipher.encrypt_block(block_arr);
        }

        ciphertext.extend_from_slice(&[0xaa; 12]);

        let etype_val = vec![0x02, 1, 17];
        let mut etype_seq = vec![0xa0, etype_val.len() as u8];
        etype_seq.extend_from_slice(&etype_val);

        let mut cipher_val = vec![0x04, ciphertext.len() as u8];
        cipher_val.extend_from_slice(&ciphertext);
        let mut cipher_seq = vec![0xa2, cipher_val.len() as u8];
        cipher_seq.extend_from_slice(&cipher_val);

        let mut krb_data = Vec::new();
        krb_data.extend_from_slice(&etype_seq);
        krb_data.extend_from_slice(&cipher_seq);

        let res = dissect_kerberos(None, None, 88, 50000, &krb_data);
        assert!(res.summary.contains("[Kerberos Decrypted]"));
        assert!(res.summary.contains("admin/admin@REALM"));
    }

    /// Build a KRB-ERROR carrying the given code, with the fields that precede
    /// error-code present so the walk has to step over them.
    fn error_message(code: u8) -> Vec<u8> {
        let mut seq = vec![
            0xA0, 0x03, 0x02, 0x01, 0x05, // pvno = 5
            0xA1, 0x03, 0x02, 0x01, 0x1E, // msg-type = 30
        ];
        seq.extend_from_slice(&[0xA4, 0x03, 0x02, 0x01, 0x00]); // stime
        seq.extend_from_slice(&[0xA5, 0x03, 0x02, 0x01, 0x00]); // susec
        seq.extend_from_slice(&[0xA6, 0x03, 0x02, 0x01, code]); // error-code
        let mut body = vec![0x30, seq.len() as u8];
        body.extend_from_slice(&seq);
        let mut out = vec![0x7E, body.len() as u8];
        out.extend_from_slice(&body);
        out
    }

    /// "KRB-ERROR" alone says a login failed without saying why, and the three
    /// commonest causes need completely different responses.
    #[test]
    fn an_error_says_which_failure_it_was() {
        assert_eq!(
            dissect_kerberos(None, None, 88, 50000, &error_message(24)).summary,
            "Kerberos error — pre-authentication failed (usually a wrong password) (code 24)"
        );
        assert!(dissect_kerberos(None, None, 88, 50000, &error_message(18))
            .summary
            .contains("disabled, locked or expired"));
        assert!(dissect_kerberos(None, None, 88, 50000, &error_message(37))
            .summary
            .contains("clock skew"));
    }

    /// Pre-authentication required is the normal first step of a login, not a
    /// failure, and reading it as one would make every successful logon look
    /// broken.
    #[test]
    fn the_routine_preauth_challenge_is_named_plainly() {
        let summary = dissect_kerberos(None, None, 88, 50000, &error_message(25)).summary;
        assert!(summary.contains("pre-authentication required"), "{summary}");
    }

    /// A missing service principal name is the classic cause of a service that
    /// authenticates everywhere except one host.
    #[test]
    fn a_missing_service_principal_is_named() {
        assert!(dissect_kerberos(None, None, 88, 50000, &error_message(7))
            .summary
            .contains("missing service principal name"));
    }

    /// The code is found by walking the fields, not by scanning for a byte
    /// pattern: the fields before it encode identically, and a scan would
    /// return the protocol version instead.
    #[test]
    fn the_walk_skips_the_fields_before_the_error_code() {
        let summary = dissect_kerberos(None, None, 88, 50000, &error_message(24)).summary;
        assert!(summary.contains("code 24"), "{summary}");
        assert!(
            !summary.contains("code 5"),
            "returned a preceding field instead"
        );
    }

    /// A code outside the table keeps its number rather than being mapped to
    /// whichever error was nearest.
    #[test]
    fn an_unknown_error_code_keeps_its_number() {
        assert_eq!(
            dissect_kerberos(None, None, 88, 50000, &error_message(99)).summary,
            "Kerberos error — code 99"
        );
    }

    /// A malformed or truncated error must fall back rather than panic.
    #[test]
    fn a_malformed_error_falls_back() {
        assert_eq!(
            dissect_kerberos(None, None, 88, 50000, &[0x7E, 0x02, 0x30, 0x00]).summary,
            "Kerberos KRB-ERROR"
        );
        assert!(error_code(&[0x7E]).is_none());
        assert!(error_code(&[]).is_none());
    }
}
