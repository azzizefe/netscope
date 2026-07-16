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
        while plaintext.len() % 16 != 0 {
            plaintext.push(0);
        }

        let cipher = Aes128::new_from_slice(&key).unwrap();
        let mut ciphertext = plaintext.clone();
        for i in (0..ciphertext.len()).step_by(16) {
            let block = &mut ciphertext[i..i + 16];
            let mut block_arr =
                aes_gcm::aes::cipher::generic_array::GenericArray::from_mut_slice(block);
            cipher.encrypt_block(&mut block_arr);
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
}
