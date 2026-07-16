// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use aes_gcm::{aead::Aead, Aes128Gcm, Aes256Gcm, KeyInit};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

#[derive(Hash, PartialEq, Eq, Clone, Debug)]
struct TlsFlowKey {
    client_ip: IpAddr,
    client_port: u16,
    server_ip: IpAddr,
    server_port: u16,
}

#[derive(Clone)]
struct TlsSessionState {
    client_random: [u8; 32],
    server_random: Option<[u8; 32]>,
    cipher_suite: Option<u16>,
    client_key: Option<Vec<u8>>,
    client_iv: Option<Vec<u8>>,
    server_key: Option<Vec<u8>>,
    server_iv: Option<Vec<u8>>,
    seq_num_client: u64,
    seq_num_server: u64,
}

thread_local! {
    static TLS_SESSIONS: RefCell<HashMap<TlsFlowKey, TlsSessionState>> = RefCell::new(HashMap::new());
}

#[cfg(test)]
pub fn clear_tls_sessions() {
    TLS_SESSIONS.with(|sessions| {
        sessions.borrow_mut().clear();
    });
}

fn get_rsa_private_key() -> Option<rsa::RsaPrivateKey> {
    let path = std::env::var("TLS_RSA_PRIVATE_KEY").ok()?;
    let content = std::fs::read_to_string(path).ok()?;
    rsa::RsaPrivateKey::from_pkcs1_pem(&content)
        .or_else(|_| rsa::RsaPrivateKey::from_pkcs8_pem(&content))
        .ok()
}

fn decrypt_rsa_pre_master(enc: &[u8], key: &rsa::RsaPrivateKey) -> Option<[u8; 48]> {
    let decrypted = key.decrypt(rsa::Pkcs1v15Encrypt, enc).ok()?;
    if decrypted.len() == 48 {
        let mut out = [0u8; 48];
        out.copy_from_slice(&decrypted);
        Some(out)
    } else {
        None
    }
}

fn prf_sha256(secret: &[u8], label: &str, seed: &[u8], length: usize) -> Vec<u8> {
    let mut label_seed = label.as_bytes().to_vec();
    label_seed.extend_from_slice(seed);

    let mut out = Vec::new();
    let mut a = label_seed.clone();
    while out.len() < length {
        a = hmac_sha256(secret, &a).to_vec();
        let mut data = a.clone();
        data.extend_from_slice(&label_seed);
        let block = hmac_sha256(secret, &data);
        out.extend_from_slice(&block);
    }
    out.truncate(length);
    out
}

fn decrypt_tls12_gcm_record(
    key: &[u8],
    salt: &[u8],
    seq_num: u64,
    record_header: &[u8; 5],
    payload: &[u8],
    cipher_suite: u16,
) -> Option<Vec<u8>> {
    if payload.len() < 24 {
        return None;
    }
    let explicit_nonce = &payload[..8];
    let ciphertext_and_tag = &payload[8..];

    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(salt);
    nonce[4..].copy_from_slice(explicit_nonce);

    let plaintext_len = (ciphertext_and_tag.len() - 16) as u16;
    let mut aad = [0u8; 13];
    aad[..8].copy_from_slice(&seq_num.to_be_bytes());
    aad[8] = record_header[0];
    aad[9..11].copy_from_slice(&record_header[1..3]);
    aad[11..13].copy_from_slice(&plaintext_len.to_be_bytes());

    if cipher_suite == 0x009c {
        let cipher = Aes128Gcm::new_from_slice(key).ok()?;
        cipher
            .decrypt(
                nonce.as_ref().into(),
                aes_gcm::aead::Payload {
                    msg: ciphertext_and_tag,
                    aad: &aad,
                },
            )
            .ok()
    } else if cipher_suite == 0x009d {
        let cipher = Aes256Gcm::new_from_slice(key).ok()?;
        cipher
            .decrypt(
                nonce.as_ref().into(),
                aes_gcm::aead::Payload {
                    msg: ciphertext_and_tag,
                    aad: &aad,
                },
            )
            .ok()
    } else {
        None
    }
}

fn get_client_key_exchange_encrypted_pre_master(payload: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0;
    while pos + 5 <= payload.len() {
        let typ = payload[pos];
        let len = u16::from_be_bytes([payload[pos + 3], payload[pos + 4]]) as usize;
        if pos + 5 + len > payload.len() {
            break;
        }
        let record_body = &payload[pos + 5..pos + 5 + len];
        if typ == 22 && record_body.len() >= 6 && record_body[0] == 16 {
            let enc_len = u16::from_be_bytes([record_body[4], record_body[5]]) as usize;
            if 6 + enc_len <= record_body.len() {
                return Some(record_body[6..6 + enc_len].to_vec());
            }
        }
        pos += 5 + len;
    }
    None
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

fn get_secrets_for_random(client_random: &[u8; 32]) -> Option<HashMap<String, Vec<u8>>> {
    let path = std::env::var("SSLKEYLOGFILE").ok()?;
    let content = std::fs::read_to_string(path).ok()?;
    let target_hex = hex_encode(client_random);
    let mut secrets = HashMap::new();
    for line in content.lines() {
        if line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() == 3 {
            let label = parts[0];
            let rand_hex = parts[1];
            let secret_hex = parts[2];
            if rand_hex.to_lowercase() == target_hex {
                if let Ok(sec) = decode_hex(secret_hex) {
                    secrets.insert(label.to_string(), sec);
                }
            }
        }
    }
    if secrets.is_empty() {
        None
    } else {
        Some(secrets)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut ipad = [0x36; 64];
    let mut opad = [0x5c; 64];
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        let h = Sha256::digest(key);
        key_block[..32].copy_from_slice(&h);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    for i in 0..64 {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }
    let mut h = Sha256::new();
    h.update(ipad);
    h.update(data);
    let inner = h.finalize();
    let mut h = Sha256::new();
    h.update(opad);
    h.update(inner);
    h.finalize().into()
}

fn hmac_sha384(key: &[u8], data: &[u8]) -> [u8; 48] {
    use sha2::{Digest, Sha384};
    let mut ipad = [0x36; 128];
    let mut opad = [0x5c; 128];
    let mut key_block = [0u8; 128];
    if key.len() > 128 {
        let h = Sha384::digest(key);
        key_block[..48].copy_from_slice(&h);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    for i in 0..128 {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }
    let mut h = Sha384::new();
    h.update(ipad);
    h.update(data);
    let inner = h.finalize();
    let mut h = Sha384::new();
    h.update(opad);
    h.update(inner);
    h.finalize().into()
}

fn hkdf_expand_sha256(prk: &[u8], info: &[u8], okm_len: usize) -> Vec<u8> {
    let mut okm = Vec::new();
    let mut t = Vec::new();
    let mut i = 1u8;
    while okm.len() < okm_len {
        let mut data = t.clone();
        data.extend_from_slice(info);
        data.push(i);
        let hash = hmac_sha256(prk, &data);
        t = hash.to_vec();
        okm.extend_from_slice(&t);
        i += 1;
    }
    okm.truncate(okm_len);
    okm
}

fn hkdf_expand_sha384(prk: &[u8], info: &[u8], okm_len: usize) -> Vec<u8> {
    let mut okm = Vec::new();
    let mut t = Vec::new();
    let mut i = 1u8;
    while okm.len() < okm_len {
        let mut data = t.clone();
        data.extend_from_slice(info);
        data.push(i);
        let hash = hmac_sha384(prk, &data);
        t = hash.to_vec();
        okm.extend_from_slice(&t);
        i += 1;
    }
    okm.truncate(okm_len);
    okm
}

fn hkdf_expand_label_sha256(secret: &[u8], label: &str, context: &[u8], length: u16) -> Vec<u8> {
    let full_label = format!("tls13 {label}");
    let mut info = Vec::new();
    info.extend_from_slice(&length.to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(full_label.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hkdf_expand_sha256(secret, &info, length as usize)
}

fn hkdf_expand_label_sha384(secret: &[u8], label: &str, context: &[u8], length: u16) -> Vec<u8> {
    let full_label = format!("tls13 {label}");
    let mut info = Vec::new();
    info.extend_from_slice(&length.to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(full_label.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hkdf_expand_sha384(secret, &info, length as usize)
}

fn decrypt_tls13_record(
    key: &[u8],
    iv: &[u8],
    seq_num: u64,
    record_header: &[u8; 5],
    ciphertext_and_tag: &[u8],
    cipher_suite: u16,
) -> Option<(u8, Vec<u8>)> {
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&iv[..12]);
    let seq_bytes = seq_num.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= seq_bytes[i];
    }

    let plaintext = if cipher_suite == 0x1301 {
        let cipher = Aes128Gcm::new_from_slice(key).ok()?;
        cipher
            .decrypt(
                nonce.as_ref().into(),
                aes_gcm::aead::Payload {
                    msg: ciphertext_and_tag,
                    aad: record_header,
                },
            )
            .ok()?
    } else if cipher_suite == 0x1302 {
        let cipher = Aes256Gcm::new_from_slice(key).ok()?;
        cipher
            .decrypt(
                nonce.as_ref().into(),
                aes_gcm::aead::Payload {
                    msg: ciphertext_and_tag,
                    aad: record_header,
                },
            )
            .ok()?
    } else {
        return None;
    };

    let mut inner_type = 0;
    let mut payload_len = 0;
    for i in (0..plaintext.len()).rev() {
        if plaintext[i] != 0 {
            inner_type = plaintext[i];
            payload_len = i;
            break;
        }
    }
    if inner_type == 0 {
        return None;
    }
    Some((inner_type, plaintext[..payload_len].to_vec()))
}

fn decrypt_tls_record_stream(
    payload: &[u8],
    key: &[u8],
    iv: &[u8],
    seq_num: &mut u64,
    cipher_suite: u16,
) -> Option<Vec<u8>> {
    let mut decrypted_stream = Vec::new();
    let mut pos = 0;
    while pos + 5 <= payload.len() {
        let typ = payload[pos];
        let len = u16::from_be_bytes([payload[pos + 3], payload[pos + 4]]) as usize;
        if pos + 5 + len > payload.len() {
            break;
        }
        let record_body = &payload[pos + 5..pos + 5 + len];
        let mut header = [0u8; 5];
        header.copy_from_slice(&payload[pos..pos + 5]);

        let is_tls13 = cipher_suite == 0x1301 || cipher_suite == 0x1302;
        if is_tls13 {
            if typ == 23 {
                // Application Data / Encrypted Handshake
                if let Some((inner_type, plaintext)) =
                    decrypt_tls13_record(key, iv, *seq_num, &header, record_body, cipher_suite)
                {
                    if inner_type == 23 {
                        decrypted_stream.extend_from_slice(&plaintext);
                    }
                    *seq_num += 1;
                } else {
                    return None;
                }
            }
        } else {
            // TLS 1.2 GCM
            if typ == 23 {
                if let Some(plaintext) =
                    decrypt_tls12_gcm_record(key, iv, *seq_num, &header, record_body, cipher_suite)
                {
                    decrypted_stream.extend_from_slice(&plaintext);
                    *seq_num += 1;
                } else {
                    return None;
                }
            }
        }
        pos += 5 + len;
    }
    if decrypted_stream.is_empty() {
        None
    } else {
        Some(decrypted_stream)
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub fn generate_ca() -> Result<(rcgen::Certificate, rcgen::KeyPair), rcgen::Error> {
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "netscope MITM CA");

    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let cert = params.self_signed(&key_pair)?;
    Ok((cert, key_pair))
}

#[cfg(not(target_arch = "wasm32"))]
pub fn sign_host_cert(
    host: &str,
    ca: &rcgen::Certificate,
    ca_key: &rcgen::KeyPair,
) -> Result<String, rcgen::Error> {
    let mut params = rcgen::CertificateParams::new(vec![host.to_string()])?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, host);

    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let cert = params.signed_by(&key_pair, ca, ca_key)?;
    Ok(cert.pem())
}

pub fn dissect_tls(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let mut client_hello = None;
    let mut server_hello = None;

    if let (Some(sip), Some(dip)) = (src_ip, dst_ip) {
        if let Some(h) = parse_client_hello(payload) {
            client_hello = Some(h.clone());
            let key = TlsFlowKey {
                client_ip: sip,
                client_port: src_port,
                server_ip: dip,
                server_port: dst_port,
            };
            TLS_SESSIONS.with(|sessions| {
                sessions.borrow_mut().insert(
                    key,
                    TlsSessionState {
                        client_random: h.random,
                        server_random: None,
                        cipher_suite: None,
                        client_key: None,
                        client_iv: None,
                        server_key: None,
                        server_iv: None,
                        seq_num_client: 0,
                        seq_num_server: 0,
                    },
                );
            });
        } else if let Some(s) = parse_server_hello(payload) {
            server_hello = Some(s.clone());
            let key = TlsFlowKey {
                client_ip: dip,
                client_port: dst_port,
                server_ip: sip,
                server_port: src_port,
            };
            TLS_SESSIONS.with(|sessions| {
                let mut sessions_map = sessions.borrow_mut();
                if let Some(state) = sessions_map.get_mut(&key) {
                    state.cipher_suite = Some(s.cipher_suite);
                    state.server_random = Some(s.random);
                    if let Some(secrets) = get_secrets_for_random(&state.client_random) {
                        if let Some(client_secret) = secrets.get("CLIENT_TRAFFIC_SECRET_0") {
                            if s.cipher_suite == 0x1301 {
                                state.client_key =
                                    Some(hkdf_expand_label_sha256(client_secret, "key", &[], 16));
                                state.client_iv =
                                    Some(hkdf_expand_label_sha256(client_secret, "iv", &[], 12));
                            } else if s.cipher_suite == 0x1302 {
                                state.client_key =
                                    Some(hkdf_expand_label_sha384(client_secret, "key", &[], 32));
                                state.client_iv =
                                    Some(hkdf_expand_label_sha384(client_secret, "iv", &[], 12));
                            }
                        }
                        if let Some(server_secret) = secrets.get("SERVER_TRAFFIC_SECRET_0") {
                            if s.cipher_suite == 0x1301 {
                                state.server_key =
                                    Some(hkdf_expand_label_sha256(server_secret, "key", &[], 16));
                                state.server_iv =
                                    Some(hkdf_expand_label_sha256(server_secret, "iv", &[], 12));
                            } else if s.cipher_suite == 0x1302 {
                                state.server_key =
                                    Some(hkdf_expand_label_sha384(server_secret, "key", &[], 32));
                                state.server_iv =
                                    Some(hkdf_expand_label_sha384(server_secret, "iv", &[], 12));
                            }
                        }
                    }
                }
            });
        } else {
            // Check for ClientKeyExchange (sent from client to server)
            if let Some(enc_pm) = get_client_key_exchange_encrypted_pre_master(payload) {
                let key = TlsFlowKey {
                    client_ip: sip,
                    client_port: src_port,
                    server_ip: dip,
                    server_port: dst_port,
                };
                if let Some(rsa_key) = get_rsa_private_key() {
                    if let Some(pm_secret) = decrypt_rsa_pre_master(&enc_pm, &rsa_key) {
                        TLS_SESSIONS.with(|sessions| {
                            let mut sessions_map = sessions.borrow_mut();
                            if let Some(state) = sessions_map.get_mut(&key) {
                                if let (Some(cs), Some(srv_rand)) =
                                    (state.cipher_suite, state.server_random)
                                {
                                    if cs == 0x009c || cs == 0x009d {
                                        let mut seed = state.client_random.to_vec();
                                        seed.extend_from_slice(&srv_rand);
                                        let master_secret =
                                            prf_sha256(&pm_secret, "master secret", &seed, 48);

                                        let mut seed2 = srv_rand.to_vec();
                                        seed2.extend_from_slice(&state.client_random);

                                        let key_len = if cs == 0x009c { 16 } else { 32 };
                                        let key_block_len = key_len * 2 + 4 * 2;
                                        let key_block = prf_sha256(
                                            &master_secret,
                                            "key expansion",
                                            &seed2,
                                            key_block_len,
                                        );

                                        let client_key = key_block[..key_len].to_vec();
                                        let server_key = key_block[key_len..key_len * 2].to_vec();
                                        let client_salt =
                                            key_block[key_len * 2..key_len * 2 + 4].to_vec();
                                        let server_salt =
                                            key_block[key_len * 2 + 4..key_len * 2 + 8].to_vec();

                                        state.client_key = Some(client_key);
                                        state.server_key = Some(server_key);
                                        state.client_iv = Some(client_salt);
                                        state.server_iv = Some(server_salt);
                                    }
                                }
                            }
                        });
                    }
                }
            }
        }
    }

    let mut decrypted_payload = Vec::new();
    let mut was_decrypted = false;

    if let (Some(sip), Some(dip)) = (src_ip, dst_ip) {
        let key_c_to_s = TlsFlowKey {
            client_ip: sip,
            client_port: src_port,
            server_ip: dip,
            server_port: dst_port,
        };
        let key_s_to_c = TlsFlowKey {
            client_ip: dip,
            client_port: dst_port,
            server_ip: sip,
            server_port: src_port,
        };

        TLS_SESSIONS.with(|sessions| {
            let mut sessions_map = sessions.borrow_mut();
            if let Some(state) = sessions_map.get_mut(&key_c_to_s) {
                if let (Some(key), Some(iv), Some(cs)) =
                    (&state.client_key, &state.client_iv, state.cipher_suite)
                {
                    if let Some(decrypted) =
                        decrypt_tls_record_stream(payload, key, iv, &mut state.seq_num_client, cs)
                    {
                        decrypted_payload = decrypted;
                        was_decrypted = true;
                    }
                }
            } else if let Some(state) = sessions_map.get_mut(&key_s_to_c) {
                if let (Some(key), Some(iv), Some(cs)) =
                    (&state.server_key, &state.server_iv, state.cipher_suite)
                {
                    if let Some(decrypted) =
                        decrypt_tls_record_stream(payload, key, iv, &mut state.seq_num_server, cs)
                    {
                        decrypted_payload = decrypted;
                        was_decrypted = true;
                    }
                }
            }
        });
    }

    if was_decrypted && !decrypted_payload.is_empty() {
        if let Some(mut h2) =
            super::http2::try_dissect(src_ip, dst_ip, src_port, dst_port, &decrypted_payload)
        {
            h2.summary = format!("[HTTPS] {}", h2.summary);
            return h2;
        }
        let mut http_res =
            super::http::dissect_http(src_ip, dst_ip, src_port, dst_port, &decrypted_payload);
        if http_res.protocol == Protocol::Http {
            http_res.summary = format!("[HTTPS] {}", http_res.summary);
            return http_res;
        }
    }

    let summary = if let Some(h) = client_hello {
        let ja3 = ja3_hash(&h);
        let ja4 = ja4(&h, 't');
        match &h.sni {
            Some(host) => format!("TLS ClientHello — {host} · JA4 {ja4} · JA3 {ja3}"),
            None => format!("TLS ClientHello (no SNI) · JA4 {ja4} · JA3 {ja3}"),
        }
    } else if let Some(s) = server_hello {
        format!("TLS ServerHello · JA3S {}", ja3s_hash(&s))
    } else {
        if payload.len() > 5 && payload[0] == 0x16 && payload[1] == 0x03 {
            "TLS Handshake".into()
        } else if payload.len() == 1 {
            "TLS — 1 byte of encrypted data".into()
        } else {
            format!("TLS — {} bytes of encrypted data", payload.len())
        }
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Tls,
        summary,
    }
}

/// The fields of a TLS ClientHello that JA3 and JA4 fingerprints are computed
/// from, plus the SNI for display.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientHello {
    /// `legacy_version` from the handshake body (e.g. 0x0303 for TLS 1.2).
    pub version: u16,
    /// Offered random bytes (32 bytes).
    pub random: [u8; 32],
    /// Offered cipher suites, in order, GREASE values retained (the JA3/JA4
    /// builders filter them).
    pub cipher_suites: Vec<u16>,
    /// Extension types, in the order they appear.
    pub extensions: Vec<u16>,
    /// `supported_groups` extension (0x000a) — the elliptic curves.
    pub supported_groups: Vec<u16>,
    /// `ec_point_formats` extension (0x000b).
    pub ec_point_formats: Vec<u8>,
    /// `application_layer_protocol_negotiation` extension (0x0010), in order.
    pub alpn: Vec<String>,
    /// `supported_versions` extension (0x002b) — decides the JA4 version.
    pub supported_versions: Vec<u16>,
    /// `signature_algorithms` extension (0x000d), in order (JA4 keeps order).
    pub signature_algorithms: Vec<u16>,
    /// Server Name Indication host, if present.
    pub sni: Option<String>,
}

/// The fields of a TLS ServerHello a JA3S fingerprint is computed from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerHello {
    /// `legacy_version` from the handshake body.
    pub version: u16,
    /// Server random (32 bytes).
    pub random: [u8; 32],
    /// The single cipher suite the server selected.
    pub cipher_suite: u16,
    /// Extension types the server returned, in order.
    pub extensions: Vec<u16>,
}

/// RFC 8701 GREASE values are reserved placeholders a client sprinkles into
/// its cipher/extension/group lists; they must be stripped before fingerprinting
/// so the same client always hashes identically. A 16-bit value is GREASE when
/// both bytes are equal and their low nibble is 0xa (0x0a0a, 0x1a1a, … 0xfafa).
fn is_grease(v: u16) -> bool {
    (v >> 8) == (v & 0x00ff) && (v & 0x000f) == 0x000a
}

/// Parse a TLS record that should hold a ClientHello. Returns `None` if the
/// bytes are not a well-formed handshake ClientHello. Every field access is
/// bounds-checked, so arbitrary/truncated input can never panic.
pub fn parse_client_hello(data: &[u8]) -> Option<ClientHello> {
    // TLS record header: type(1)=0x16 handshake, version(2), length(2).
    if data.len() < 9 || data[0] != 0x16 {
        return None;
    }
    // Handshake header: type(1)=0x01 ClientHello, length(3).
    if data[5] != 0x01 {
        return None;
    }

    let mut c = Cursor::new(data);
    c.skip(5)?; // record header
    c.skip(4)?; // handshake type + length

    let version = c.u16()?;
    let random_slice = c.read_bytes(32)?;
    let mut random = [0u8; 32];
    random.copy_from_slice(random_slice);

    let session_id_len = c.u8()? as usize;
    c.skip(session_id_len)?;

    let cipher_bytes = c.u16()? as usize;
    if !cipher_bytes.is_multiple_of(2) {
        return None;
    }
    let mut cipher_suites = Vec::with_capacity(cipher_bytes / 2);
    for _ in 0..cipher_bytes / 2 {
        cipher_suites.push(c.u16()?);
    }

    let comp_len = c.u8()? as usize;
    c.skip(comp_len)?;

    let mut hello = ClientHello {
        version,
        random,
        cipher_suites,
        ..Default::default()
    };

    // Extensions are optional (older ClientHellos omit them entirely).
    let ext_total = match c.u16() {
        Some(n) => n as usize,
        None => return Some(hello),
    };
    let ext_end = c.pos + ext_total;
    while c.pos + 4 <= data.len() && c.pos < ext_end {
        let ext_type = c.u16()?;
        let ext_len = c.u16()? as usize;
        let body_start = c.pos;
        if body_start + ext_len > data.len() {
            break;
        }
        let body = &data[body_start..body_start + ext_len];
        hello.extensions.push(ext_type);
        match ext_type {
            0x0000 => hello.sni = parse_sni(body),
            0x000a => hello.supported_groups = parse_u16_list(body),
            0x000b => hello.ec_point_formats = parse_u8_list(body),
            0x000d => hello.signature_algorithms = parse_u16_list(body),
            0x0010 => hello.alpn = parse_alpn(body),
            0x002b => hello.supported_versions = parse_supported_versions(body),
            _ => {}
        }
        c.pos = body_start + ext_len;
    }

    Some(hello)
}

/// Parse a TLS record that should hold a ServerHello (handshake type 0x02).
/// Bounds-checked throughout; returns `None` on anything malformed.
pub fn parse_server_hello(data: &[u8]) -> Option<ServerHello> {
    if data.len() < 9 || data[0] != 0x16 || data[5] != 0x02 {
        return None;
    }
    let mut c = Cursor::new(data);
    c.skip(5)?; // record header
    c.skip(4)?; // handshake type + length

    let version = c.u16()?;
    let random_slice = c.read_bytes(32)?;
    let mut random = [0u8; 32];
    random.copy_from_slice(random_slice);

    let session_id_len = c.u8()? as usize;
    c.skip(session_id_len)?;

    let cipher_suite = c.u16()?; // the single chosen suite
    c.skip(1)?; // compression method

    let mut server = ServerHello {
        version,
        random,
        cipher_suite,
        extensions: Vec::new(),
    };

    let ext_total = match c.u16() {
        Some(n) => n as usize,
        None => return Some(server),
    };
    let ext_end = c.pos + ext_total;
    while c.pos + 4 <= data.len() && c.pos < ext_end {
        let ext_type = c.u16()?;
        let ext_len = c.u16()? as usize;
        let body_start = c.pos;
        if body_start + ext_len > data.len() {
            break;
        }
        server.extensions.push(ext_type);
        c.pos = body_start + ext_len;
    }
    Some(server)
}

/// The `server_name` extension body: list length(2), then entries of
/// type(1) + name length(2) + name. Returns the first host_name (type 0).
fn parse_sni(body: &[u8]) -> Option<String> {
    if body.len() < 5 {
        return None;
    }
    // body[0..2] = server_name_list length. Entry starts at 2.
    let name_type = body[2];
    if name_type != 0x00 {
        return None;
    }
    let name_len = u16::from_be_bytes([body[3], body[4]]) as usize;
    let start = 5;
    if start + name_len > body.len() {
        return None;
    }
    std::str::from_utf8(&body[start..start + name_len])
        .ok()
        .map(str::to_string)
}

/// A `u16` vector prefixed by a 2-byte length (supported_groups body).
fn parse_u16_list(body: &[u8]) -> Vec<u16> {
    if body.len() < 2 {
        return Vec::new();
    }
    let len = u16::from_be_bytes([body[0], body[1]]) as usize;
    let list = &body[2..(2 + len).min(body.len())];
    list.chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect()
}

/// A `u8` vector prefixed by a 1-byte length (ec_point_formats body).
fn parse_u8_list(body: &[u8]) -> Vec<u8> {
    if body.is_empty() {
        return Vec::new();
    }
    let len = body[0] as usize;
    body[1..(1 + len).min(body.len())].to_vec()
}

/// A `u16` vector prefixed by a 1-byte length (supported_versions body).
fn parse_supported_versions(body: &[u8]) -> Vec<u16> {
    if body.is_empty() {
        return Vec::new();
    }
    let len = body[0] as usize;
    let list = &body[1..(1 + len).min(body.len())];
    list.chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect()
}

/// The ALPN extension body: protocol-list length(2), then entries of
/// length(1) + protocol bytes. Returns each advertised protocol in order.
fn parse_alpn(body: &[u8]) -> Vec<String> {
    if body.len() < 2 {
        return Vec::new();
    }
    let list_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    let end = (2 + list_len).min(body.len());
    let mut out = Vec::new();
    let mut off = 2;
    while off < end {
        let len = body[off] as usize;
        off += 1;
        if off + len > end {
            break;
        }
        if let Ok(s) = std::str::from_utf8(&body[off..off + len]) {
            out.push(s.to_string());
        }
        off += len;
    }
    out
}

/// Build the JA3 pre-hash string:
/// `Version,Ciphers,Extensions,EllipticCurves,ECPointFormats`, where each list
/// is `-`-joined decimals with GREASE removed (RFC 8701). This is the exact
/// string the MD5 is taken over, exposed for testing.
pub fn ja3_string(h: &ClientHello) -> String {
    let join_u16 = |xs: &[u16]| -> String {
        xs.iter()
            .filter(|&&v| !is_grease(v))
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join("-")
    };
    let point_formats = h
        .ec_point_formats
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-");
    format!(
        "{},{},{},{},{}",
        h.version,
        join_u16(&h.cipher_suites),
        join_u16(&h.extensions),
        join_u16(&h.supported_groups),
        point_formats,
    )
}

/// The JA3 fingerprint: the MD5 of [`ja3_string`], as 32 lowercase hex chars.
pub fn ja3_hash(h: &ClientHello) -> String {
    md5_hex(&ja3_string(h))
}

/// Build the JA3S pre-hash string for a ServerHello:
/// `Version,Cipher,Extensions` — a single chosen cipher (not a list) and the
/// server's extension types, GREASE removed. Exposed for testing.
pub fn ja3s_string(s: &ServerHello) -> String {
    let extensions = s
        .extensions
        .iter()
        .filter(|&&v| !is_grease(v))
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-");
    format!("{},{},{}", s.version, s.cipher_suite, extensions)
}

/// The JA3S fingerprint: MD5 of [`ja3s_string`], 32 lowercase hex chars.
pub fn ja3s_hash(s: &ServerHello) -> String {
    md5_hex(&ja3s_string(s))
}

/// The JA4 client fingerprint (FoxIO), `JA4_a_JA4_b_JA4_c`:
/// - **a** (10 chars): transport, TLS version, SNI presence, cipher count,
///   extension count and first-ALPN two-char code.
/// - **b** (12 hex): SHA-256 of the sorted cipher list.
/// - **c** (12 hex): SHA-256 of the sorted extensions (minus SNI/ALPN) plus the
///   signature algorithms in their original order.
///
/// `transport` is `t` for TCP, `q` for QUIC. GREASE values are excluded from
/// every count and list (RFC 8701).
pub fn ja4(h: &ClientHello, transport: char) -> String {
    let ciphers: Vec<u16> = h
        .cipher_suites
        .iter()
        .copied()
        .filter(|&v| !is_grease(v))
        .collect();
    let extensions: Vec<u16> = h
        .extensions
        .iter()
        .copied()
        .filter(|&v| !is_grease(v))
        .collect();

    // --- JA4_a ---
    let version = ja4_version(h);
    let sni = if h.sni.is_some() { 'd' } else { 'i' };
    let cipher_count = ciphers.len().min(99);
    let ext_count = extensions.len().min(99);
    let alpn = ja4_alpn(h);
    let a = format!("{transport}{version}{sni}{cipher_count:02}{ext_count:02}{alpn}");

    // --- JA4_b: sorted ciphers ---
    let mut cipher_hex: Vec<String> = ciphers.iter().map(|c| format!("{c:04x}")).collect();
    cipher_hex.sort();
    let b = truncated_sha256(&cipher_hex.join(","));

    // --- JA4_c: sorted extensions (minus SNI 0x0000 and ALPN 0x0010),
    // then signature algorithms in order ---
    let mut ext_hex: Vec<String> = extensions
        .iter()
        .filter(|&&e| e != 0x0000 && e != 0x0010)
        .map(|e| format!("{e:04x}"))
        .collect();
    ext_hex.sort();
    let sig_hex: Vec<String> = h
        .signature_algorithms
        .iter()
        .map(|s| format!("{s:04x}"))
        .collect();
    let c_raw = if sig_hex.is_empty() {
        ext_hex.join(",")
    } else {
        format!("{}_{}", ext_hex.join(","), sig_hex.join(","))
    };
    let c = truncated_sha256(&c_raw);

    format!("{a}_{b}_{c}")
}

/// The 2-char JA4 version: the highest non-GREASE version from the
/// `supported_versions` extension if present, else the legacy handshake version.
fn ja4_version(h: &ClientHello) -> &'static str {
    let chosen = h
        .supported_versions
        .iter()
        .copied()
        .filter(|&v| !is_grease(v))
        .max()
        .unwrap_or(h.version);
    match chosen {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        _ => "00",
    }
}

/// The 2-char JA4 ALPN code: first and last character of the first advertised
/// ALPN protocol (`"00"` if none). Non-alphanumeric endpoints fall back to the
/// first hex nibble of each boundary byte, per the JA4 spec's edge-case rule.
fn ja4_alpn(h: &ClientHello) -> String {
    let Some(first) = h.alpn.iter().find(|p| !p.is_empty()) else {
        return "00".to_string();
    };
    let bytes = first.as_bytes();
    let (a, b) = (bytes[0], bytes[bytes.len() - 1]);
    if a.is_ascii_alphanumeric() && b.is_ascii_alphanumeric() {
        format!("{}{}", a as char, b as char)
    } else {
        let hex = format!("{a:02x}{b:02x}");
        format!("{}{}", &hex[0..1], &hex[3..4])
    }
}

/// MD5 of `s`, lowercase hex.
fn md5_hex(s: &str) -> String {
    use md5::{Digest, Md5};
    let mut hasher = Md5::new();
    hasher.update(s.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The first 12 lowercase hex chars of SHA-256(`s`), or twelve zeros when `s`
/// is empty — the JA4 convention for an absent cipher/extension list.
fn truncated_sha256(s: &str) -> String {
    if s.is_empty() {
        return "000000000000".to_string();
    }
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let full: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    full[..12].to_string()
}

/// Minimal forward-only byte cursor with bounds-checked reads. Every accessor
/// returns `None` past the end so the parser degrades gracefully on truncation.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    fn u8(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    fn u16(&mut self) -> Option<u16> {
        if self.pos + 2 > self.data.len() {
            return None;
        }
        let v = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Some(v)
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        let next = self.pos.checked_add(n)?;
        if next > self.data.len() {
            return None;
        }
        self.pos = next;
        Some(())
    }
    fn read_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let next = self.pos.checked_add(n)?;
        if next > self.data.len() {
            return None;
        }
        let slice = &self.data[self.pos..next];
        self.pos = next;
        Some(slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal TLS ClientHello with an optional SNI, a fixed cipher
    /// list, and supported_groups + ec_point_formats extensions.
    fn build_client_hello_with_sni(hostname: &str) -> Vec<u8> {
        let hostname_bytes = hostname.as_bytes();
        let mut buf = Vec::new();

        // TLS Record: content type 0x16 (Handshake), version 0x0303.
        buf.push(0x16);
        buf.extend_from_slice(&[0x03, 0x03]);
        let record_len_pos = buf.len();
        buf.extend_from_slice(&[0x00, 0x00]);

        // Handshake: type 0x01 (ClientHello), 3-byte length placeholder.
        buf.push(0x01);
        let hs_len_pos = buf.len();
        buf.extend_from_slice(&[0x00, 0x00, 0x00]);

        // ClientHello body: version, random, session id.
        buf.extend_from_slice(&[0x03, 0x03]);
        buf.extend_from_slice(&[0u8; 32]);
        buf.push(0x00); // session id length

        // Cipher suites: two entries, one of them a GREASE value (0x1a1a).
        buf.extend_from_slice(&[0x00, 0x04]); // length = 4 bytes
        buf.extend_from_slice(&[0x1a, 0x1a]); // GREASE — must be filtered
        buf.extend_from_slice(&[0x00, 0x2f]); // TLS_RSA_WITH_AES_128_CBC_SHA (47)

        // Compression: null.
        buf.push(0x01);
        buf.push(0x00);

        // Extensions.
        let ext_len_pos = buf.len();
        buf.extend_from_slice(&[0x00, 0x00]);

        // SNI extension (0x0000).
        buf.extend_from_slice(&[0x00, 0x00]);
        let sni_ext_len_pos = buf.len();
        buf.extend_from_slice(&[0x00, 0x00]);
        let sni_list_len_pos = buf.len();
        buf.extend_from_slice(&[0x00, 0x00]);
        buf.push(0x00); // host_name type
        buf.extend_from_slice(&(hostname_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(hostname_bytes);
        let sni_list_total = buf.len() - sni_list_len_pos - 2;
        buf[sni_list_len_pos..sni_list_len_pos + 2]
            .copy_from_slice(&(sni_list_total as u16).to_be_bytes());
        let sni_ext_total = buf.len() - sni_ext_len_pos - 2;
        buf[sni_ext_len_pos..sni_ext_len_pos + 2]
            .copy_from_slice(&(sni_ext_total as u16).to_be_bytes());

        // supported_groups extension (0x000a): one group 0x001d (x25519).
        buf.extend_from_slice(&[0x00, 0x0a]); // type
        buf.extend_from_slice(&[0x00, 0x04]); // ext length
        buf.extend_from_slice(&[0x00, 0x02]); // list length
        buf.extend_from_slice(&[0x00, 0x1d]); // x25519 (29)

        // ec_point_formats extension (0x000b): one format 0x00 (uncompressed).
        buf.extend_from_slice(&[0x00, 0x0b]); // type
        buf.extend_from_slice(&[0x00, 0x02]); // ext length
        buf.push(0x01); // list length
        buf.push(0x00); // uncompressed (0)

        // signature_algorithms extension (0x000d): [0x0403, 0x0804], in order.
        buf.extend_from_slice(&[0x00, 0x0d]); // type
        buf.extend_from_slice(&[0x00, 0x06]); // ext length
        buf.extend_from_slice(&[0x00, 0x04]); // list length (bytes)
        buf.extend_from_slice(&[0x04, 0x03, 0x08, 0x04]);

        // ALPN extension (0x0010): a single "h2" protocol.
        buf.extend_from_slice(&[0x00, 0x10]); // type
        buf.extend_from_slice(&[0x00, 0x05]); // ext length
        buf.extend_from_slice(&[0x00, 0x03]); // protocol list length
        buf.push(0x02); // protocol string length
        buf.extend_from_slice(b"h2");

        // supported_versions extension (0x002b): [GREASE 0x0a0a, TLS 1.3].
        buf.extend_from_slice(&[0x00, 0x2b]); // type
        buf.extend_from_slice(&[0x00, 0x05]); // ext length
        buf.push(0x04); // list length (bytes)
        buf.extend_from_slice(&[0x0a, 0x0a, 0x03, 0x04]);

        let ext_total = buf.len() - ext_len_pos - 2;
        buf[ext_len_pos..ext_len_pos + 2].copy_from_slice(&(ext_total as u16).to_be_bytes());

        let hs_total = buf.len() - hs_len_pos - 3;
        buf[hs_len_pos..hs_len_pos + 3].copy_from_slice(&[
            (hs_total >> 16) as u8,
            (hs_total >> 8) as u8,
            hs_total as u8,
        ]);
        let record_total = buf.len() - record_len_pos - 2;
        buf[record_len_pos..record_len_pos + 2]
            .copy_from_slice(&(record_total as u16).to_be_bytes());
        buf
    }

    /// Build a minimal TLS ServerHello: version, chosen cipher, and a couple of
    /// extensions (one of them GREASE, which JA3S must strip).
    fn build_server_hello() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(0x16); // record: handshake
        buf.extend_from_slice(&[0x03, 0x03]);
        let record_len_pos = buf.len();
        buf.extend_from_slice(&[0x00, 0x00]);

        buf.push(0x02); // handshake: ServerHello
        let hs_len_pos = buf.len();
        buf.extend_from_slice(&[0x00, 0x00, 0x00]);

        buf.extend_from_slice(&[0x03, 0x03]); // version
        buf.extend_from_slice(&[0u8; 32]); // random
        buf.push(0x00); // session id length
        buf.extend_from_slice(&[0x00, 0x2f]); // chosen cipher (47)
        buf.push(0x00); // compression method

        let ext_len_pos = buf.len();
        buf.extend_from_slice(&[0x00, 0x00]);
        // supported_versions (0x002b) — server picks TLS 1.3.
        buf.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
        // A GREASE extension (0x1a1a) that must be filtered from JA3S.
        buf.extend_from_slice(&[0x1a, 0x1a, 0x00, 0x00]);
        let ext_total = buf.len() - ext_len_pos - 2;
        buf[ext_len_pos..ext_len_pos + 2].copy_from_slice(&(ext_total as u16).to_be_bytes());

        let hs_total = buf.len() - hs_len_pos - 3;
        buf[hs_len_pos..hs_len_pos + 3].copy_from_slice(&[
            (hs_total >> 16) as u8,
            (hs_total >> 8) as u8,
            hs_total as u8,
        ]);
        let record_total = buf.len() - record_len_pos - 2;
        buf[record_len_pos..record_len_pos + 2]
            .copy_from_slice(&(record_total as u16).to_be_bytes());
        buf
    }

    #[test]
    fn parses_hello_fields() {
        let data = build_client_hello_with_sni("github.com");
        let h = parse_client_hello(&data).expect("should parse");
        assert_eq!(h.version, 0x0303);
        assert_eq!(h.cipher_suites, vec![0x1a1a, 0x002f]);
        assert_eq!(
            h.extensions,
            vec![0x0000, 0x000a, 0x000b, 0x000d, 0x0010, 0x002b]
        );
        assert_eq!(h.supported_groups, vec![0x001d]);
        assert_eq!(h.ec_point_formats, vec![0x00]);
        assert_eq!(h.signature_algorithms, vec![0x0403, 0x0804]);
        assert_eq!(h.alpn, vec!["h2".to_string()]);
        assert_eq!(h.supported_versions, vec![0x0a0a, 0x0304]);
        assert_eq!(h.sni.as_deref(), Some("github.com"));
    }

    #[test]
    fn grease_is_stripped_and_ja3_string_is_exact() {
        let data = build_client_hello_with_sni("github.com");
        let h = parse_client_hello(&data).unwrap();
        // Version 771; cipher GREASE 0x1a1a dropped leaving 47; extensions
        // 0,10,11,13,16,43; curve 29; point format 0.
        assert_eq!(ja3_string(&h), "771,47,0-10-11-13-16-43,29,0");
    }

    #[test]
    fn ja4_a_prefix_is_exact() {
        let data = build_client_hello_with_sni("github.com");
        let h = parse_client_hello(&data).unwrap();
        let ja4 = ja4(&h, 't');
        // t (TCP) · 13 (TLS 1.3 from supported_versions) · d (SNI present) ·
        // 01 (one non-GREASE cipher) · 06 (six extensions) · h2 (first ALPN).
        assert!(ja4.starts_with("t13d0106h2_"), "{ja4}");
        // Shape: a_b_c with 12-hex b and c.
        let parts: Vec<&str> = ja4.split('_').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "t13d0106h2");
        assert_eq!(parts[1].len(), 12);
        assert_eq!(parts[2].len(), 12);
        assert!(parts[1].chars().all(|c| c.is_ascii_hexdigit()));
        assert!(parts[2].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn ja4_b_and_c_match_hashed_inputs() {
        let data = build_client_hello_with_sni("github.com");
        let h = parse_client_hello(&data).unwrap();
        let ja4 = ja4(&h, 't');
        let parts: Vec<&str> = ja4.split('_').collect();
        // b = sha256 of the sorted non-GREASE cipher list ("002f").
        assert_eq!(parts[1], &sha256_first12("002f"));
        // c = sha256 of sorted extensions (minus SNI 0000 and ALPN 0010),
        // then signature algorithms in order.
        assert_eq!(parts[2], &sha256_first12("000a,000b,000d,002b_0403,0804"));
    }

    fn sha256_first12(s: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(s.as_bytes());
        let full: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        full[..12].to_string()
    }

    #[test]
    fn ja4_version_and_alpn_fallbacks() {
        // No supported_versions: fall back to the legacy version (TLS 1.2).
        let mut h = ClientHello {
            version: 0x0303,
            ..Default::default()
        };
        assert!(ja4(&h, 't').starts_with("t12i0000"));
        // No ALPN → "00"; here also zero ciphers/extensions.
        assert!(ja4(&h, 't').starts_with("t12i000000_000000000000_000000000000"));
        // ALPN "http/1.1" → first 'h', last '1'.
        h.alpn = vec!["http/1.1".to_string()];
        assert!(ja4(&h, 't').contains("h1_"));
    }

    #[test]
    fn ja3s_string_and_hash() {
        let data = build_server_hello();
        let s = parse_server_hello(&data).expect("should parse ServerHello");
        assert_eq!(s.version, 0x0303);
        assert_eq!(s.cipher_suite, 0x002f);
        assert_eq!(s.extensions, vec![0x002b, 0x1a1a]);
        // GREASE 0x1a1a is stripped; only 43 (0x002b) remains.
        assert_eq!(ja3s_string(&s), "771,47,43");
        assert_eq!(ja3s_hash(&s).len(), 32);
    }

    #[test]
    fn ja3_hash_is_md5_of_the_string() {
        let data = build_client_hello_with_sni("github.com");
        let h = parse_client_hello(&data).unwrap();
        // MD5("771,47,0-10-11,29,0").
        let expected = {
            use md5::{Digest, Md5};
            let mut hasher = Md5::new();
            hasher.update(ja3_string(&h).as_bytes());
            format!("{:x}", hasher.finalize())
        };
        assert_eq!(ja3_hash(&h), expected);
        assert_eq!(ja3_hash(&h).len(), 32);
        assert!(ja3_hash(&h).chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn is_grease_matches_rfc8701_values() {
        for &g in &[0x0a0au16, 0x1a1a, 0x2a2a, 0x3a3a, 0x8a8a, 0xdada, 0xfafa] {
            assert!(is_grease(g), "0x{g:04x} should be GREASE");
        }
        for &n in &[0x0000u16, 0x002f, 0x1301, 0xabab, 0x0a0b] {
            assert!(!is_grease(n), "0x{n:04x} should not be GREASE");
        }
    }

    #[test]
    fn dissect_reports_sni_ja3_and_ja4() {
        let data = build_client_hello_with_sni("github.com");
        let result = dissect_tls(
            Some("10.0.0.1".parse().unwrap()),
            Some("10.0.0.2".parse().unwrap()),
            54321,
            443,
            &data,
        );
        assert_eq!(result.protocol, Protocol::Tls);
        assert!(result
            .summary
            .starts_with("TLS ClientHello — github.com · JA4 "));
        let h = parse_client_hello(&data).unwrap();
        // Both fingerprints are present and match the computed values.
        assert!(result.summary.contains(&ja4(&h, 't')));
        assert!(result.summary.contains(&ja3_hash(&h)));
    }

    #[test]
    fn dissect_reports_server_hello_ja3s() {
        let data = build_server_hello();
        let result = dissect_tls(
            Some("10.0.0.2".parse().unwrap()),
            Some("10.0.0.1".parse().unwrap()),
            443,
            54321,
            &data,
        );
        assert_eq!(result.protocol, Protocol::Tls);
        let s = parse_server_hello(&data).unwrap();
        assert_eq!(
            result.summary,
            format!("TLS ServerHello · JA3S {}", ja3s_hash(&s))
        );
    }

    #[test]
    fn tls_encrypted_data() {
        let result = dissect_tls(
            None,
            None,
            54321,
            443,
            &[0x17, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05],
        );
        assert_eq!(result.protocol, Protocol::Tls);
        assert_eq!(result.summary, "TLS — 10 bytes of encrypted data");
    }

    #[test]
    fn truncated_hello_never_panics() {
        // Every prefix of a real ClientHello and ServerHello must parse to
        // Some/None without panicking (fuzzing the length-prefix bounds checks).
        let client = build_client_hello_with_sni("example.org");
        for cut in 0..client.len() {
            let _ = parse_client_hello(&client[..cut]);
            let _ = dissect_tls(None, None, 1, 443, &client[..cut]);
        }
        let server = build_server_hello();
        for cut in 0..server.len() {
            let _ = parse_server_hello(&server[..cut]);
            let _ = dissect_tls(None, None, 443, 1, &server[..cut]);
        }
    }

    #[test]
    fn test_tls_decryption_with_keylog() {
        use std::fs::File;
        use std::io::Write;

        clear_tls_sessions();

        let keylog_path = std::env::temp_dir().join("test_sslkeylog.log");
        let client_random = [0xaa; 32];
        let client_random_hex = hex_encode(&client_random);

        let client_secret = [0x55; 32];
        let client_secret_hex = hex_encode(&client_secret);

        let mut file = File::create(&keylog_path).unwrap();
        writeln!(
            file,
            "CLIENT_TRAFFIC_SECRET_0 {} {}",
            client_random_hex, client_secret_hex
        )
        .unwrap();
        drop(file);

        std::env::set_var("SSLKEYLOGFILE", &keylog_path);

        let derived_key = hkdf_expand_label_sha256(&client_secret, "key", &[], 16);
        let derived_iv = hkdf_expand_label_sha256(&client_secret, "iv", &[], 12);

        assert_eq!(derived_key.len(), 16);
        assert_eq!(derived_iv.len(), 12);

        let plaintext_payload = b"GET / HTTP/1.1\r\n\r\n";
        let mut inner_plaintext = plaintext_payload.to_vec();
        inner_plaintext.push(23); // inner type

        let cipher = Aes128Gcm::new_from_slice(&derived_key).unwrap();
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&derived_iv[..12]);

        let header = [23, 3, 3, 0, (inner_plaintext.len() + 16) as u8];
        let ciphertext = cipher
            .encrypt(
                nonce.as_ref().into(),
                aes_gcm::aead::Payload {
                    msg: &inner_plaintext,
                    aad: &header,
                },
            )
            .unwrap();

        let mut record = header.to_vec();
        record.extend_from_slice(&ciphertext);

        let ip_src = "10.0.0.1".parse().unwrap();
        let ip_dst = "10.0.0.2".parse().unwrap();
        let key = TlsFlowKey {
            client_ip: ip_src,
            client_port: 12345,
            server_ip: ip_dst,
            server_port: 443,
        };
        TLS_SESSIONS.with(|sessions| {
            sessions.borrow_mut().insert(
                key,
                TlsSessionState {
                    client_random,
                    server_random: None,
                    cipher_suite: Some(0x1301),
                    client_key: Some(derived_key),
                    client_iv: Some(derived_iv),
                    server_key: None,
                    server_iv: None,
                    seq_num_client: 0,
                    seq_num_server: 0,
                },
            );
        });

        let res = dissect_tls(Some(ip_src), Some(ip_dst), 12345, 443, &record);
        assert_eq!(res.protocol, Protocol::Http);
        assert!(res.summary.contains("[HTTPS] HTTP GET /"));

        std::env::remove_var("SSLKEYLOGFILE");
        std::fs::remove_file(keylog_path).ok();
    }

    #[test]
    fn test_tls_12_rsa_decryption() {
        use std::fs::File;
        use std::io::Write;

        clear_tls_sessions();

        let rsa_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 1024).unwrap();
        use rsa::pkcs8::EncodePrivateKey;
        let private_key_pem = rsa_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap()
            .to_string();

        let key_path = std::env::temp_dir().join("test_rsa.key");
        let mut file = File::create(&key_path).unwrap();
        file.write_all(private_key_pem.as_bytes()).unwrap();
        drop(file);

        std::env::set_var("TLS_RSA_PRIVATE_KEY", &key_path);

        let rsa_key = get_rsa_private_key().unwrap();

        let mut pre_master = [0u8; 48];
        pre_master[0] = 0x03;
        pre_master[1] = 0x03;
        for (i, byte) in pre_master.iter_mut().enumerate().skip(2) {
            *byte = i as u8;
        }

        let rsa_pub = rsa::RsaPublicKey::from(&rsa_key);
        let enc_pm = rsa_pub
            .encrypt(&mut rand::thread_rng(), rsa::Pkcs1v15Encrypt, &pre_master)
            .unwrap();

        let client_random = [0x77; 32];
        let server_random = [0x88; 32];

        let mut seed = client_random.to_vec();
        seed.extend_from_slice(&server_random);
        let master_secret = prf_sha256(&pre_master, "master secret", &seed, 48);

        let mut seed2 = server_random.to_vec();
        seed2.extend_from_slice(&client_random);
        let key_block = prf_sha256(&master_secret, "key expansion", &seed2, 40);

        let client_key = key_block[..16].to_vec();
        let _server_key = key_block[16..32].to_vec();
        let client_salt = key_block[32..36].to_vec();
        let _server_salt = key_block[36..40].to_vec();

        let plaintext_payload = b"GET /index.html HTTP/1.1\r\n\r\n";
        let cipher = Aes128Gcm::new_from_slice(&client_key).unwrap();

        let explicit_nonce = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&client_salt);
        nonce[4..].copy_from_slice(&explicit_nonce);

        let header = [23, 3, 3, 0, (plaintext_payload.len() + 8 + 16) as u8];

        let mut aad = [0u8; 13];
        aad[8] = 23;
        aad[9] = 3;
        aad[10] = 3;
        aad[11..13].copy_from_slice(&(plaintext_payload.len() as u16).to_be_bytes());

        let ciphertext = cipher
            .encrypt(
                nonce.as_ref().into(),
                aes_gcm::aead::Payload {
                    msg: plaintext_payload,
                    aad: &aad,
                },
            )
            .unwrap();

        let mut cke_body = vec![16, 0, 0, 0];
        let cke_len = (enc_pm.len() + 2) as u32;
        cke_body[1..4].copy_from_slice(&cke_len.to_be_bytes()[1..4]);
        cke_body.extend_from_slice(&(enc_pm.len() as u16).to_be_bytes());
        cke_body.extend_from_slice(&enc_pm);

        let mut cke_record = vec![22, 3, 3, 0, 0];
        let rec_len = cke_body.len() as u16;
        cke_record[3..5].copy_from_slice(&rec_len.to_be_bytes());
        cke_record.extend_from_slice(&cke_body);

        let ip_src = "10.0.0.1".parse().unwrap();
        let ip_dst = "10.0.0.2".parse().unwrap();
        let key = TlsFlowKey {
            client_ip: ip_src,
            client_port: 12345,
            server_ip: ip_dst,
            server_port: 443,
        };
        TLS_SESSIONS.with(|sessions| {
            sessions.borrow_mut().insert(
                key,
                TlsSessionState {
                    client_random,
                    server_random: Some(server_random),
                    cipher_suite: Some(0x009c),
                    client_key: None,
                    client_iv: None,
                    server_key: None,
                    server_iv: None,
                    seq_num_client: 0,
                    seq_num_server: 0,
                },
            );
        });

        dissect_tls(Some(ip_src), Some(ip_dst), 12345, 443, &cke_record);

        let mut data_record = header.to_vec();
        data_record.extend_from_slice(&explicit_nonce);
        data_record.extend_from_slice(&ciphertext);

        let res = dissect_tls(Some(ip_src), Some(ip_dst), 12345, 443, &data_record);
        assert_eq!(res.protocol, Protocol::Http);
        assert!(res.summary.contains("[HTTPS] HTTP GET /index.html"));

        std::env::remove_var("TLS_RSA_PRIVATE_KEY");
        std::fs::remove_file(key_path).ok();
    }

    #[test]
    fn test_tls_mitm_ca_generation() {
        let (ca, ca_key) = generate_ca().unwrap();
        let cert_pem = sign_host_cert("example.com", &ca, &ca_key).unwrap();
        assert!(cert_pem.contains("-----BEGIN CERTIFICATE-----"));
        assert!(cert_pem.contains("-----END CERTIFICATE-----"));
    }
}
