use std::net::IpAddr;
use std::collections::HashMap;
use std::cell::RefCell;

use crate::models::Protocol;

use super::DissectedResult;

thread_local! {
    static TEST_ESP_KEYS: RefCell<HashMap<u32, Vec<u8>>> = RefCell::new(HashMap::new());
}

#[cfg(test)]
pub fn clear_esp_keys() {
    TEST_ESP_KEYS.with(|keys| keys.borrow_mut().clear());
}

fn decode_hex(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 {
        return Err(());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i+2], 16).map_err(|_| ()))
        .collect()
}

fn decrypt_esp_gcm(payload: &[u8], _spi: u32, key_bytes: &[u8]) -> Option<(u8, Vec<u8>)> {
    if key_bytes.len() != 20 || payload.len() < 8 + 8 + 16 + 2 { return None; }
    
    let iv = &payload[8..16];
    let ciphertext_and_tag = &payload[16..];
    
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&key_bytes[16..20]);
    nonce[4..12].copy_from_slice(iv);
    
    let mut aad = [0u8; 8];
    aad[..4].copy_from_slice(&payload[..4]);
    aad[4..8].copy_from_slice(&payload[4..8]);
    
    use aes_gcm::{Aes128Gcm, KeyInit, aead::Aead};
    let cipher = Aes128Gcm::new_from_slice(&key_bytes[..16]).ok()?;
    let plaintext = cipher.decrypt(nonce.as_ref().into(), aes_gcm::aead::Payload {
        msg: ciphertext_and_tag,
        aad: &aad,
    }).ok()?;
    
    if plaintext.len() < 2 { return None; }
    let pad_len = plaintext[plaintext.len() - 2] as usize;
    let next_header = plaintext[plaintext.len() - 1];
    if plaintext.len() < 2 + pad_len { return None; }
    
    let decrypted_payload = plaintext[..plaintext.len() - 2 - pad_len].to_vec();
    Some((next_header, decrypted_payload))
}

pub fn dissect_esp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    let base = DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Esp,
        summary: String::new(),
    };

    if payload.len() < 8 {
        return DissectedResult {
            summary: "ESP (IPsec, partial)".into(),
            ..base
        };
    }
    let spi = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let seq = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);

    let mut key_bytes = TEST_ESP_KEYS.with(|keys| keys.borrow().get(&spi).cloned());
    if key_bytes.is_none() {
        if let Ok(keys_str) = std::env::var("IPSEC_ESP_KEYS") {
            for part in keys_str.split(',') {
                let subparts: Vec<&str> = part.split(':').collect();
                if subparts.len() == 2 {
                    let spi_str = subparts[0].trim().trim_start_matches("0x");
                    let key_hex = subparts[1].trim();
                    if let (Ok(parsed_spi), Ok(parsed_bytes)) = (u32::from_str_radix(spi_str, 16), decode_hex(key_hex)) {
                        if parsed_spi == spi {
                            key_bytes = Some(parsed_bytes);
                            break;
                        }
                    }
                }
            }
        }
    }

    if let Some(key) = key_bytes {
        if let Some((next_proto, decrypted)) = decrypt_esp_gcm(payload, spi, &key) {
            let mut res = if next_proto == 4 {
                super::dispatch_l3(0x0800, &decrypted, 0)
            } else if next_proto == 41 {
                super::dispatch_l3(0x86dd, &decrypted, 0)
            } else {
                DissectedResult {
                    src_addr: src_ip,
                    dst_addr: dst_ip,
                    src_port: None,
                    dst_port: None,
                    protocol: Protocol::Esp,
                    summary: format!("Decrypted ESP payload (next header {next_proto})"),
                }
            };
            res.summary = format!("[ESP Decrypted] {}", res.summary);
            return res;
        }
    }

    DissectedResult {
        summary: format!("ESP (IPsec) — SPI 0x{spi:08x}, seq {seq}"),
        ..base
    }
}

/// Dissect an IPsec AH datagram (IP protocol 51).
///
/// AH (Authentication Header) authenticates a packet without encrypting it:
/// next-header(1), payload-len(1), reserved(2), SPI(4), sequence(4), then the
/// integrity check value. We report the SPI, sequence and the protocol AH is
/// protecting.
pub fn dissect_ah(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    let base = DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Ah,
        summary: String::new(),
    };

    if payload.len() < 12 {
        return DissectedResult {
            summary: "AH (IPsec, partial)".into(),
            ..base
        };
    }
    let next_header = payload[0];
    let spi = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let seq = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
    DissectedResult {
        summary: format!(
            "AH (IPsec) — SPI 0x{spi:08x}, seq {seq}, protects {}",
            next_header_name(next_header)
        ),
        ..base
    }
}

fn next_header_name(p: u8) -> String {
    match p {
        1 => "ICMP".into(),
        6 => "TCP".into(),
        17 => "UDP".into(),
        50 => "ESP".into(),
        58 => "ICMPv6".into(),
        other => format!("IP proto {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn esp_spi_and_seq() {
        let mut p = Vec::new();
        p.extend_from_slice(&0xdead_beefu32.to_be_bytes());
        p.extend_from_slice(&42u32.to_be_bytes());
        p.extend_from_slice(&[0u8; 16]);
        let r = dissect_esp(None, None, &p);
        assert_eq!(r.protocol, Protocol::Esp);
        assert_eq!(r.summary, "ESP (IPsec) — SPI 0xdeadbeef, seq 42");
    }

    #[test]
    fn ah_reports_protected_protocol() {
        let mut p = vec![6, 4, 0, 0]; // next-header TCP, len, reserved
        p.extend_from_slice(&0x11223344u32.to_be_bytes()); // SPI
        p.extend_from_slice(&7u32.to_be_bytes()); // seq
        p.extend_from_slice(&[0u8; 12]); // ICV
        let r = dissect_ah(None, None, &p);
        assert_eq!(r.protocol, Protocol::Ah);
        assert_eq!(
            r.summary,
            "AH (IPsec) — SPI 0x11223344, seq 7, protects TCP"
        );
    }

    #[test]
    fn esp_partial_is_safe() {
        let r = dissect_esp(None, None, &[0, 1, 2]);
        assert!(r.summary.contains("partial"));
    }

    #[test]
    fn test_esp_gcm_decryption() {
        use aes_gcm::{Aes128Gcm, KeyInit, aead::Aead};

        clear_esp_keys();

        let spi = 0x12345678u32;
        let mut key = [0u8; 20];
        key[..16].copy_from_slice(&[0xaa; 16]);
        key[16..20].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);

        TEST_ESP_KEYS.with(|keys| {
            keys.borrow_mut().insert(spi, key.to_vec());
        });

        let mut inner_plaintext = vec![
            0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 1, 10, 0, 0, 2,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ];
        inner_plaintext.push(0);
        inner_plaintext.push(0);
        inner_plaintext.push(4);

        let cipher = Aes128Gcm::new_from_slice(&key[..16]).unwrap();
        let iv = [0x99u8; 8];
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&key[16..20]);
        nonce[4..12].copy_from_slice(&iv);

        let mut aad = [0u8; 8];
        aad[..4].copy_from_slice(&spi.to_be_bytes());
        aad[4..8].copy_from_slice(&1u32.to_be_bytes());

        let ciphertext = cipher.encrypt(nonce.as_ref().into(), aes_gcm::aead::Payload {
            msg: &inner_plaintext,
            aad: &aad,
        }).unwrap();

        let mut packet = Vec::new();
        packet.extend_from_slice(&spi.to_be_bytes());
        packet.extend_from_slice(&1u32.to_be_bytes());
        packet.extend_from_slice(&iv);
        packet.extend_from_slice(&ciphertext);

        let res = dissect_esp(Some("10.0.0.1".parse().unwrap()), Some("10.0.0.2".parse().unwrap()), &packet);
        assert!(res.summary.contains("[ESP Decrypted]"));
        assert!(res.summary.contains("TCP"));
    }
}
