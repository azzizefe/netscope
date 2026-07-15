//! IEEE 802.11 (Wi-Fi) frame dissection.
//!
//! Handles the three frame classes — management (beacons, probe/assoc/auth),
//! control (ACK/RTS/CTS/Block-Ack) and data — and pulls the SSID out of
//! beacon and probe frames. Wi-Fi frames are link-layer, so no IP addresses
//! are set; the summary carries the SSID/BSSID and (from radiotap) the signal
//! and channel.

use crate::models::Protocol;

use std::collections::HashMap;
use std::cell::RefCell;

use super::ethernet::mac_to_string;
use super::{radiotap, DissectedResult};

#[derive(Hash, PartialEq, Eq, Clone, Debug)]
struct WlanSessionKey {
    addr1: [u8; 6],
    addr2: [u8; 6],
}

struct WlanSessionState {
    anonce: Option<[u8; 32]>,
    snonce: Option<[u8; 32]>,
    tk: Option<[u8; 16]>,
}

thread_local! {
    static WLAN_SESSIONS: RefCell<HashMap<WlanSessionKey, WlanSessionState>> = RefCell::new(HashMap::new());
    static TEST_WEP_KEY: RefCell<Option<String>> = RefCell::new(None);
    static TEST_WPA_TK: RefCell<Option<String>> = RefCell::new(None);
}

#[cfg(test)]
pub fn clear_wlan_sessions() {
    WLAN_SESSIONS.with(|sessions| {
        sessions.borrow_mut().clear();
    });
    TEST_WEP_KEY.with(|k| {
        *k.borrow_mut() = None;
    });
    TEST_WPA_TK.with(|k| {
        *k.borrow_mut() = None;
    });
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

fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    use sha1::{Sha1, Digest};
    let mut ipad = [0x36; 64];
    let mut opad = [0x5c; 64];
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        let h = Sha1::digest(key);
        key_block[..20].copy_from_slice(&h);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    for i in 0..64 {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }
    let mut h = Sha1::new();
    h.update(&ipad);
    h.update(data);
    let inner = h.finalize();
    let mut h = Sha1::new();
    h.update(&opad);
    h.update(&inner);
    h.finalize().into()
}

fn pbkdf2_hmac_sha1(passphrase: &str, salt: &str, iterations: u32, key_len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 1u32;
    while out.len() < key_len {
        let mut salt_i = salt.as_bytes().to_vec();
        salt_i.extend_from_slice(&i.to_be_bytes());
        
        let mut u = hmac_sha1(passphrase.as_bytes(), &salt_i);
        let mut f = u;
        for _ in 1..iterations {
            u = hmac_sha1(passphrase.as_bytes(), &u);
            for j in 0..20 {
                f[j] ^= u[j];
            }
        }
        out.extend_from_slice(&f);
        i += 1;
    }
    out.truncate(key_len);
    out
}

fn prf_512(key: &[u8], label: &str, init: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut label_init = label.as_bytes().to_vec();
    label_init.push(0);
    label_init.extend_from_slice(init);
    
    let mut i = 0u8;
    while out.len() < 64 {
        let mut data = label_init.clone();
        data.push(i);
        let block = hmac_sha1(key, &data);
        out.extend_from_slice(&block);
        i += 1;
    }
    out.truncate(64);
    out
}

fn rc4_decrypt(key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut s = [0u8; 256];
    for i in 0..256 { s[i] = i as u8; }
    let mut j = 0u8;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    let mut i = 0usize;
    let mut j = 0usize;
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    for &c in ciphertext {
        i = (i + 1) % 256;
        j = (j + s[i] as usize) % 256;
        s.swap(i, j);
        let k = s[(s[i] as usize + s[j] as usize) % 256];
        plaintext.push(c ^ k);
    }
    plaintext
}

fn decrypt_wep(iv: &[u8; 3], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let key_str = TEST_WEP_KEY.with(|k| k.borrow().clone())
        .or_else(|| std::env::var("WLAN_WEP_KEY").ok())?;
    let key_bytes = if let Ok(bytes) = decode_hex(&key_str) {
        bytes
    } else {
        key_str.into_bytes()
    };
    
    let mut rc4_key = Vec::new();
    rc4_key.extend_from_slice(iv);
    rc4_key.extend_from_slice(&key_bytes);
    
    let decrypted = rc4_decrypt(&rc4_key, ciphertext);
    if decrypted.len() > 8 && decrypted[0] == 0xaa && decrypted[1] == 0xaa && decrypted[2] == 0x03 {
        Some(decrypted)
    } else {
        None
    }
}

fn track_eapol_key(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    eapol_data: &[u8],
) {
    if eapol_data.len() < 95 { return; }
    let eapol_type = eapol_data[1];
    if eapol_type != 3 { return; }
    
    let key_info = u16::from_be_bytes([eapol_data[5], eapol_data[6]]);
    let is_pairwise = (key_info & 0x0008) != 0;
    if !is_pairwise { return; }
    
    let is_mic = (key_info & 0x0100) != 0;
    let is_ack = (key_info & 0x0080) != 0;
    
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&eapol_data[17..49]);
    
    let (min_mac, max_mac) = if src_mac < dst_mac { (src_mac, dst_mac) } else { (dst_mac, src_mac) };
    let session_key = WlanSessionKey { addr1: min_mac, addr2: max_mac };
    
    WLAN_SESSIONS.with(|sessions| {
        let mut map = sessions.borrow_mut();
        let state = map.entry(session_key).or_insert_with(|| WlanSessionState {
            anonce: None,
            snonce: None,
            tk: None,
        });
        
        if is_ack && !is_mic {
            state.anonce = Some(nonce);
        } else if !is_ack && is_mic {
            state.snonce = Some(nonce);
        }
        
        if state.tk.is_none() {
            if let (Some(anonce), Some(snonce)) = (state.anonce, state.snonce) {
                if let (Ok(passphrase), Ok(ssid)) = (std::env::var("WLAN_WPA_PASSPHRASE"), std::env::var("WLAN_SSID")) {
                    let pmk = pbkdf2_hmac_sha1(&passphrase, &ssid, 4096, 32);
                    
                    let mut init = Vec::new();
                    init.extend_from_slice(&min_mac);
                    init.extend_from_slice(&max_mac);
                    if anonce < snonce {
                        init.extend_from_slice(&anonce);
                        init.extend_from_slice(&snonce);
                    } else {
                        init.extend_from_slice(&snonce);
                        init.extend_from_slice(&anonce);
                    }
                    
                    let ptk = prf_512(&pmk, "Pairwise key expansion", &init);
                    let mut tk = [0u8; 16];
                    tk.copy_from_slice(&ptk[32..48]);
                    state.tk = Some(tk);
                }
            }
        }
    });
}

fn get_mac_header_len(fc: u8, subtype: u8) -> usize {
    let from_ds = (fc & 0x02) != 0;
    let to_ds = (fc & 0x01) != 0;
    let mut len = 24;
    if from_ds && to_ds { len += 6; }
    if subtype == 8 || subtype == 11 { len += 2; }
    len
}

fn decrypt_ccmp(
    data: &[u8],
    mac_header_len: usize,
    tk: &[u8; 16],
    addr2: [u8; 6],
    subtype: u8,
) -> Option<Vec<u8>> {
    use ccm::{Ccm, consts::{U8, U13}};
    use ccm::aead::{Aead, KeyInit, generic_array::GenericArray};
    type AesCcm = Ccm<aes_gcm::aes::Aes128, U8, U13>;

    if data.len() < mac_header_len + 8 { return None; }
    let ccmp_header = &data[mac_header_len..mac_header_len + 8];
    let pn0 = ccmp_header[0];
    let pn1 = ccmp_header[1];
    let pn2 = ccmp_header[4];
    let pn3 = ccmp_header[5];
    let pn4 = ccmp_header[6];
    let pn5 = ccmp_header[7];
    let pn = [pn5, pn4, pn3, pn2, pn1, pn0];

    let mut nonce = [0u8; 13];
    let priority = if subtype == 8 || subtype == 11 {
        data[mac_header_len - 2] & 0x0f
    } else {
        0
    };
    nonce[0] = priority;
    nonce[1..7].copy_from_slice(&addr2);
    nonce[7..13].copy_from_slice(&pn);

    let addr1: [u8; 6] = data[4..10].try_into().unwrap_or([0u8; 6]);
    let addr3: [u8; 6] = data[16..22].try_into().unwrap_or([0u8; 6]);
    
    let mut aad = Vec::new();
    let fc = data[0];
    let fc1 = data[1];
    aad.push(fc & 0x0f);
    aad.push(fc1 & 0x07);
    aad.extend_from_slice(&addr1);
    aad.extend_from_slice(&addr2);
    aad.extend_from_slice(&addr3);
    
    let seq = u16::from_le_bytes([data[22], data[23]]);
    aad.extend_from_slice(&(seq & 0x000f).to_be_bytes());
    
    if mac_header_len >= 30 {
        let addr4 = data[24..30].try_into().unwrap_or([0u8; 6]);
        aad.extend_from_slice(&addr4);
    }
    if subtype == 8 || subtype == 11 {
        let qos = u16::from_le_bytes([data[mac_header_len - 2], data[mac_header_len - 1]]);
        aad.extend_from_slice(&(qos & 0x000f).to_be_bytes());
    }

    let ciphertext_and_tag = &data[mac_header_len + 8..];
    if ciphertext_and_tag.len() < 8 { return None; }

    let key_ga = GenericArray::from_slice(tk);
    let cipher = AesCcm::new(key_ga);
    cipher.decrypt(GenericArray::from_slice(&nonce), ccm::aead::Payload {
        msg: ciphertext_and_tag,
        aad: &aad,
    }).ok()
}

/// Dissect a radiotap-prefixed 802.11 frame (monitor-mode capture,
/// `DLT_IEEE802_11_RADIO`).
pub fn dissect_radiotap(data: &[u8]) -> DissectedResult {
    match radiotap::parse(data) {
        Some(rt) if rt.header_len <= data.len() => {
            let frame = &data[rt.header_len..];
            dissect_80211(frame, Some(&rt))
        }
        // Not a valid radiotap header — treat the whole buffer as 802.11.
        _ => dissect_80211(data, None),
    }
}

/// Dissect a bare 802.11 frame (`DLT_IEEE802_11`), optionally annotated with
/// radiotap radio metadata.
pub fn dissect_80211(data: &[u8], radio: Option<&radiotap::Radiotap>) -> DissectedResult {
    let unknown = |summary: String| DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Wlan,
        summary,
    };

    if data.len() < 2 {
        return unknown("802.11 (truncated frame)".into());
    }

    let fc = data[0];
    let fc1 = data[1];
    let ftype = (fc >> 2) & 0x03;
    let subtype = (fc >> 4) & 0x0F;
    let protected = (fc1 & 0x40) != 0;

    if ftype == 2 && !protected && data.len() > 24 {
        let mac_header_len = get_mac_header_len(fc, subtype);
        if data.len() > mac_header_len + 8 {
            let payload = &data[mac_header_len..];
            if payload.len() > 8 && payload[0] == 0xaa && payload[1] == 0xaa {
                let ethertype = u16::from_be_bytes([payload[6], payload[7]]);
                if ethertype == 0x888e {
                    let addr1: [u8; 6] = data[4..10].try_into().unwrap_or([0u8; 6]);
                    let addr2: [u8; 6] = data[10..16].try_into().unwrap_or([0u8; 6]);
                    track_eapol_key(addr2, addr1, &payload[8..]);
                }
            }
        }
    }

    let mut decrypted_payload = None;
    if ftype == 2 && protected && data.len() > 24 {
        let mac_header_len = get_mac_header_len(fc, subtype);
        if data.len() > mac_header_len + 8 {
            let addr1: [u8; 6] = data[4..10].try_into().unwrap_or([0u8; 6]);
            let addr2: [u8; 6] = data[10..16].try_into().unwrap_or([0u8; 6]);

            let session_key = if addr2 < addr1 { WlanSessionKey { addr1: addr2, addr2: addr1 } } else { WlanSessionKey { addr1: addr1, addr2: addr2 } };
            let mut tk = TEST_WPA_TK.with(|k| k.borrow().clone())
                .or_else(|| std::env::var("WLAN_WPA_TK").ok())
                .and_then(|tk_str| decode_hex(&tk_str).ok().and_then(|b| b.try_into().ok()));
            
            if tk.is_none() {
                tk = WLAN_SESSIONS.with(|sessions| {
                    sessions.borrow().get(&session_key).and_then(|s| s.tk)
                });
            }
            
            if let Some(key) = tk {
                if let Some(decrypted) = decrypt_ccmp(data, mac_header_len, &key, addr2, subtype) {
                    decrypted_payload = Some(decrypted);
                }
            }
            
            if decrypted_payload.is_none() {
                if data.len() > mac_header_len + 8 {
                    let iv: [u8; 3] = data[mac_header_len..mac_header_len + 3].try_into().unwrap_or([0u8; 3]);
                    let ciphertext = &data[mac_header_len + 4..data.len() - 4];
                    if let Some(decrypted) = decrypt_wep(&iv, ciphertext) {
                        decrypted_payload = Some(decrypted);
                    }
                }
            }
        }
    }

    if let Some(decrypted) = decrypted_payload {
        if decrypted.len() > 8 && decrypted[0] == 0xaa && decrypted[1] == 0xaa {
            let ethertype = u16::from_be_bytes([decrypted[6], decrypted[7]]);
            let ip_payload = &decrypted[8..];
            
            let mut res = if ethertype == 0x0800 {
                super::dispatch_l3(ethertype, ip_payload, 0)
            } else if ethertype == 0x86dd {
                super::dispatch_l3(ethertype, ip_payload, 0)
            } else if ethertype == 0x888e {
                DissectedResult {
                    src_addr: None,
                    dst_addr: None,
                    src_port: None,
                    dst_port: None,
                    protocol: Protocol::Wlan,
                    summary: "EAPOL 4-Way Handshake".to_string(),
                }
            } else {
                DissectedResult {
                    src_addr: None,
                    dst_addr: None,
                    src_port: None,
                    dst_port: None,
                    protocol: Protocol::Wlan,
                    summary: format!("Decrypted payload (EtherType 0x{ethertype:04x})"),
                }
            };
            res.summary = format!("[WLAN Decrypted] {}", res.summary);
            return res;
        }
    }

    let mut summary = match ftype {
        0 => management_summary(data, subtype),
        1 => format!("802.11 {}", control_name(subtype)),
        2 => format!("802.11 {}", data_name(subtype)),
        _ => "802.11 Extension frame".to_string(),
    };

    if let Some(suffix) = radio_suffix(radio) {
        summary.push_str(&suffix);
    }

    unknown(summary)
}

/// Management frames carry a 24-byte header (FC, duration, addr1/2/3, seq).
/// Beacon and probe frames also carry an SSID we surface.
fn management_summary(data: &[u8], subtype: u8) -> String {
    let name = mgmt_name(subtype);

    // BSSID is address 3, at offset 16..22 in the management header.
    let bssid = data
        .get(16..22)
        .map(|b| mac_to_string(&[b[0], b[1], b[2], b[3], b[4], b[5]]));

    match subtype {
        // Beacon (8) and Probe Response (5): fixed params (12 bytes) then tags.
        8 | 5 => match ssid_label(data, 36) {
            Some(ssid) => format!("802.11 {name} — {ssid}"),
            None => match bssid {
                Some(b) => format!("802.11 {name} (BSSID {b})"),
                None => format!("802.11 {name}"),
            },
        },
        // Probe Request (4): tags start right after the 24-byte header.
        4 => match ssid_label(data, 24) {
            Some(ssid) => format!("802.11 {name} — {ssid}"),
            None => format!("802.11 {name}"),
        },
        _ => match bssid {
            Some(b) => format!("802.11 {name} (BSSID {b})"),
            None => format!("802.11 {name}"),
        },
    }
}

/// Read the SSID (tagged parameter id 0) starting at `start`, returning a
/// display label (`"MyWiFi"`, or `<hidden>` for a zero-length SSID).
fn ssid_label(frame: &[u8], start: usize) -> Option<String> {
    let mut i = start;
    while i + 2 <= frame.len() {
        let tag = frame[i];
        let len = frame[i + 1] as usize;
        let val_start = i + 2;
        if val_start + len > frame.len() {
            break;
        }
        if tag == 0 {
            return Some(if len == 0 {
                "<hidden>".to_string()
            } else {
                format!(
                    "\"{}\"",
                    String::from_utf8_lossy(&frame[val_start..val_start + len])
                )
            });
        }
        i = val_start + len;
    }
    None
}

fn radio_suffix(radio: Option<&radiotap::Radiotap>) -> Option<String> {
    let rt = radio?;
    let mut parts = Vec::new();
    if let Some(sig) = rt.signal_dbm {
        parts.push(format!("{sig} dBm"));
    }
    if let Some(ch) = rt.channel_mhz {
        parts.push(format!("{ch} MHz"));
    }
    if parts.is_empty() {
        None
    } else {
        Some(format!(" · {}", parts.join(" · ")))
    }
}

fn mgmt_name(subtype: u8) -> &'static str {
    match subtype {
        0 => "Association Request",
        1 => "Association Response",
        2 => "Reassociation Request",
        3 => "Reassociation Response",
        4 => "Probe Request",
        5 => "Probe Response",
        8 => "Beacon",
        9 => "ATIM",
        10 => "Disassociation",
        11 => "Authentication",
        12 => "Deauthentication",
        13 => "Action",
        _ => "Management",
    }
}

fn control_name(subtype: u8) -> &'static str {
    match subtype {
        8 => "Block Ack Request",
        9 => "Block Ack",
        10 => "PS-Poll",
        11 => "RTS",
        12 => "CTS",
        13 => "ACK",
        14 => "CF-End",
        _ => "Control",
    }
}

fn data_name(subtype: u8) -> &'static str {
    match subtype {
        0 => "Data",
        4 => "Null (no data)",
        8 => "QoS Data",
        12 => "QoS Null",
        _ => "Data",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a management frame header (24 bytes) with a given subtype and
    /// BSSID, plus an optional body.
    fn mgmt_frame(subtype: u8, body: &[u8]) -> Vec<u8> {
        let fc0 = subtype << 4; // type 0 (management), version 0
        let mut f = vec![fc0, 0x00]; // frame control
        f.extend_from_slice(&[0x00, 0x00]); // duration
        f.extend_from_slice(&[0xff; 6]); // addr1 (DA)
        f.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // addr2 (SA)
        f.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // addr3 (BSSID)
        f.extend_from_slice(&[0x00, 0x00]); // seq ctl
        f.extend_from_slice(body);
        f
    }

    fn beacon_body(ssid: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 12]; // timestamp(8) + interval(2) + caps(2)
        b.push(0x00); // SSID tag id
        b.push(ssid.len() as u8);
        b.extend_from_slice(ssid);
        b
    }

    #[test]
    fn beacon_with_ssid() {
        let frame = mgmt_frame(8, &beacon_body(b"MyWiFi"));
        let r = dissect_80211(&frame, None);
        assert_eq!(r.protocol, Protocol::Wlan);
        assert_eq!(r.summary, "802.11 Beacon — \"MyWiFi\"");
    }

    #[test]
    fn hidden_ssid_beacon() {
        let frame = mgmt_frame(8, &beacon_body(b""));
        let r = dissect_80211(&frame, None);
        assert_eq!(r.summary, "802.11 Beacon — <hidden>");
    }

    #[test]
    fn probe_request_ssid() {
        // Probe Request (subtype 4): tags right after the 24-byte header.
        let mut body = vec![0x00, 6];
        body.extend_from_slice(b"coffee");
        let frame = mgmt_frame(4, &body);
        let r = dissect_80211(&frame, None);
        assert_eq!(r.summary, "802.11 Probe Request — \"coffee\"");
    }

    #[test]
    fn deauth_names_and_bssid() {
        let frame = mgmt_frame(12, &[]);
        let r = dissect_80211(&frame, None);
        assert_eq!(
            r.summary,
            "802.11 Deauthentication (BSSID aa:bb:cc:dd:ee:ff)"
        );
    }

    #[test]
    fn control_ack() {
        // Control (type 1), subtype 13 (ACK): fc0 = (13<<4)|(1<<2) = 0xD4
        let frame = [0xD4, 0x00, 0x00, 0x00];
        let r = dissect_80211(&frame, None);
        assert_eq!(r.summary, "802.11 ACK");
    }

    #[test]
    fn data_qos() {
        // Data (type 2), subtype 8 (QoS Data): fc0 = (8<<4)|(2<<2) = 0x88
        let frame = mgmt_frame(0, &[]); // reuse header shape
        let mut f = frame;
        f[0] = 0x88;
        let r = dissect_80211(&f, None);
        assert_eq!(r.summary, "802.11 QoS Data");
    }

    #[test]
    fn radiotap_suffix_appended() {
        let rt = radiotap::Radiotap {
            header_len: 0,
            signal_dbm: Some(-42),
            channel_mhz: Some(2412),
        };
        let frame = mgmt_frame(8, &beacon_body(b"Net"));
        let r = dissect_80211(&frame, Some(&rt));
        assert_eq!(r.summary, "802.11 Beacon — \"Net\" · -42 dBm · 2412 MHz");
    }

    #[test]
    fn truncated_frame() {
        let r = dissect_80211(&[0x80], None);
        assert_eq!(r.protocol, Protocol::Wlan);
        assert!(r.summary.contains("truncated"));
    }

    #[test]
    fn test_wep_decryption() {
        clear_wlan_sessions();
        TEST_WEP_KEY.with(|k| *k.borrow_mut() = Some("mywepkey".to_string()));
        
        let iv = [0x01, 0x02, 0x03];
        let mut plaintext = vec![0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 1, 10, 0, 0, 2];
        plaintext.extend_from_slice(&[0; 4]);
        
        let mut key = vec![0x01, 0x02, 0x03];
        key.extend_from_slice(b"mywepkey");
        
        let ciphertext = rc4_decrypt(&key, &plaintext);
        
        let mut frame = vec![0x08, 0x40];
        frame.extend_from_slice(&[0, 0]);
        frame.extend_from_slice(&[0xff; 6]);
        frame.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        frame.extend_from_slice(&[0, 0]);
        
        frame.extend_from_slice(&iv);
        frame.push(0);
        frame.extend_from_slice(&ciphertext);
        frame.extend_from_slice(&[0, 0, 0, 0]);
        
        let res = dissect_80211(&frame, None);
        assert!(res.summary.contains("[WLAN Decrypted]"));
        assert!(res.summary.contains("TCP"));
    }

    #[test]
    fn test_wpa2_ccmp_decryption() {
        clear_wlan_sessions();
        let tk = [0x55u8; 16];
        let tk_hex = "55555555555555555555555555555555";
        TEST_WPA_TK.with(|k| *k.borrow_mut() = Some(tk_hex.to_string()));
        
        let plaintext = vec![
            0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x3c, 0xce, 10, 0, 0, 1, 10, 0, 0, 2
        ];
        
        let addr1 = [0x02u8; 6];
        let addr2 = [0x01u8; 6];
        let addr3 = [0x03u8; 6];
        
        let pn = [0, 0, 0, 0, 0, 1];
        let mut nonce = [0u8; 13];
        nonce[0] = 0;
        nonce[1..7].copy_from_slice(&addr2);
        nonce[7..13].copy_from_slice(&pn);
        
        let mut aad = Vec::new();
        aad.push(0x08 & 0x0f);
        aad.push(0);
        aad.extend_from_slice(&addr1);
        aad.extend_from_slice(&addr2);
        aad.extend_from_slice(&addr3);
        aad.extend_from_slice(&[0, 0]);
        
        use ccm::{Ccm, consts::{U8, U13}};
        use ccm::aead::{Aead, KeyInit, generic_array::GenericArray};
        type AesCcm = Ccm<aes_gcm::aes::Aes128, U8, U13>;
        
        let key_ga = GenericArray::from_slice(&tk);
        let cipher = AesCcm::new(key_ga);
        let ciphertext_and_tag = cipher.encrypt(GenericArray::from_slice(&nonce), ccm::aead::Payload {
            msg: &plaintext,
            aad: &aad,
        }).unwrap();
        
        let mut frame = vec![0x08, 0x40];
        frame.extend_from_slice(&[0, 0]);
        frame.extend_from_slice(&addr1);
        frame.extend_from_slice(&addr2);
        frame.extend_from_slice(&addr3);
        frame.extend_from_slice(&[0, 0]);
        
        frame.extend_from_slice(&[1, 0, 0, 0x20, 0, 0, 0, 0]);
        frame.extend_from_slice(&ciphertext_and_tag);
        
        let res = dissect_80211(&frame, None);
        assert!(res.summary.contains("[WLAN Decrypted]"));
        assert!(res.summary.contains("TCP"));
    }
}
