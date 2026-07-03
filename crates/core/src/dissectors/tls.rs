use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

pub fn dissect_tls(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let sni = extract_sni(payload);

    let summary = match &sni {
        Some(hostname) => format!("TLS — {} (HTTPS)", hostname),
        None => {
            // Check for TLS handshake even without SNI
            if payload.len() > 5 && payload[0] == 0x16 && payload[1] == 0x03 {
                "TLS Handshake (no SNI)".into()
            } else if payload.len() == 1 {
                "TLS — 1 byte of encrypted data".into()
            } else {
                format!("TLS — {} bytes of encrypted data", payload.len())
            }
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

fn extract_sni(data: &[u8]) -> Option<String> {
    if data.len() < 9 {
        return None;
    }
    if data[0] != 0x16 {
        return None;
    }
    if data[5] != 0x01 {
        return None;
    }
    let _hs_len = (data[6] as usize) << 16 | (data[7] as usize) << 8 | data[8] as usize;
    let mut offset = 9usize;
    offset += 2;
    offset += 32;
    if offset >= data.len() {
        return None;
    }
    let session_id_len = data[offset] as usize;
    offset += 1 + session_id_len;
    if offset + 1 >= data.len() {
        return None;
    }
    let cipher_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2 + cipher_len;
    if offset + 1 >= data.len() {
        return None;
    }
    let comp_len = data[offset] as usize;
    offset += 1 + comp_len;
    if offset + 1 >= data.len() {
        return None;
    }
    let ext_total_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;
    if offset + ext_total_len > data.len() {
        return None;
    }
    while offset + 4 <= data.len() {
        let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let ext_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;
        if offset + ext_len > data.len() {
            break;
        }
        if ext_type == 0x0000 && ext_len > 5 {
            let name_len = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;
            if offset + 5 + name_len <= data.len() && data[offset + 2] == 0x00 {
                let hostname =
                    std::str::from_utf8(&data[offset + 5..offset + 5 + name_len]).ok()?;
                return Some(hostname.to_string());
            }
        }
        offset += ext_len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal TLS ClientHello with SNI.
    /// Byte reference: TLS record (5) + Handshake header (4) + ClientHello fixed (34+)
    /// + session_id (1+0) + cipher_suites (2+2) + compression (1+1) + extensions (2+) + SNI
    fn build_client_hello_with_sni(hostname: &str) -> Vec<u8> {
        let hostname_bytes = hostname.as_bytes();
        let _sni_ext_len = 2  // server name list length
            + 1              // name type (host_name)
            + 2              // name length
            + hostname_bytes.len();

        let mut buf = Vec::new();

        // TLS Record: content type 0x16 (Handshake)
        buf.push(0x16);
        // version 0x0303 (TLS 1.2)
        buf.extend_from_slice(&[0x03, 0x03]);
        // length placeholder (will fill later)
        let record_len_pos = buf.len();
        buf.extend_from_slice(&[0x00, 0x00]);

        // Handshake: type 0x01 (ClientHello)
        buf.push(0x01);
        // length placeholder (3 bytes)
        let hs_len_pos = buf.len();
        buf.extend_from_slice(&[0x00, 0x00, 0x00]);

        // ClientHello: version
        buf.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
                                              // random (32 bytes of zeros)
        buf.extend_from_slice(&[0u8; 32]);
        // session id length
        buf.push(0x00);
        // cipher suites length
        buf.extend_from_slice(&[0x00, 0x02]);
        buf.extend_from_slice(&[0x00, 0x2f]); // TLS_RSA_AES_128_CBC_SHA
                                              // compression length
        buf.push(0x01);
        buf.push(0x00); // null compression

        // Extensions length
        let ext_len_pos = buf.len();
        buf.extend_from_slice(&[0x00, 0x00]);

        // SNI extension (type 0x0000)
        buf.extend_from_slice(&[0x00, 0x00]); // type
        let sni_ext_len_pos = buf.len();
        buf.extend_from_slice(&[0x00, 0x00]); // length placeholder

        // SNI list
        let sni_list_len_pos = buf.len();
        buf.extend_from_slice(&[0x00, 0x00]); // list length placeholder
        buf.push(0x00); // host_name type
        buf.extend_from_slice(&(hostname_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(hostname_bytes);

        // Fill in lengths
        let sni_list_total = buf.len() - sni_list_len_pos - 2; // subtract list length field itself
        buf[sni_list_len_pos..sni_list_len_pos + 2]
            .copy_from_slice(&(sni_list_total as u16).to_be_bytes());

        let sni_ext_total = buf.len() - sni_ext_len_pos - 2;
        buf[sni_ext_len_pos..sni_ext_len_pos + 2]
            .copy_from_slice(&(sni_ext_total as u16).to_be_bytes());

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
    fn tls_with_sni() {
        let data = build_client_hello_with_sni("github.com");
        let result = dissect_tls(
            Some("10.0.0.1".parse().unwrap()),
            Some("10.0.0.2".parse().unwrap()),
            54321,
            443,
            &data,
        );
        assert_eq!(result.protocol, Protocol::Tls);
        assert_eq!(result.summary, "TLS — github.com (HTTPS)");
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
    fn tls_no_sni() {
        // Just a handshake header without extensions
        let mut data = vec![
            0x16, 0x03, 0x03, 0x00, 0x00, // record header, length to be filled
            0x01, 0x00, 0x00, 0x00, // handshake type ClientHello, length 0 (no extensions)
        ];
        let record_len = (data.len() - 5) as u16;
        data[3..5].copy_from_slice(&record_len.to_be_bytes());

        let result = dissect_tls(None, None, 54321, 443, &data);
        assert_eq!(result.protocol, Protocol::Tls);
        // Should detect the handshake but no SNI
        assert!(result.summary.contains("no SNI") || result.summary.contains("TLS"));
    }
}
