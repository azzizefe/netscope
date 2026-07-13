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
    let hello = parse_client_hello(payload);

    let summary = match &hello {
        Some(h) => {
            // A ClientHello: surface the SNI (if any) plus the JA3 fingerprint,
            // which downstream tooling and threat feeds match against even when
            // the rest of the session is encrypted (ROADMAP §5.2).
            let ja3 = ja3_hash(h);
            match &h.sni {
                Some(host) => format!("TLS ClientHello — {host} · JA3 {ja3}"),
                None => format!("TLS ClientHello (no SNI) · JA3 {ja3}"),
            }
        }
        None => {
            // Not a ClientHello — a handshake continuation or encrypted record.
            if payload.len() > 5 && payload[0] == 0x16 && payload[1] == 0x03 {
                "TLS Handshake".into()
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

/// The fields of a TLS ClientHello that a JA3 fingerprint is computed from,
/// plus the SNI for display.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientHello {
    /// `legacy_version` from the handshake body (e.g. 0x0303 for TLS 1.2).
    pub version: u16,
    /// Offered cipher suites, in order, GREASE values retained (the JA3
    /// builder filters them).
    pub cipher_suites: Vec<u16>,
    /// Extension types, in the order they appear.
    pub extensions: Vec<u16>,
    /// `supported_groups` extension (0x000a) — the elliptic curves.
    pub supported_groups: Vec<u16>,
    /// `ec_point_formats` extension (0x000b).
    pub ec_point_formats: Vec<u8>,
    /// Server Name Indication host, if present.
    pub sni: Option<String>,
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
    c.skip(32)?; // random

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
            _ => {}
        }
        c.pos = body_start + ext_len;
    }

    Some(hello)
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
    use md5::{Digest, Md5};
    let mut hasher = Md5::new();
    hasher.update(ja3_string(h).as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(32);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
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
        assert_eq!(h.extensions, vec![0x0000, 0x000a, 0x000b]);
        assert_eq!(h.supported_groups, vec![0x001d]);
        assert_eq!(h.ec_point_formats, vec![0x00]);
        assert_eq!(h.sni.as_deref(), Some("github.com"));
    }

    #[test]
    fn grease_is_stripped_and_ja3_string_is_exact() {
        let data = build_client_hello_with_sni("github.com");
        let h = parse_client_hello(&data).unwrap();
        // Version 771; cipher GREASE 0x1a1a dropped leaving 47; extensions
        // 0,10,11; curve 29; point format 0.
        assert_eq!(ja3_string(&h), "771,47,0-10-11,29,0");
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
    fn dissect_reports_sni_and_ja3() {
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
            .starts_with("TLS ClientHello — github.com · JA3 "));
        // The JA3 in the summary matches the computed hash.
        let h = parse_client_hello(&data).unwrap();
        assert!(result.summary.ends_with(&ja3_hash(&h)));
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
        let full = build_client_hello_with_sni("example.org");
        // Every prefix of a real ClientHello must parse to Some/None without
        // panicking (fuzzing the length-prefix bounds checks).
        for cut in 0..full.len() {
            let _ = parse_client_hello(&full[..cut]);
            let _ = dissect_tls(None, None, 1, 443, &full[..cut]);
        }
    }
}
