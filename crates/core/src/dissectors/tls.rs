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
    let summary = if let Some(h) = parse_client_hello(payload) {
        // A ClientHello: surface the SNI plus the JA3 and JA4 fingerprints,
        // which downstream tooling and threat feeds match against even when the
        // rest of the session is encrypted (ROADMAP §5.2). This runs over TCP,
        // so the JA4 transport nibble is always `t`.
        let ja3 = ja3_hash(&h);
        let ja4 = ja4(&h, 't');
        match &h.sni {
            Some(host) => format!("TLS ClientHello — {host} · JA4 {ja4} · JA3 {ja3}"),
            None => format!("TLS ClientHello (no SNI) · JA4 {ja4} · JA3 {ja3}"),
        }
    } else if let Some(s) = parse_server_hello(payload) {
        // A ServerHello: JA3S fingerprints the server's response (chosen cipher
        // + extensions), pairing with the client JA3 for beacon detection.
        format!("TLS ServerHello · JA3S {}", ja3s_hash(&s))
    } else {
        // Not a hello — a handshake continuation or encrypted record.
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
    c.skip(32)?; // random

    let session_id_len = c.u8()? as usize;
    c.skip(session_id_len)?;

    let cipher_suite = c.u16()?; // the single chosen suite
    c.skip(1)?; // compression method

    let mut server = ServerHello {
        version,
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
}
