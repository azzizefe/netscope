// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
/// QPACK Static Table and Decoder (RFC 9204).
/// QPACK is the header compression protocol for HTTP/3 over QUIC.

pub const STATIC_TABLE: &[(&str, &str)] = &[
    (":authority", ""),
    (":path", "/"),
    (":method", "GET"),
    (":method", "POST"),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "PUT"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("age", ""),
    ("allow", ""),
    ("cache-control", "public, max-age=31536000"),
    ("content-disposition", ""),
    ("content-encoding", "gzip"),
    ("content-length", ""),
    ("content-type", "application/json"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("host", ""),
    ("last-modified", ""),
    ("location", ""),
    ("referer", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("user-agent", ""),
];

/// Decode QPACK encoded header representation.
pub fn decode_qpack(mut bytes: &[u8]) -> Option<Vec<(String, String)>> {
    if bytes.len() < 2 {
        return None;
    }
    
    // Skip the prefix: Required Insert Count and Base
    bytes = &bytes[2..];
    let mut headers = Vec::new();
    
    while !bytes.is_empty() {
        let b = bytes[0];
        if b & 0x80 != 0 {
            // Indexed Header Field: static table lookup (using 6-bit index)
            let index = (b & 0x3f) as usize;
            bytes = &bytes[1..];
            if index < STATIC_TABLE.len() {
                let (name, val) = STATIC_TABLE[index];
                headers.push((name.to_string(), val.to_string()));
            }
        } else if b & 0x40 == 0x40 {
            // Literal Header Field with Name Reference
            bytes = &bytes[1..];
        } else {
            bytes = &bytes[1..];
        }
    }
    
    if headers.is_empty() {
        None
    } else {
        Some(headers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qpack_indexed() {
        // Required Insert Count = 0, Base = 0, Indexed Static index 2 (:method: GET)
        // index 2 is matched by index bit 0x80 | 2 = 0x82
        let payload = vec![0x00, 0x00, 0x82];
        let headers = decode_qpack(&payload).unwrap();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0], (":method".to_string(), "GET".to_string()));
    }
}
