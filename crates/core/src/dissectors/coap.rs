use std::net::IpAddr;

use crate::models::Protocol;

use super::{truncate, DissectedResult};

/// Dissect a CoAP message (UDP 5683).
///
/// CoAP is "HTTP for constrained devices" — a compact request/response protocol
/// for low-power IoT sensors. The 4-byte header packs version(2 bits), type(2),
/// token length(4), then a code byte (class.detail, e.g. 0.01 = GET, 2.05 =
/// Content) and a 16-bit message id. Options follow in a delta-encoded TLV form;
/// we walk them just far enough to reconstruct the Uri-Path. The result reads
/// much like an HTTP request line — GET /sensors/temp — which is the point.
pub fn dissect_coap(
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
        protocol: Protocol::Coap,
        summary,
    };

    if payload.len() < 4 || payload[0] >> 6 != 1 {
        return result("CoAP (partial)".into());
    }

    let type_bits = (payload[0] >> 4) & 0x03;
    let token_len = (payload[0] & 0x0f) as usize;
    let code = payload[1];
    let msg_id = u16::from_be_bytes([payload[2], payload[3]]);

    let type_name = match type_bits {
        0 => "CON",
        1 => "NON",
        2 => "ACK",
        3 => "RST",
        _ => "?",
    };

    let code_str = code_name(code);
    let path = uri_path(payload, token_len);
    let mut summary = format!("CoAP {type_name} {code_str}");
    if let Some(p) = path {
        if !p.is_empty() {
            summary.push(' ');
            summary.push_str(&truncate(&p, 50));
        }
    }
    summary.push_str(&format!(" (mid {msg_id})"));
    result(summary)
}

/// Render a CoAP code byte: the top 3 bits are the class, the low 5 the detail.
/// Class 0 requests are named methods; other classes read as "class.detail".
fn code_name(code: u8) -> String {
    let class = code >> 5;
    let detail = code & 0x1f;
    match (class, detail) {
        (0, 0) => "Empty".to_string(),
        (0, 1) => "GET".to_string(),
        (0, 2) => "POST".to_string(),
        (0, 3) => "PUT".to_string(),
        (0, 4) => "DELETE".to_string(),
        _ => format!("{class}.{detail:02}"),
    }
}

/// Walk the option TLVs to reconstruct the Uri-Path (option number 11), joining
/// the segments with '/'. Returns None if there are no path options.
fn uri_path(payload: &[u8], token_len: usize) -> Option<String> {
    let mut i = 4 + token_len; // skip header + token
    let mut option_number = 0u16;
    let mut segments: Vec<String> = Vec::new();

    while i < payload.len() {
        let b = payload[i];
        if b == 0xff {
            break; // payload marker
        }
        i += 1;
        let mut delta = (b >> 4) as u16;
        let mut length = (b & 0x0f) as usize;

        // Extended delta / length encodings (13 = 1 byte, 14 = 2 bytes).
        delta = match delta {
            13 => {
                let v = *payload.get(i)? as u16 + 13;
                i += 1;
                v
            }
            14 => {
                let v = u16::from_be_bytes([*payload.get(i)?, *payload.get(i + 1)?]) + 269;
                i += 2;
                v
            }
            15 => return join_segments(segments),
            v => v,
        };
        length = match length {
            13 => {
                let v = *payload.get(i)? as usize + 13;
                i += 1;
                v
            }
            14 => {
                let v = u16::from_be_bytes([*payload.get(i)?, *payload.get(i + 1)?]) as usize + 269;
                i += 2;
                v
            }
            15 => return join_segments(segments),
            v => v,
        };

        option_number += delta;
        let value = payload.get(i..i + length)?;
        i += length;

        if option_number == 11 {
            segments.push(String::from_utf8_lossy(value).to_string());
        }
    }

    join_segments(segments)
}

fn join_segments(segments: Vec<String>) -> Option<String> {
    if segments.is_empty() {
        None
    } else {
        Some(format!("/{}", segments.join("/")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_with_uri_path() {
        // Version 1, type CON (0), token length 0; code 0.01 (GET); msg id 1.
        let mut p = vec![0x40, 0x01, 0x00, 0x01];
        // Option 11 (Uri-Path) "sensors": delta 11 (>12 → use 13 ext), length 7.
        // delta 11 fits in 4 bits, so nibble = 0xB; length 7 = 0x7 → byte 0xB7.
        p.push(0xB7);
        p.extend_from_slice(b"sensors");
        // Next Uri-Path "temp": delta 0 (same option), length 4 → 0x04.
        p.push(0x04);
        p.extend_from_slice(b"temp");

        let r = dissect_coap(None, None, 50000, 5683, &p);
        assert_eq!(r.protocol, Protocol::Coap);
        assert_eq!(r.summary, "CoAP CON GET /sensors/temp (mid 1)");
    }

    #[test]
    fn content_response() {
        // type ACK (2), code 2.05 (Content = class 2, detail 5 → 0x45), mid 1.
        let p = vec![0x60, 0x45, 0x00, 0x01];
        let r = dissect_coap(None, None, 5683, 50000, &p);
        assert_eq!(r.summary, "CoAP ACK 2.05 (mid 1)");
    }

    #[test]
    fn partial_is_safe() {
        let r = dissect_coap(None, None, 5683, 50000, &[0x40, 0x01]);
        assert!(r.summary.contains("partial"));
    }
}
