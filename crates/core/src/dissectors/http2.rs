// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! HTTP/2 (RFC 9113) cleartext frames + gRPC detection.
//!
//! Like WebSocket, HTTP/2 has no port of its own in the clear: h2c runs on 80,
//! 8080, or wherever the server listens, and gRPC servers default to 50051 but
//! use anything. netscope's dissection is stateless per packet, so instead of
//! tracking the connection we *validate*: a TCP payload is reported as HTTP/2
//! only when it starts with the client connection preface, or parses as a
//! complete, well-formed chain of frames (known types, per-type flag/length/
//! stream-id rules, reserved bit zero). Random data passes those checks only
//! rarely.
//!
//! HTTP/2 over TLS (`h2` via ALPN) is encrypted and stays `Protocol::Tls` —
//! netscope can't see inside it, and neither can Wireshark without keys.
//!
//! gRPC rides on HTTP/2 and is recognised two ways:
//! - a HEADERS/CONTINUATION block carrying `content-type: application/grpc`
//!   (matched raw or in its HPACK-Huffman encoding — the Huffman bytes of a
//!   fixed string are a fixed byte sequence, no decoder needed);
//! - a DATA frame whose payload is exactly one or more complete gRPC
//!   length-prefixed messages (1-byte compressed flag + 4-byte length).

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Client connection preface (RFC 9113 §3.4) — sent before the first frame.
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// Frame types (RFC 9113 §6).
const FT_DATA: u8 = 0x0;
const FT_HEADERS: u8 = 0x1;
const FT_PRIORITY: u8 = 0x2;
const FT_RST_STREAM: u8 = 0x3;
const FT_SETTINGS: u8 = 0x4;
const FT_PUSH_PROMISE: u8 = 0x5;
const FT_PING: u8 = 0x6;
const FT_GOAWAY: u8 = 0x7;
const FT_WINDOW_UPDATE: u8 = 0x8;
const FT_CONTINUATION: u8 = 0x9;

// Frame flags (RFC 9113 §6, per frame type).
const F_ACK: u8 = 0x1; // SETTINGS, PING
const F_END_STREAM: u8 = 0x1; // DATA, HEADERS
const F_END_HEADERS: u8 = 0x4; // HEADERS, PUSH_PROMISE, CONTINUATION
const F_PADDED: u8 = 0x8; // DATA, HEADERS, PUSH_PROMISE
const F_PRIORITY: u8 = 0x20; // HEADERS

/// `content-type: application/grpc` markers inside a HEADERS block. The
/// Huffman form is the HPACK encoding of `"application/grpc"` (RFC 7541
/// Appendix B); its 88 bits end on a byte boundary, so the same 11 bytes are
/// also the prefix of `application/grpc+proto`, `application/grpc-web`, etc.
const GRPC_CT_RAW: &[u8] = b"application/grpc";
const GRPC_CT_HUFFMAN: &[u8] = &[
    0x1d, 0x75, 0xd0, 0x62, 0x0d, 0x26, 0x3d, 0x4c, 0x4d, 0x65, 0x64,
];

#[derive(Debug)]
struct Frame<'a> {
    typ: u8,
    flags: u8,
    stream_id: u32,
    /// Declared payload length from the 24-bit header field.
    declared_len: usize,
    /// Payload bytes present in this TCP segment (may be truncated when the
    /// frame spans segments).
    payload: &'a [u8],
    /// Whether the whole declared payload is present in this segment.
    complete: bool,
}

/// Per-type validity rules (RFC 9113 §6): who may carry which flags, which
/// stream ids are legal, and which lengths are fixed. This is what separates
/// real HTTP/2 from random bytes that happen to have a small type octet.
fn frame_valid(typ: u8, flags: u8, stream_id: u32, len: usize) -> bool {
    match typ {
        FT_DATA => stream_id != 0 && flags & !(F_END_STREAM | F_PADDED) == 0,
        FT_HEADERS => {
            stream_id != 0 && flags & !(F_END_STREAM | F_END_HEADERS | F_PADDED | F_PRIORITY) == 0
        }
        FT_PRIORITY => stream_id != 0 && len == 5 && flags == 0,
        FT_RST_STREAM => stream_id != 0 && len == 4 && flags == 0,
        FT_SETTINGS => {
            stream_id == 0
                && flags & !F_ACK == 0
                && if flags & F_ACK != 0 {
                    len == 0
                } else {
                    len.is_multiple_of(6)
                }
        }
        FT_PUSH_PROMISE => stream_id != 0 && flags & !(F_END_HEADERS | F_PADDED) == 0 && len >= 4,
        FT_PING => stream_id == 0 && len == 8 && flags & !F_ACK == 0,
        FT_GOAWAY => stream_id == 0 && len >= 8 && flags == 0,
        FT_WINDOW_UPDATE => len == 4 && flags == 0,
        FT_CONTINUATION => stream_id != 0 && flags & !F_END_HEADERS == 0,
        _ => false,
    }
}

/// Parse one frame at `b[0..]`. Returns `None` unless the 9-byte header is
/// present and passes the strict per-type rules.
fn parse_frame(b: &[u8]) -> Option<Frame<'_>> {
    if b.len() < 9 {
        return None;
    }
    let declared_len = usize::from(b[0]) << 16 | usize::from(b[1]) << 8 | usize::from(b[2]);
    let typ = b[3];
    let flags = b[4];
    let stream_id = u32::from_be_bytes([b[5], b[6], b[7], b[8]]);
    if stream_id & 0x8000_0000 != 0 {
        return None; // reserved bit must be 0
    }
    if !frame_valid(typ, flags, stream_id, declared_len) {
        return None;
    }
    let avail = b.len() - 9;
    let take = declared_len.min(avail);
    Some(Frame {
        typ,
        flags,
        stream_id,
        declared_len,
        payload: &b[9..9 + take],
        complete: declared_len <= avail,
    })
}

/// Parse the segment as a chain of frames starting at offset 0. Accepts only
/// two shapes: every frame complete and the chain consuming the segment
/// exactly, or a final frame whose payload continues in the next segment.
fn parse_chain(payload: &[u8]) -> Option<Vec<Frame<'_>>> {
    let mut frames = Vec::new();
    let mut off = 0usize;
    while off < payload.len() {
        let frame = parse_frame(&payload[off..])?;
        let complete = frame.complete;
        off += 9 + frame.payload.len();
        frames.push(frame);
        if !complete {
            return Some(frames); // truncated frame: valid only as the tail
        }
    }
    (!frames.is_empty()).then_some(frames)
}

fn type_name(typ: u8) -> &'static str {
    match typ {
        FT_DATA => "DATA",
        FT_HEADERS => "HEADERS",
        FT_PRIORITY => "PRIORITY",
        FT_RST_STREAM => "RST_STREAM",
        FT_SETTINGS => "SETTINGS",
        FT_PUSH_PROMISE => "PUSH_PROMISE",
        FT_PING => "PING",
        FT_GOAWAY => "GOAWAY",
        FT_WINDOW_UPDATE => "WINDOW_UPDATE",
        FT_CONTINUATION => "CONTINUATION",
        _ => "?",
    }
}

/// Error code names (RFC 9113 §7), used by RST_STREAM and GOAWAY.
fn error_name(code: u32) -> &'static str {
    match code {
        0 => "NO_ERROR",
        1 => "PROTOCOL_ERROR",
        2 => "INTERNAL_ERROR",
        3 => "FLOW_CONTROL_ERROR",
        4 => "SETTINGS_TIMEOUT",
        5 => "STREAM_CLOSED",
        6 => "FRAME_SIZE_ERROR",
        7 => "REFUSED_STREAM",
        8 => "CANCEL",
        9 => "COMPRESSION_ERROR",
        10 => "CONNECT_ERROR",
        11 => "ENHANCE_YOUR_CALM",
        12 => "INADEQUATE_SECURITY",
        13 => "HTTP_1_1_REQUIRED",
        _ => "unknown error",
    }
}

/// One or more complete gRPC length-prefixed messages (1-byte compressed
/// flag + 4-byte big-endian length) filling `data` exactly.
struct GrpcMessages {
    count: usize,
    bytes: u64,
    compressed: bool,
}

fn grpc_messages(data: &[u8]) -> Option<GrpcMessages> {
    let mut off = 0usize;
    let mut out = GrpcMessages {
        count: 0,
        bytes: 0,
        compressed: false,
    };
    while off < data.len() {
        let flag = *data.get(off)?;
        if flag > 1 {
            return None;
        }
        let len = u32::from_be_bytes([
            *data.get(off + 1)?,
            *data.get(off + 2)?,
            *data.get(off + 3)?,
            *data.get(off + 4)?,
        ]) as usize;
        off = off.checked_add(5 + len)?;
        if off > data.len() {
            return None; // partial message — not confident enough to claim gRPC
        }
        out.count += 1;
        out.bytes += len as u64;
        out.compressed |= flag == 1;
    }
    (out.count > 0).then_some(out)
}

/// Does this HEADERS/CONTINUATION block carry `content-type: application/grpc`?
fn headers_mention_grpc(block: &[u8]) -> bool {
    contains(block, GRPC_CT_RAW) || contains(block, GRPC_CT_HUFFMAN)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn describe(frame: &Frame) -> String {
    let cont = if frame.complete { "" } else { ", continues" };
    match frame.typ {
        FT_DATA => format!(
            "DATA — {} bytes on stream {}{cont}",
            frame.declared_len, frame.stream_id
        ),
        FT_SETTINGS => {
            if frame.flags & F_ACK != 0 {
                "SETTINGS ACK".into()
            } else {
                format!("SETTINGS — {} parameters", frame.declared_len / 6)
            }
        }
        FT_PING => {
            if frame.flags & F_ACK != 0 {
                "PING ACK".into()
            } else {
                "PING".into()
            }
        }
        FT_RST_STREAM if frame.payload.len() >= 4 => {
            let code = u32::from_be_bytes([
                frame.payload[0],
                frame.payload[1],
                frame.payload[2],
                frame.payload[3],
            ]);
            format!(
                "RST_STREAM {} — stream {}",
                error_name(code),
                frame.stream_id
            )
        }
        FT_GOAWAY if frame.payload.len() >= 8 => {
            let code = u32::from_be_bytes([
                frame.payload[4],
                frame.payload[5],
                frame.payload[6],
                frame.payload[7],
            ]);
            format!("GOAWAY — {}", error_name(code))
        }
        FT_WINDOW_UPDATE if frame.payload.len() >= 4 => {
            let inc = u32::from_be_bytes([
                frame.payload[0],
                frame.payload[1],
                frame.payload[2],
                frame.payload[3],
            ]) & 0x7fff_ffff;
            format!("WINDOW_UPDATE +{inc}")
        }
        FT_HEADERS | FT_PUSH_PROMISE | FT_CONTINUATION | FT_PRIORITY => {
            format!(
                "{} — stream {}{cont}",
                type_name(frame.typ),
                frame.stream_id
            )
        }
        typ => format!("{} — stream {}{cont}", type_name(typ), frame.stream_id),
    }
}

/// Try to dissect a TCP payload as HTTP/2 (and, within it, gRPC). Returns
/// `None` when the bytes don't validate — the caller falls through to its
/// generic TCP summary.
pub fn try_dissect(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<DissectedResult> {
    let (frames, preface) = match payload.strip_prefix(PREFACE) {
        // The preface is definitive HTTP/2 even if the rest of the segment
        // doesn't parse (e.g. a frame header split across segments).
        Some(rest) => (parse_chain(rest).unwrap_or_default(), true),
        None => (parse_chain(payload)?, false),
    };

    // gRPC: content-type in a header block, or DATA carrying exact messages.
    let grpc_headers = frames
        .iter()
        .any(|f| matches!(f.typ, FT_HEADERS | FT_CONTINUATION) && headers_mention_grpc(f.payload));
    let grpc_data = frames
        .iter()
        .filter(|f| f.typ == FT_DATA && f.complete)
        .find_map(|f| grpc_messages(f.payload).map(|m| (f.stream_id, m)));

    let (protocol, mut summary) = if grpc_headers {
        let sid = frames
            .iter()
            .find(|f| matches!(f.typ, FT_HEADERS | FT_CONTINUATION))
            .map(|f| f.stream_id)
            .unwrap_or(0);
        (
            Protocol::Grpc,
            format!("gRPC headers (application/grpc) — stream {sid}"),
        )
    } else if let Some((sid, m)) = grpc_data {
        let comp = if m.compressed {
            "compressed"
        } else {
            "uncompressed"
        };
        let count = if m.count > 1 {
            format!("{} messages", m.count)
        } else {
            "message".into()
        };
        // Try decoding the first message heuristically
        let proto_desc = frames
            .iter()
            .filter(|f| f.typ == FT_DATA && f.complete)
            .find_map(|f| decode_grpc_payload(f.payload));
        let details = if let Some(p) = proto_desc {
            p
        } else {
            format!("{} bytes ({comp})", m.bytes)
        };
        (
            Protocol::Grpc,
            format!("gRPC {count} — {details} on stream {sid}"),
        )
    } else if preface {
        let first = frames.first().map(describe);
        (
            Protocol::Http2,
            match first {
                Some(f) => format!("HTTP/2 connection preface + {f}"),
                None => "HTTP/2 connection preface".into(),
            },
        )
    } else {
        (Protocol::Http2, format!("HTTP/2 {}", describe(&frames[0])))
    };

    let extra = frames.len().saturating_sub(1);
    if extra > 0 && !preface {
        summary.push_str(&format!(" (+{extra} more frames)"));
    }

    Some(DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol,
        summary,
    })
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_protobuf_heuristic(mut bytes: &[u8]) -> Option<String> {
    let mut fields = Vec::new();

    fn read_varint(bytes: &mut &[u8]) -> Option<u64> {
        let mut val = 0u64;
        let mut shift = 0;
        loop {
            if bytes.is_empty() {
                return None;
            }
            let b = bytes[0];
            *bytes = &bytes[1..];
            val |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift >= 64 {
                return None;
            }
        }
        Some(val)
    }

    while !bytes.is_empty() {
        let tag = read_varint(&mut bytes)?;
        let wire_type = tag & 0x7;
        let field_num = tag >> 3;
        if field_num == 0 {
            return None;
        }

        match wire_type {
            0 => {
                let val = read_varint(&mut bytes)?;
                fields.push(format!("{field_num}: {val}"));
            }
            1 => {
                if bytes.len() < 8 {
                    return None;
                }
                let val = u64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]);
                bytes = &bytes[8..];
                fields.push(format!("{field_num}: 0x{val:016x}"));
            }
            2 => {
                let len = read_varint(&mut bytes)? as usize;
                if bytes.len() < len {
                    return None;
                }
                let sub = &bytes[..len];
                bytes = &bytes[len..];
                // Check if it's printable ASCII
                if sub
                    .iter()
                    .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
                {
                    if let Ok(s) = std::str::from_utf8(sub) {
                        let display_str = if s.len() > 30 {
                            format!("\"{}...\"", &s[..27])
                        } else {
                            format!("\"{s}\"")
                        };
                        fields.push(format!("{field_num}: {display_str}"));
                        continue;
                    }
                }
                // Try recursively
                if let Some(nested) = decode_protobuf_heuristic(sub) {
                    fields.push(format!("{field_num}: {nested}"));
                } else {
                    let hex = if sub.len() > 8 {
                        format!("{}...", to_hex(&sub[..8]))
                    } else {
                        to_hex(sub)
                    };
                    fields.push(format!("{field_num}: bytes(0x{hex})"));
                }
            }
            5 => {
                if bytes.len() < 4 {
                    return None;
                }
                let val = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                bytes = &bytes[4..];
                fields.push(format!("{field_num}: 0x{val:08x}"));
            }
            _ => return None,
        }
    }

    Some(format!("{{{}}}", fields.join(", ")))
}

fn decode_grpc_payload(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }
    let compressed = data[0] == 1;
    let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
    if data.len() < 5 + len {
        return None;
    }
    let msg_bytes = &data[5..5 + len];
    if compressed {
        None
    } else {
        decode_protobuf_heuristic(msg_bytes)
    }
}

/// Note appended to HTTP summaries when the message is an h2c upgrade: a
/// request carrying `Upgrade: h2c` (with its `HTTP2-Settings` header), or the
/// `101 Switching Protocols` response completing it.
pub fn upgrade_note(body: &str) -> Option<&'static str> {
    let head = super::head_str(body, 2048);
    let mut upgrade_h2c = false;
    let mut settings = false;
    for line in head.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        let Some((name, val)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.eq_ignore_ascii_case("upgrade") && val.trim().eq_ignore_ascii_case("h2c") {
            upgrade_h2c = true;
        } else if name.eq_ignore_ascii_case("http2-settings") {
            settings = true;
        }
    }
    if upgrade_h2c && settings {
        Some("HTTP/2 upgrade (h2c)")
    } else if upgrade_h2c {
        Some("HTTP/2 upgrade accepted (h2c)")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a frame: 9-byte header + payload (`declared` overrides the
    /// length field when the payload is deliberately truncated).
    fn frame(
        typ: u8,
        flags: u8,
        stream_id: u32,
        payload: &[u8],
        declared: Option<usize>,
    ) -> Vec<u8> {
        let len = declared.unwrap_or(payload.len());
        let mut f = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, typ, flags];
        f.extend(stream_id.to_be_bytes());
        f.extend(payload);
        f
    }

    fn dissect(bytes: &[u8]) -> Option<DissectedResult> {
        try_dissect(None, None, 50000, 8080, bytes)
    }

    fn summary_of(bytes: &[u8]) -> Option<String> {
        dissect(bytes).map(|r| r.summary)
    }

    #[test]
    fn connection_preface() {
        assert_eq!(summary_of(PREFACE).unwrap(), "HTTP/2 connection preface");
        // Typical first segment: preface + SETTINGS.
        let mut b = PREFACE.to_vec();
        b.extend(frame(
            FT_SETTINGS,
            0,
            0,
            &[0, 3, 0, 0, 0, 100, 0, 4, 0, 1, 0, 0],
            None,
        ));
        assert_eq!(
            summary_of(&b).unwrap(),
            "HTTP/2 connection preface + SETTINGS — 2 parameters"
        );
        assert_eq!(dissect(&b).unwrap().protocol, Protocol::Http2);
    }

    #[test]
    fn settings_ping_window_update() {
        let s = frame(FT_SETTINGS, F_ACK, 0, &[], None);
        assert_eq!(summary_of(&s).unwrap(), "HTTP/2 SETTINGS ACK");

        let p = frame(FT_PING, 0, 0, &[0; 8], None);
        assert_eq!(summary_of(&p).unwrap(), "HTTP/2 PING");

        let w = frame(FT_WINDOW_UPDATE, 0, 0, &65535u32.to_be_bytes(), None);
        assert_eq!(summary_of(&w).unwrap(), "HTTP/2 WINDOW_UPDATE +65535");
    }

    #[test]
    fn goaway_and_rst_stream_error_names() {
        let mut goaway = 0u32.to_be_bytes().to_vec(); // last stream id
        goaway.extend(11u32.to_be_bytes()); // ENHANCE_YOUR_CALM
        let g = frame(FT_GOAWAY, 0, 0, &goaway, None);
        assert_eq!(summary_of(&g).unwrap(), "HTTP/2 GOAWAY — ENHANCE_YOUR_CALM");

        let r = frame(FT_RST_STREAM, 0, 3, &8u32.to_be_bytes(), None);
        assert_eq!(
            summary_of(&r).unwrap(),
            "HTTP/2 RST_STREAM CANCEL — stream 3"
        );
    }

    #[test]
    fn multiple_frames_in_one_segment() {
        let mut b = frame(FT_HEADERS, F_END_HEADERS, 1, &[0x82, 0x86], None);
        b.extend(frame(FT_DATA, F_END_STREAM, 1, b"hello", None));
        assert_eq!(
            summary_of(&b).unwrap(),
            "HTTP/2 HEADERS — stream 1 (+1 more frames)"
        );
    }

    #[test]
    fn data_frame_spanning_segments() {
        // 16 KiB declared, only the first bytes present in this segment.
        let b = frame(FT_DATA, 0, 5, &[0u8; 100], Some(16384));
        assert_eq!(
            summary_of(&b).unwrap(),
            "HTTP/2 DATA — 16384 bytes on stream 5, continues"
        );
    }

    #[test]
    fn grpc_message_in_data_frame() {
        // One complete uncompressed message: flag 0 + len 4 + 4 bytes.
        let mut msg = vec![0u8, 0, 0, 0, 4];
        msg.extend([1, 2, 3, 4]);
        let b = frame(FT_DATA, F_END_STREAM, 1, &msg, None);
        let r = dissect(&b).unwrap();
        assert_eq!(r.protocol, Protocol::Grpc);
        assert_eq!(
            r.summary,
            "gRPC message — 4 bytes (uncompressed) on stream 1"
        );

        // One complete uncompressed message with valid protobuf: tag 1, length-delimited string "grpc"
        // 10 = (1 << 3) | 2
        let mut msg2 = vec![0u8, 0, 0, 0, 6];
        msg2.extend([10, 4, b'g', b'r', b'p', b'c']);
        let b2 = frame(FT_DATA, F_END_STREAM, 1, &msg2, None);
        let r2 = dissect(&b2).unwrap();
        assert_eq!(r2.protocol, Protocol::Grpc);
        assert_eq!(r2.summary, "gRPC message — {1: \"grpc\"} on stream 1");
    }

    #[test]
    fn grpc_multiple_messages_and_compression() {
        let mut payload = vec![0u8, 0, 0, 0, 2, 9, 9]; // uncompressed, 2 bytes
        payload.extend([1u8, 0, 0, 0, 3, 7, 7, 7]); // compressed, 3 bytes
        let b = frame(FT_DATA, 0, 7, &payload, None);
        let r = dissect(&b).unwrap();
        assert_eq!(r.protocol, Protocol::Grpc);
        assert_eq!(
            r.summary,
            "gRPC 2 messages — 5 bytes (compressed) on stream 7"
        );
    }

    #[test]
    fn grpc_headers_detected_raw_and_huffman() {
        // Literal (non-Huffman) content-type value in the header block.
        let mut block = vec![0x40, 0x0c];
        block.extend(b"content-type");
        block.push(0x10);
        block.extend(b"application/grpc");
        let b = frame(FT_HEADERS, F_END_HEADERS, 1, &block, None);
        let r = dissect(&b).unwrap();
        assert_eq!(r.protocol, Protocol::Grpc);
        assert_eq!(r.summary, "gRPC headers (application/grpc) — stream 1");

        // Huffman-coded value, as real clients send it (indexed name 31 =
        // content-type, then H bit + length 11 + the Huffman bytes).
        let mut block = vec![0x5f, 0x8b];
        block.extend(GRPC_CT_HUFFMAN);
        let b = frame(FT_HEADERS, F_END_HEADERS, 3, &block, None);
        let r = dissect(&b).unwrap();
        assert_eq!(r.protocol, Protocol::Grpc);
    }

    #[test]
    fn plain_data_frame_stays_http2() {
        // DATA whose payload is not a gRPC message chain.
        let b = frame(FT_DATA, 0, 1, b"<html>hello</html>", None);
        let r = dissect(&b).unwrap();
        assert_eq!(r.protocol, Protocol::Http2);
    }

    #[test]
    fn rejects_non_http2_data() {
        assert!(dissect(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").is_none());
        assert!(dissect(b"").is_none());
        assert!(dissect(&[0u8; 9]).is_none()); // DATA on stream 0
        assert!(dissect(&[0u8; 30]).is_none());
        // Unknown frame type 0x0a.
        assert!(dissect(&frame(0x0a, 0, 1, &[], None)).is_none());
        // Reserved stream-id bit set.
        assert!(dissect(&frame(FT_DATA, 0, 0x8000_0001, b"x", None)).is_none());
        // SETTINGS length not a multiple of 6.
        assert!(dissect(&frame(FT_SETTINGS, 0, 0, &[0; 5], None)).is_none());
        // PING with wrong length.
        assert!(dissect(&frame(FT_PING, 0, 0, &[0; 4], None)).is_none());
        // Trailing garbage after a valid frame breaks the chain.
        let mut b = frame(FT_PING, 0, 0, &[0; 8], None);
        b.push(0xff);
        assert!(dissect(&b).is_none());
        // TLS-ish record header is not a valid frame.
        assert!(dissect(&[0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03]).is_none());
    }

    #[test]
    fn upgrade_notes() {
        let req = "GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n";
        assert_eq!(upgrade_note(req), Some("HTTP/2 upgrade (h2c)"));
        let resp =
            "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n";
        assert_eq!(upgrade_note(resp), Some("HTTP/2 upgrade accepted (h2c)"));
        assert_eq!(upgrade_note("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), None);
    }
}
