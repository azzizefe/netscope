// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! WebSocket (RFC 6455) — data frames after an HTTP/1.1 Upgrade handshake.
//!
//! WebSocket has no port of its own: a connection starts as plain HTTP and is
//! upgraded in place, so frames can appear on 80, 8080, 3000 or any other
//! port. netscope's dissection is stateless per packet, so instead of tracking
//! the upgrade we *validate*: a TCP payload is reported as WebSocket only when
//! it parses as a complete, well-formed chain of frames (reserved bits zero,
//! known opcodes, self-consistent lengths). Random data passes those checks
//! only rarely, and real WebSocket traffic always does.
//!
//! The handshake itself is genuine HTTP and stays `Protocol::Http` (as in
//! Wireshark); `dissect_http` annotates it — see [`upgrade_note`].

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

// Frame opcodes (RFC 6455 §5.2).
const OP_CONTINUATION: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

#[derive(Debug)]
struct Frame {
    opcode: u8,
    /// Payload bytes present in this TCP segment (may be truncated when the
    /// frame spans segments), already unmasked.
    payload: Vec<u8>,
    /// Declared payload length from the header.
    declared_len: u64,
    /// Header + declared payload size — where the next frame would start.
    total_len: Option<usize>,
}

/// Parse one frame header at `b[0..]`. Returns `None` unless the header is
/// well-formed by the strict rules above.
fn parse_frame(b: &[u8]) -> Option<Frame> {
    if b.len() < 2 {
        return None;
    }
    if b[0] & 0x70 != 0 {
        return None; // RSV bits must be 0 (no negotiated extensions)
    }
    let fin = b[0] & 0x80 != 0;
    let opcode = b[0] & 0x0f;
    if !matches!(
        opcode,
        OP_CONTINUATION | OP_TEXT | OP_BINARY | OP_CLOSE | OP_PING | OP_PONG
    ) {
        return None;
    }
    let masked = b[1] & 0x80 != 0;
    let len7 = (b[1] & 0x7f) as u64;

    let mut off = 2usize;
    let declared_len = match len7 {
        126 => {
            let v = u64::from(u16::from_be_bytes([*b.get(off)?, *b.get(off + 1)?]));
            off += 2;
            if v < 126 {
                return None; // RFC requires minimal length encoding
            }
            v
        }
        127 => {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(b.get(off..off + 8)?);
            off += 8;
            let v = u64::from_be_bytes(buf);
            if v < 65536 {
                return None;
            }
            v
        }
        n => n,
    };

    // Control frames must be short and unfragmented (RFC 6455 §5.5).
    if opcode >= OP_CLOSE && (!fin || declared_len > 125) {
        return None;
    }

    let mask_key = if masked {
        let k = b.get(off..off + 4)?;
        off += 4;
        Some([k[0], k[1], k[2], k[3]])
    } else {
        None
    };

    let avail = b.len().saturating_sub(off);
    let take = declared_len.min(avail as u64) as usize;
    let mut payload = b[off..off + take].to_vec();
    if let Some(key) = mask_key {
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= key[i % 4]; // masking is XOR, not encryption — undo it
        }
    }
    let total_len = (declared_len <= avail as u64).then(|| off + declared_len as usize);

    Some(Frame {
        opcode,
        payload,
        declared_len,
        total_len,
    })
}

/// Parse the segment as a chain of frames starting at offset 0. Accepts only
/// two shapes: every frame complete and the chain consuming the segment
/// exactly, or a final/only frame whose payload continues in the next segment.
fn parse_chain(payload: &[u8]) -> Option<Vec<Frame>> {
    let mut frames = Vec::new();
    let mut off = 0usize;
    while off < payload.len() {
        let frame = parse_frame(&payload[off..])?;
        match frame.total_len {
            Some(n) => {
                off += n;
                frames.push(frame);
            }
            None => {
                // Truncated frame: valid only as the tail of the segment.
                frames.push(frame);
                return Some(frames);
            }
        }
    }
    (off == payload.len() && !frames.is_empty()).then_some(frames)
}

fn opcode_name(op: u8) -> &'static str {
    match op {
        OP_CONTINUATION => "Continuation",
        OP_TEXT => "Text",
        OP_BINARY => "Binary",
        OP_CLOSE => "Close",
        OP_PING => "Ping",
        OP_PONG => "Pong",
        _ => "?",
    }
}

/// Printable preview of a text payload for the summary column.
fn text_preview(payload: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(payload).ok()?;
    let clean: String = s
        .chars()
        .map(|c| if c.is_control() { '·' } else { c })
        .take(48)
        .collect();
    (!clean.is_empty()).then_some(clean)
}

fn describe(frame: &Frame) -> String {
    match frame.opcode {
        OP_TEXT => match text_preview(&frame.payload) {
            Some(t) => format!("WebSocket Text — \"{t}\""),
            None => format!("WebSocket Text — {} bytes", frame.declared_len),
        },
        OP_CLOSE => {
            if frame.payload.len() >= 2 {
                let code = u16::from_be_bytes([frame.payload[0], frame.payload[1]]);
                format!("WebSocket Close ({code})")
            } else {
                "WebSocket Close".into()
            }
        }
        OP_PING => "WebSocket Ping".into(),
        OP_PONG => "WebSocket Pong".into(),
        op => {
            let kind = opcode_name(op);
            let cont = if frame.total_len.is_none() {
                ", continues"
            } else {
                ""
            };
            format!("WebSocket {kind} — {} bytes{cont}", frame.declared_len)
        }
    }
}

/// Try to dissect a TCP payload as WebSocket frames. Returns `None` when the
/// bytes don't validate as a frame chain — the caller falls through to its
/// generic TCP summary.
pub fn try_dissect(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<DissectedResult> {
    let frames = parse_chain(payload)?;
    let mut summary = describe(&frames[0]);
    if frames.len() > 1 {
        summary.push_str(&format!(" (+{} more frames)", frames.len() - 1));
    }
    Some(DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::WebSocket,
        summary,
    })
}

/// Note appended to HTTP summaries when the message is a WebSocket handshake:
/// a request carrying `Upgrade: websocket`, or the `101 Switching Protocols`
/// response completing it.
pub fn upgrade_note(body: &str) -> Option<&'static str> {
    let head = super::head_str(body, 2048);
    let mut upgrade_ws = false;
    let mut ws_key = false;
    let mut ws_accept = false;
    for line in head.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        let Some((name, val)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.eq_ignore_ascii_case("upgrade") && val.trim().eq_ignore_ascii_case("websocket") {
            upgrade_ws = true;
        } else if name.eq_ignore_ascii_case("sec-websocket-key") {
            ws_key = true;
        } else if name.eq_ignore_ascii_case("sec-websocket-accept") {
            ws_accept = true;
        }
    }
    if upgrade_ws && ws_key {
        Some("WebSocket handshake")
    } else if upgrade_ws && ws_accept {
        Some("WebSocket handshake accepted")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a frame: header + optional mask + payload.
    fn frame(fin: bool, opcode: u8, mask: Option<[u8; 4]>, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![(u8::from(fin) << 7) | opcode];
        let masked_bit = if mask.is_some() { 0x80 } else { 0 };
        match payload.len() {
            n if n < 126 => f.push(masked_bit | n as u8),
            n if n < 65536 => {
                f.push(masked_bit | 126);
                f.extend((n as u16).to_be_bytes());
            }
            n => {
                f.push(masked_bit | 127);
                f.extend((n as u64).to_be_bytes());
            }
        }
        match mask {
            Some(key) => {
                f.extend(key);
                f.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
            }
            None => f.extend(payload),
        }
        f
    }

    fn summary_of(bytes: &[u8]) -> Option<String> {
        try_dissect(None, None, 50000, 8080, bytes).map(|r| {
            assert_eq!(r.protocol, Protocol::WebSocket);
            r.summary
        })
    }

    #[test]
    fn unmasked_text_frame() {
        let f = frame(true, OP_TEXT, None, b"hello world");
        assert_eq!(summary_of(&f).unwrap(), "WebSocket Text — \"hello world\"");
    }

    #[test]
    fn masked_text_frame_is_unmasked_for_preview() {
        let f = frame(true, OP_TEXT, Some([0xde, 0xad, 0xbe, 0xef]), b"ping me");
        assert_eq!(summary_of(&f).unwrap(), "WebSocket Text — \"ping me\"");
    }

    #[test]
    fn binary_and_control_frames() {
        let f = frame(true, OP_BINARY, None, &[0u8; 300]);
        assert_eq!(summary_of(&f).unwrap(), "WebSocket Binary — 300 bytes");

        let ping = frame(true, OP_PING, Some([1, 2, 3, 4]), b"");
        assert_eq!(summary_of(&ping).unwrap(), "WebSocket Ping");

        let close = frame(true, OP_CLOSE, None, &1000u16.to_be_bytes());
        assert_eq!(summary_of(&close).unwrap(), "WebSocket Close (1000)");
    }

    #[test]
    fn multiple_frames_in_one_segment() {
        let mut b = frame(true, OP_TEXT, None, b"a");
        b.extend(frame(true, OP_PING, None, b""));
        b.extend(frame(true, OP_PONG, None, b""));
        assert_eq!(
            summary_of(&b).unwrap(),
            "WebSocket Text — \"a\" (+2 more frames)"
        );
    }

    #[test]
    fn frame_spanning_segments() {
        // 64 KiB declared, only the first bytes present in this segment.
        let mut f = frame(true, OP_BINARY, None, &[0u8; 70000]);
        f.truncate(200);
        assert_eq!(
            summary_of(&f).unwrap(),
            "WebSocket Binary — 70000 bytes, continues"
        );
    }

    #[test]
    fn rejects_non_websocket_data() {
        assert!(summary_of(b"GET / HTTP/1.1\r\n\r\n").is_none()); // RSV bits set ('G' = 0x47)
        assert!(summary_of(&[]).is_none());
        assert!(summary_of(&[0x80]).is_none()); // too short
        assert!(summary_of(&[0x83, 0x01, 0xff]).is_none()); // reserved opcode 0x3
        assert!(summary_of(&[0xf1, 0x01, 0xff]).is_none()); // RSV bits set
                                                            // Trailing garbage after a valid frame breaks the chain.
        let mut f = frame(true, OP_TEXT, None, b"ok");
        f.push(0xff);
        assert!(summary_of(&f).is_none());
        // Non-minimal extended length is rejected.
        assert!(summary_of(&[0x81, 126, 0x00, 0x05, b'h', b'e', b'l', b'l', b'o']).is_none());
    }

    #[test]
    fn control_frames_must_be_unfragmented_and_short() {
        let unfinished_ping = frame(false, OP_PING, None, b"");
        assert!(summary_of(&unfinished_ping).is_none());
    }

    #[test]
    fn upgrade_notes() {
        let req = "GET /chat HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
        assert_eq!(upgrade_note(req), Some("WebSocket handshake"));
        let resp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
        assert_eq!(upgrade_note(resp), Some("WebSocket handshake accepted"));
        assert_eq!(upgrade_note("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), None);
    }
}
