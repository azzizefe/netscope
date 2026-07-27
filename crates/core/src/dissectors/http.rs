// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::{cmp, http2, ocsp, soap, tsp, websocket, DissectedResult};

#[derive(Debug)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub version: String,
}

#[derive(Debug)]
pub struct HttpResponse {
    pub version: String,
    pub status_code: u16,
    pub reason: String,
}

pub fn dissect_http(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    // Only the request/status line and headers shape the summary — the body
    // can be megabytes of binary. Decode just the head (first 2 KiB), taking
    // the longest valid UTF-8 prefix so a text header followed by a binary
    // body still parses (ROADMAP §4.1: don't UTF-8-scan whole payloads).
    let head_bytes = &payload[..payload.len().min(2048)];
    let body = match std::str::from_utf8(head_bytes) {
        Ok(s) => s,
        // Text head, binary tail: keep the valid prefix (headers end well
        // before the first invalid byte in any real HTTP message).
        Err(e) if e.valid_up_to() > 0 => {
            std::str::from_utf8(&head_bytes[..e.valid_up_to()]).expect("prefix just validated")
        }
        Err(_) => {
            return DissectedResult {
                src_addr: src_ip,
                dst_addr: dst_ip,
                src_port: Some(src_port),
                dst_port: Some(dst_port),
                protocol: Protocol::Http,
                summary: "HTTP — non-UTF8 payload".into(),
            };
        }
    };

    let body = body.trim_start_matches('\0');

    // A great deal rides inside HTTP bodies rather than on a port of its own.
    // `http_body` finds the body without decoding it; if something here
    // understands what the Content-Type names, that inner protocol is the
    // answer and HTTP is the envelope — the same treatment MPLS and EtherIP
    // get. Only content types that are actually claimed take this path, so an
    // ordinary page or API call still reads as HTTP.
    if let Some(message) = super::http_body::split(payload) {
        if let Some(content_type) = message.content_type.as_deref() {
            let inner = if message.body.is_empty() {
                None
            } else if soap::is_soap_type(content_type) {
                Some(soap::dissect_soap(
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    message.body,
                ))
            } else if cmp::is_cmp_type(content_type) {
                Some(cmp::dissect_cmp(
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    message.body,
                ))
            } else if tsp::is_query_type(content_type) || tsp::is_reply_type(content_type) {
                Some(tsp::dissect_tsp(
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    message.body,
                    tsp::is_reply_type(content_type),
                ))
            } else if ocsp::is_request_type(content_type) || ocsp::is_response_type(content_type) {
                Some(ocsp::dissect_ocsp(
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    message.body,
                    ocsp::is_response_type(content_type),
                ))
            } else {
                None
            };
            if let Some(mut inner) = inner {
                inner.summary = format!("HTTP · {}", inner.summary);
                return inner;
            }
        }
    }

    // A WebSocket or h2c upgrade is still HTTP on the wire — flag it in the
    // summary so the handshake is recognisable next to the frames that follow.
    let ws_note = websocket::upgrade_note(body)
        .or_else(|| http2::upgrade_note(body))
        .map(|n| format!(" — {n}"))
        .unwrap_or_default();

    if let Some(req) = parse_request(body) {
        DissectedResult {
            src_addr: src_ip,
            dst_addr: dst_ip,
            src_port: Some(src_port),
            dst_port: Some(dst_port),
            protocol: Protocol::Http,
            summary: format!(
                "HTTP {} {} ({}){ws_note}",
                req.method, req.path, req.version
            ),
        }
    } else if let Some(resp) = parse_response(body) {
        DissectedResult {
            src_addr: src_ip,
            dst_addr: dst_ip,
            src_port: Some(src_port),
            dst_port: Some(dst_port),
            protocol: Protocol::Http,
            summary: format!(
                "HTTP {} {} ({} bytes){ws_note}",
                resp.status_code,
                resp.reason,
                payload.len()
            ),
        }
    } else {
        DissectedResult {
            src_addr: src_ip,
            dst_addr: dst_ip,
            src_port: Some(src_port),
            dst_port: Some(dst_port),
            protocol: Protocol::Http,
            summary: format!("HTTP — {} of data", super::bytes(payload.len() as u64)),
        }
    }
}

fn parse_request(body: &str) -> Option<HttpRequest> {
    let first_line = body.lines().next()?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }
    let method = parts[0];
    if ![
        "GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS", "CONNECT", "TRACE",
    ]
    .contains(&method)
    {
        return None;
    }
    let path = parts[1].to_string();
    let version = parts[2].to_string();
    Some(HttpRequest {
        method: method.to_string(),
        path,
        version,
    })
}

fn parse_response(body: &str) -> Option<HttpResponse> {
    let first_line = body.lines().next()?;
    let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return None;
    }
    let version = parts[0];
    if !version.starts_with("HTTP/") {
        return None;
    }
    let status_code: u16 = parts[1].parse().ok()?;
    let reason = parts.get(2).unwrap_or(&"").to_string();
    Some(HttpResponse {
        version: version.to_string(),
        status_code,
        reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_request() {
        let req = b"GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = dissect_http(None, None, 12345, 80, req);
        assert_eq!(result.protocol, Protocol::Http);
        assert_eq!(result.summary, "HTTP GET /api/users (HTTP/1.1)");
    }

    #[test]
    fn http_response() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n{\"ok\":true}";
        let result = dissect_http(None, None, 80, 12345, resp);
        assert_eq!(result.protocol, Protocol::Http);
        assert_eq!(result.summary, "HTTP 200 OK (50 bytes)");
    }

    #[test]
    fn http_non_utf8() {
        let result = dissect_http(None, None, 80, 12345, &[0xff, 0xfe, 0x00]);
        assert_eq!(result.summary, "HTTP — non-UTF8 payload");
    }

    #[test]
    fn http_text_head_with_binary_body_still_parses() {
        // A response whose body is binary (image, gzip…) must still yield the
        // status line — only the head is decoded, not the whole payload.
        let mut resp = b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n".to_vec();
        resp.extend_from_slice(&[0x89, 0x50, 0x4e, 0x47, 0xff, 0xfe, 0x00, 0x81]);
        let len = resp.len();
        let result = dissect_http(None, None, 80, 12345, &resp);
        assert_eq!(result.summary, format!("HTTP 200 OK ({len} bytes)"));
    }

    #[test]
    fn http_garbage() {
        let result = dissect_http(None, None, 80, 12345, b"not http data");
        assert_eq!(result.summary, "HTTP — 13 bytes of data");
    }

    #[test]
    fn http_post_request() {
        let req =
            b"POST /api/data HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"key\":\"value\"}";
        let result = dissect_http(None, None, 12345, 80, req);
        assert_eq!(result.protocol, Protocol::Http);
        assert_eq!(result.summary, "HTTP POST /api/data (HTTP/1.1)");
    }

    #[test]
    fn http_empty_request_line() {
        let result = dissect_http(None, None, 80, 12345, b"\r\n");
        assert_eq!(result.summary, "HTTP — 2 bytes of data");
    }

    #[test]
    fn http_unknown_method() {
        let req = b"INVALID /path HTTP/1.1\r\n\r\n";
        let result = dissect_http(None, None, 12345, 80, req);
        assert_eq!(result.summary, "HTTP — 26 bytes of data");
    }
}
