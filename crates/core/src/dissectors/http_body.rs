// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Finding the body of an HTTP message, so what rides inside it can be read.
//!
//! A great deal of what runs on a network is not a protocol on a port — it is a
//! protocol inside an HTTP body. Certificate status checks, camera control,
//! router management, telemetry export and half the database wire protocols in
//! use all arrive as `POST / HTTP/1.1` with the real message in the body. Until
//! something looks past the header block, every one of them reads as "HTTP POST
//! /" and nothing more.
//!
//! This module is that step. It does not dissect anything itself; it locates
//! the body and reports the one header that says what the body *is*.
//!
//! ## Why it does not simply decode the payload
//!
//! `http.rs` deliberately decodes only the first 2 KiB as UTF-8, because a body
//! can be megabytes of binary and scanning all of it for every packet is the
//! difference between a fast reader and a slow one. This module keeps that
//! constraint: the header block is found by a **byte** search for the blank
//! line, and only the header block is ever decoded as text. The body is handed
//! on as raw bytes for whoever understands it.

/// Nothing useful lives past this much header, and a message claiming to is
/// either broken or trying to hide something in it.
const MAX_HEADER: usize = 8192;

/// The parts of an HTTP message a body dissector needs.
pub(crate) struct Message<'a> {
    /// The value of the `Content-Type` header, lowercased, without parameters.
    /// `application/soap+xml; charset=utf-8` becomes `application/soap+xml`.
    pub content_type: Option<String>,
    /// The bytes after the blank line. Empty when the message has no body.
    pub body: &'a [u8],
}

/// Split an HTTP message into its header block and its body.
///
/// Returns `None` when there is no complete header block in the payload — a
/// segment carrying only part of the headers has no body to point at yet.
pub(crate) fn split(payload: &[u8]) -> Option<Message<'_>> {
    let window = &payload[..payload.len().min(MAX_HEADER)];
    // The blank line is found by byte search rather than by decoding: the body
    // may not be text at all, and decoding it is exactly the cost to avoid.
    let blank = find_blank_line(window)?;
    let (head, rest) = payload.split_at(blank.0);
    let body = &rest[blank.1 - blank.0..];

    // Only the head is decoded, and only its longest valid prefix — a header
    // block with a stray byte should not lose the headers before it.
    let head = match std::str::from_utf8(head) {
        Ok(s) => s,
        Err(e) if e.valid_up_to() > 0 => std::str::from_utf8(&head[..e.valid_up_to()]).ok()?,
        Err(_) => return None,
    };

    Some(Message {
        content_type: header(head, "content-type").map(|v| {
            // Parameters after a semicolon are not part of the type.
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        }),
        body,
    })
}

/// Find the blank line ending the header block, returning where the headers
/// end and where the body starts.
///
/// Both `\r\n\r\n` and the bare `\n\n` that some embedded servers emit are
/// accepted, because a device that gets this wrong is exactly the sort this
/// tool is pointed at.
fn find_blank_line(window: &[u8]) -> Option<(usize, usize)> {
    if let Some(at) = memchr::memmem::find(window, b"\r\n\r\n") {
        return Some((at, at + 4));
    }
    memchr::memmem::find(window, b"\n\n").map(|at| (at, at + 2))
}

/// Read one header's value, case-insensitively.
///
/// Walked line by line rather than searched for, because a header *value* can
/// contain the name of another header — a `Referer` carrying a URL with
/// `content-type=` in its query string is the ordinary example.
fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim())
            .filter(|v| !v.is_empty())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(headers: &str, body: &[u8]) -> Vec<u8> {
        let mut v = headers.as_bytes().to_vec();
        v.extend_from_slice(b"\r\n\r\n");
        v.extend_from_slice(body);
        v
    }

    /// The reason this module exists: reaching the bytes past the headers.
    #[test]
    fn the_body_is_found_after_the_blank_line() {
        let p = message(
            "POST /ocsp HTTP/1.1\r\nHost: ca.example\r\nContent-Type: application/ocsp-request",
            &[0x30, 0x45, 0xDE, 0xAD],
        );
        let m = split(&p).expect("a complete header block");
        assert_eq!(m.content_type.as_deref(), Some("application/ocsp-request"));
        assert_eq!(m.body, &[0x30, 0x45, 0xDE, 0xAD]);
    }

    /// A binary body must not stop the headers being read — that is the whole
    /// point of not decoding the payload as text.
    #[test]
    fn a_binary_body_does_not_prevent_reading_the_headers() {
        let p = message(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream",
            &[0xFF, 0xFE, 0x00, 0x80, 0x81],
        );
        let m = split(&p).expect("a complete header block");
        assert_eq!(m.content_type.as_deref(), Some("application/octet-stream"));
        assert_eq!(m.body.len(), 5);
    }

    /// Parameters are not part of the type, and the type is matched
    /// case-insensitively in practice.
    #[test]
    fn the_content_type_is_normalised() {
        let p = message(
            "POST / HTTP/1.1\r\nContent-Type: Application/SOAP+XML; charset=utf-8",
            b"<x/>",
        );
        assert_eq!(
            split(&p).unwrap().content_type.as_deref(),
            Some("application/soap+xml")
        );
    }

    /// Headers are walked, not searched. A value can contain another header's
    /// name — a URL with `content-type=` in its query string is the ordinary
    /// case, and searching would return the URL rather than the real type.
    #[test]
    fn a_header_value_naming_another_header_does_not_confuse_the_walk() {
        let p = message(
            "GET /r?content-type=text/evil HTTP/1.1\r\n\
             Referer: http://a/b?content-type=text/evil\r\n\
             Content-Type: application/json",
            b"{}",
        );
        assert_eq!(
            split(&p).unwrap().content_type.as_deref(),
            Some("application/json")
        );
    }

    /// Embedded servers do emit bare newlines, and a device that gets this
    /// wrong is exactly the sort worth being able to read.
    #[test]
    fn a_bare_newline_separator_is_accepted() {
        let mut p = b"POST / HTTP/1.1\nContent-Type: text/xml".to_vec();
        p.extend_from_slice(b"\n\n<envelope/>");
        let m = split(&p).expect("a header block");
        assert_eq!(m.content_type.as_deref(), Some("text/xml"));
        assert_eq!(m.body, b"<envelope/>");
    }

    /// A message with no body is not a failure — it simply has none.
    #[test]
    fn a_message_without_a_body_reports_an_empty_one() {
        let p = message("GET / HTTP/1.1\r\nHost: example", b"");
        let m = split(&p).expect("a header block");
        assert!(m.body.is_empty());
        assert!(m.content_type.is_none());
    }

    /// A segment carrying only part of the headers has no body to point at.
    #[test]
    fn an_incomplete_header_block_is_not_split() {
        assert!(split(b"POST / HTTP/1.1\r\nHost: exam").is_none());
        assert!(split(b"").is_none());
        // A header block longer than anything legitimate is not searched past.
        let mut huge = b"GET / HTTP/1.1\r\n".to_vec();
        huge.extend(std::iter::repeat_n(b'x', MAX_HEADER * 2));
        huge.extend_from_slice(b"\r\n\r\nbody");
        assert!(split(&huge).is_none());
    }

    /// An empty header value is not a value.
    #[test]
    fn an_empty_content_type_is_treated_as_absent() {
        let p = message("POST / HTTP/1.1\r\nContent-Type:", b"x");
        assert!(split(&p).unwrap().content_type.is_none());
    }
}
