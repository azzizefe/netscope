// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! TDS — the wire protocol of Microsoft SQL Server (MS-TDS).
//!
//! Naming the packet type is not enough. A SQL batch carries the statement
//! itself as text, and a tabular response carries the server's error messages,
//! so those are what a reader wants — the same depth the PostgreSQL and MySQL
//! dissectors already offer. "Login failed for user" is the message that
//! explains most SQL Server problems, and it is right there in the response.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Type, status, length, SPID, packet id, window.
const HEADER: usize = 8;

const TYPE_SQL_BATCH: u8 = 1;
const TYPE_RPC: u8 = 3;
const TYPE_TABULAR_RESULT: u8 = 4;

/// Token types inside a tabular response (MS-TDS §2.2.5).
const TOKEN_ERROR: u8 = 0xAA;
const TOKEN_INFO: u8 = 0xAB;
const TOKEN_LOGIN_ACK: u8 = 0xAD;

fn type_name(t: u8) -> &'static str {
    match t {
        1 => "SQL batch",
        2 => "login (pre-TDS7)",
        3 => "RPC request",
        4 => "response",
        6 => "attention",
        7 => "bulk load",
        14 => "transaction manager",
        16 => "login",
        17 => "SSPI",
        18 => "pre-login",
        _ => "message",
    }
}

/// Decode UCS-2 little-endian text, which is how TDS carries every string.
///
/// Returns `None` when the bytes do not look like text, which is how a wrong
/// starting offset is detected rather than producing plausible gibberish.
fn ucs2(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 2 {
        return None;
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let text: String = char::decode_utf16(units)
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect();
    // Deciding whether these bytes were text is a heuristic, and character
    // classes alone are not enough: arbitrary binary decodes to noncharacters
    // like U+FFFF, and pairs such as 0x0101 land on perfectly ordinary letters.
    //
    // SQL is the saving grace — keywords, operators and punctuation are ASCII,
    // so even a statement full of non-Latin identifiers stays mostly ASCII.
    // Requiring that majority rejects binary reliably. The trade is that a
    // statement which is almost entirely a non-Latin string literal falls back
    // to naming the packet type, which is the previous behaviour rather than a
    // wrong answer.
    // A NUL is decisive on its own: no statement contains one, so its presence
    // means these bytes are a header or padding rather than text. That is what
    // separates a batch from the headers block in front of it.
    if text.is_empty() || text.contains('\0') {
        return None;
    }
    let ascii = text
        .chars()
        .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
        .count();
    if ascii * 10 < text.chars().count() * 7 {
        return None;
    }
    Some(text.trim().to_string())
}

/// The body of a SQL batch, skipping the optional ALL_HEADERS block.
///
/// TDS 7.2 added a headers block in front of the statement, introduced by its
/// own total length. Older clients omit it, so try the statement directly first
/// and fall back to skipping the block — `ucs2` rejecting the bytes is what
/// tells the two apart.
fn batch_text(body: &[u8]) -> Option<String> {
    if let Some(text) = ucs2(body) {
        return Some(text);
    }
    let total =
        u32::from_le_bytes([*body.first()?, *body.get(1)?, *body.get(2)?, *body.get(3)?]) as usize;
    // A plausible headers block is small and fits inside the packet.
    if total < 4 || total > body.len() {
        return None;
    }
    ucs2(body.get(total..)?)
}

/// Pull the first error or informational message out of a tabular response.
///
/// The token stream is a sequence of typed records; an error carries a number,
/// a severity class and the message text.
fn response_message(body: &[u8]) -> Option<(bool, u32, String)> {
    let token = *body.first()?;
    if !matches!(token, TOKEN_ERROR | TOKEN_INFO) {
        return None;
    }
    // token(1), length(2), number(4), state(1), class(1), then the message
    // length in characters and the message itself.
    let number = u32::from_le_bytes([*body.get(3)?, *body.get(4)?, *body.get(5)?, *body.get(6)?]);
    let chars = u16::from_le_bytes([*body.get(9)?, *body.get(10)?]) as usize;
    let text = ucs2(body.get(11..11 + chars * 2)?)?;
    Some((token == TOKEN_ERROR, number, text))
}

/// Dissect a TDS segment (TCP 1433).
pub fn dissect_tds(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < HEADER {
        format!("TDS ({})", super::bytes(payload.len() as u64))
    } else {
        let ptype = payload[0];
        let body = &payload[HEADER..];
        match ptype {
            // The statement itself is the point of a batch.
            TYPE_SQL_BATCH => match batch_text(body) {
                Some(sql) => format!("TDS SQL batch — {}", super::truncate(&sql, 60)),
                None => "TDS SQL batch".to_string(),
            },
            // An RPC request names the stored procedure being called.
            TYPE_RPC => match batch_text(body) {
                Some(name) => format!("TDS RPC — {}", super::truncate(&name, 48)),
                None => "TDS RPC request".to_string(),
            },
            // A response is mostly rows, but an error is what explains a
            // failure — "Login failed for user" lives here.
            TYPE_TABULAR_RESULT => match response_message(body) {
                Some((true, number, text)) => {
                    format!("TDS error {number} — {}", super::truncate(&text, 60))
                }
                Some((false, _, text)) => {
                    format!("TDS message — {}", super::truncate(&text, 60))
                }
                None if body.first() == Some(&TOKEN_LOGIN_ACK) => {
                    "TDS login acknowledged".to_string()
                }
                None => "TDS response".to_string(),
            },
            other => format!("TDS {}", type_name(other)),
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Tds,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_ucs2(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    /// Build a TDS packet of the given type carrying `body`.
    fn tds(ptype: u8, body: &[u8]) -> Vec<u8> {
        let mut p = vec![ptype, 0x01];
        p.extend_from_slice(&((HEADER + body.len()) as u16).to_be_bytes());
        p.extend_from_slice(&[0, 0, 1, 0]); // SPID, packet id, window
        p.extend_from_slice(body);
        p
    }

    #[test]
    fn sql_batch_shows_the_statement() {
        let p = tds(TYPE_SQL_BATCH, &to_ucs2("SELECT * FROM Orders"));
        let r = dissect_tds(None, None, 50000, 1433, &p);
        assert_eq!(r.protocol, Protocol::Tds);
        assert_eq!(r.summary, "TDS SQL batch — SELECT * FROM Orders");
    }

    /// TDS 7.2 put a headers block in front of the statement. Reading straight
    /// past it would show binary noise instead of the query.
    #[test]
    fn statement_is_found_behind_the_headers_block() {
        let mut body = 22u32.to_le_bytes().to_vec();
        body.extend_from_slice(&[0u8; 18]); // the rest of the headers block
        body.extend_from_slice(&to_ucs2("UPDATE Users SET active = 0"));
        let r = dissect_tds(None, None, 50000, 1433, &tds(TYPE_SQL_BATCH, &body));
        assert_eq!(r.summary, "TDS SQL batch — UPDATE Users SET active = 0");
    }

    /// The message that explains most SQL Server problems.
    #[test]
    fn login_failure_is_surfaced() {
        let text = "Login failed for user 'sa'.";
        let mut body = vec![TOKEN_ERROR];
        body.extend_from_slice(&0u16.to_le_bytes()); // token length
        body.extend_from_slice(&18456u32.to_le_bytes()); // error number
        body.push(1); // state
        body.push(14); // class
        body.extend_from_slice(&(text.encode_utf16().count() as u16).to_le_bytes());
        body.extend_from_slice(&to_ucs2(text));
        let r = dissect_tds(None, None, 1433, 50000, &tds(TYPE_TABULAR_RESULT, &body));
        assert_eq!(r.summary, "TDS error 18456 — Login failed for user 'sa'.");
    }

    #[test]
    fn successful_login_is_acknowledged() {
        let r = dissect_tds(
            None,
            None,
            1433,
            50000,
            &tds(TYPE_TABULAR_RESULT, &[TOKEN_LOGIN_ACK, 0, 0]),
        );
        assert_eq!(r.summary, "TDS login acknowledged");
    }

    /// A long statement is capped so one query cannot fill the column.
    #[test]
    fn long_statements_are_truncated() {
        let long = format!("SELECT {} FROM T", "column_name, ".repeat(20));
        let r = dissect_tds(None, None, 1, 1433, &tds(TYPE_SQL_BATCH, &to_ucs2(&long)));
        assert!(r.summary.contains('…'));
        assert!(r.summary.len() < 100);
    }

    /// Binary where text should be means the offset was wrong; reporting the
    /// packet type is better than printing gibberish.
    #[test]
    fn binary_body_falls_back_to_the_packet_type() {
        // Both shapes matter: 0x00 bytes decode to NUL, a control character,
        // while 0xFF bytes decode to U+FFFF, which is not — so a check that
        // only looked for control characters would let the second through.
        let r = dissect_tds(None, None, 1, 1433, &tds(TYPE_SQL_BATCH, &[0xFF; 32]));
        assert_eq!(r.summary, "TDS SQL batch");
        let r = dissect_tds(None, None, 1, 1433, &tds(TYPE_SQL_BATCH, &[0x01; 32]));
        assert_eq!(r.summary, "TDS SQL batch");
    }

    /// A statement in a non-Latin script is still text and must survive the
    /// plausibility check.
    #[test]
    fn non_ascii_statements_are_kept() {
        let p = tds(TYPE_SQL_BATCH, &to_ucs2("SELECT * FROM Müşteriler"));
        assert_eq!(
            dissect_tds(None, None, 1, 1433, &p).summary,
            "TDS SQL batch — SELECT * FROM Müşteriler"
        );
    }

    #[test]
    fn other_packet_types_are_named() {
        let r = dissect_tds(None, None, 50000, 1433, &[18, 1, 0, 8, 0, 0, 0, 0]);
        assert_eq!(r.summary, "TDS pre-login");
        let r = dissect_tds(None, None, 50000, 1433, &tds(16, &[0u8; 4]));
        assert_eq!(r.summary, "TDS login");
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_tds(None, None, 1, 1433, &[18, 1, 0]);
        assert_eq!(r.summary, "TDS (3 bytes)");
    }
}
