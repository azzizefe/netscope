// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::{truncate, DissectedResult};

/// Dissect a Redis RESP message (TCP 6379).
///
/// RESP (REdis Serialization Protocol) is line-oriented: the first byte names
/// the type — `*` array, `$` bulk string, `+` simple string, `-` error, `:`
/// integer. Clients send commands as an array of bulk strings (`*2\r\n$3\r\n
/// GET\r\n$3\r\nfoo\r\n`); older clients and humans use the inline form
/// (`PING\r\n`). We surface the command name (or the reply) without decoding
/// the whole pipeline.
pub fn dissect_redis(
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
        protocol: Protocol::Redis,
        summary,
    };

    if payload.is_empty() {
        return result("Redis (empty)".into());
    }

    let summary = match payload[0] {
        b'+' => format!(
            "Redis reply — +{}",
            truncate(&first_line(&payload[1..]), 60)
        ),
        b'-' => format!("Redis error — {}", truncate(&first_line(&payload[1..]), 60)),
        b':' => format!(
            "Redis integer — {}",
            truncate(&first_line(&payload[1..]), 40)
        ),
        b'$' => "Redis bulk string reply".to_string(),
        b'*' => match redis_command(payload) {
            Some(cmd) => format!("Redis command — {}", truncate(&cmd, 60)),
            None => "Redis array".to_string(),
        },
        _ => {
            // Inline command form: the first word is the command verb.
            let line = first_line(payload);
            let verb = line.split_whitespace().next().unwrap_or("").to_uppercase();
            if verb.is_empty() {
                format!("Redis — {} bytes", payload.len())
            } else {
                format!("Redis command — {}", truncate(&line, 60))
            }
        }
    };

    result(summary)
}

/// Whether a payload looks enough like RESP to hand to the Redis dissector on
/// a non-standard port. Conservative: a RESP type byte plus a CRLF somewhere.
pub fn looks_like_resp(payload: &[u8]) -> bool {
    matches!(payload.first(), Some(b'*' | b'$' | b'+' | b'-' | b':'))
        && payload.windows(2).any(|w| w == b"\r\n")
}

/// Extract the command verb (and first argument) from a RESP array of bulk
/// strings: `*2\r\n$3\r\nGET\r\n$3\r\nfoo\r\n` → "GET foo".
fn redis_command(payload: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(payload);
    let mut lines = text.split("\r\n");
    let count_line = lines.next()?; // "*2"
    let n: usize = count_line.strip_prefix('*')?.parse().ok()?;
    let mut parts = Vec::new();
    for _ in 0..n.min(4) {
        let len_line = lines.next()?; // "$3"
        if !len_line.starts_with('$') {
            break;
        }
        let arg = lines.next()?;
        parts.push(arg.to_string());
    }
    if parts.is_empty() {
        return None;
    }
    // Upper-case the verb; leave arguments as-is.
    if let Some(first) = parts.first_mut() {
        *first = first.to_uppercase();
    }
    Some(parts.join(" "))
}

fn first_line(payload: &[u8]) -> String {
    let end = payload
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(payload.len());
    String::from_utf8_lossy(&payload[..end]).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resp_array_command() {
        let r = dissect_redis(None, None, 50000, 6379, b"*2\r\n$3\r\nGET\r\n$3\r\nfoo\r\n");
        assert_eq!(r.protocol, Protocol::Redis);
        assert_eq!(r.summary, "Redis command — GET foo");
    }

    #[test]
    fn simple_string_reply() {
        let r = dissect_redis(None, None, 6379, 50000, b"+OK\r\n");
        assert_eq!(r.summary, "Redis reply — +OK");
    }

    #[test]
    fn error_reply() {
        let r = dissect_redis(None, None, 6379, 50000, b"-ERR unknown command\r\n");
        assert!(r.summary.starts_with("Redis error — ERR"));
    }

    #[test]
    fn inline_command() {
        let r = dissect_redis(None, None, 50000, 6379, b"PING\r\n");
        assert_eq!(r.summary, "Redis command — PING");
    }

    #[test]
    fn resp_detection() {
        assert!(looks_like_resp(b"*1\r\n$4\r\nPING\r\n"));
        assert!(!looks_like_resp(b"GET / HTTP/1.1\r\n"));
    }
}
