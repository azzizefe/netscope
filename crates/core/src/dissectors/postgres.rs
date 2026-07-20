// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::{truncate, DissectedResult};

/// Dissect a PostgreSQL frontend/backend message (TCP 5432).
///
/// After the startup handshake every message is `type(1) + length(Int32, big
/// endian, counting itself) + body`. The startup and SSL-request messages are
/// the exception: they have no type byte, just a length followed by a protocol
/// version (0x00030000) or the SSL magic (80877103). We name the message and,
/// for a Simple Query ('Q'), show the SQL text.
pub fn dissect_postgres(
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
        protocol: Protocol::Postgres,
        summary,
    };

    if payload.len() < 5 {
        return result("PostgreSQL (partial)".into());
    }

    // Untyped startup-phase messages: length(Int32) then a 4-byte code.
    if payload[0] == 0 && payload.len() >= 8 {
        let code = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        return result(match code {
            0x0003_0000 => "PostgreSQL StartupMessage (protocol 3.0)".to_string(),
            80877103 => "PostgreSQL SSLRequest".to_string(),
            80877102 => "PostgreSQL CancelRequest".to_string(),
            80877104 => "PostgreSQL GSSENCRequest".to_string(),
            _ => "PostgreSQL startup".to_string(),
        });
    }

    let type_byte = payload[0];
    let body = &payload[5..];
    let summary = match type_byte {
        b'Q' => {
            let sql = trim_c_string(body);
            format!("PostgreSQL Query — {}", truncate(&sql, 70))
        }
        b'P' => "PostgreSQL Parse (prepared statement)".to_string(),
        b'B' => "PostgreSQL Bind".to_string(),
        b'E' if is_backend_error(body) => {
            format!("PostgreSQL Error — {}", truncate(&error_text(body), 60))
        }
        b'E' => "PostgreSQL Execute".to_string(),
        b'R' => "PostgreSQL Authentication".to_string(),
        b'C' => format!(
            "PostgreSQL CommandComplete — {}",
            truncate(&trim_c_string(body), 40)
        ),
        b'T' => "PostgreSQL RowDescription".to_string(),
        b'D' => "PostgreSQL DataRow".to_string(),
        b'Z' => "PostgreSQL ReadyForQuery".to_string(),
        b'S' => "PostgreSQL ParameterStatus".to_string(),
        b'X' => "PostgreSQL Terminate".to_string(),
        other if other.is_ascii_graphic() => {
            format!("PostgreSQL message '{}'", other as char)
        }
        _ => format!("PostgreSQL — {}", super::bytes(payload.len() as u64)),
    };

    result(summary)
}

/// The backend Error and CommandComplete messages both use type 'E'/'C'; a
/// backend ErrorResponse body is a series of `field-code + string` records
/// (severity 'S', message 'M', …). Detect one so we don't mislabel a frontend
/// Execute as an error.
fn is_backend_error(body: &[u8]) -> bool {
    matches!(body.first(), Some(b'S' | b'M' | b'C')) && body.iter().any(|&b| b == b'M' || b == 0)
}

/// Pull the human-readable message ('M' field) out of an ErrorResponse body.
fn error_text(body: &[u8]) -> String {
    let mut i = 0;
    while i < body.len() {
        let code = body[i];
        if code == 0 {
            break;
        }
        let start = i + 1;
        let end = memchr::memchr(0, &body[start..])
            .map(|p| start + p)
            .unwrap_or(body.len());
        if code == b'M' {
            return String::from_utf8_lossy(&body[start..end]).to_string();
        }
        i = end + 1;
    }
    String::from_utf8_lossy(body).trim().to_string()
}

fn trim_c_string(body: &[u8]) -> String {
    let end = memchr::memchr(0, body).unwrap_or(body.len());
    String::from_utf8_lossy(&body[..end]).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_query() {
        // 'Q' + length + "SELECT 1;\0"
        let sql = b"SELECT 1;\0";
        let mut p = vec![b'Q'];
        p.extend_from_slice(&((sql.len() + 4) as u32).to_be_bytes());
        p.extend_from_slice(sql);
        let r = dissect_postgres(None, None, 50000, 5432, &p);
        assert_eq!(r.protocol, Protocol::Postgres);
        assert_eq!(r.summary, "PostgreSQL Query — SELECT 1;");
    }

    #[test]
    fn startup_message() {
        let mut p = Vec::new();
        p.extend_from_slice(&16u32.to_be_bytes());
        p.extend_from_slice(&0x0003_0000u32.to_be_bytes());
        p.extend_from_slice(&[0u8; 8]);
        let r = dissect_postgres(None, None, 50000, 5432, &p);
        assert!(r.summary.contains("StartupMessage"));
    }

    #[test]
    fn ssl_request() {
        let mut p = Vec::new();
        p.extend_from_slice(&8u32.to_be_bytes());
        p.extend_from_slice(&80877103u32.to_be_bytes());
        let r = dissect_postgres(None, None, 50000, 5432, &p);
        assert_eq!(r.summary, "PostgreSQL SSLRequest");
    }

    #[test]
    fn ready_for_query() {
        let p = vec![b'Z', 0, 0, 0, 5, b'I'];
        let r = dissect_postgres(None, None, 5432, 50000, &p);
        assert_eq!(r.summary, "PostgreSQL ReadyForQuery");
    }
}
