// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::{truncate, DissectedResult};

/// Dissect a MySQL/MariaDB protocol packet (TCP 3306).
///
/// Every MySQL packet starts with a 4-byte header: a 3-byte little-endian
/// payload length and a 1-byte sequence number. The body's first byte then
/// disambiguates: the server's initial handshake begins with the protocol
/// version (usually 10 = 0x0a); client commands begin with a command byte
/// (0x03 = COM_QUERY, followed by the SQL text). We name the message and,
/// for a query, show the SQL.
pub fn dissect_mysql(
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
        protocol: Protocol::Mysql,
        summary,
    };

    if payload.len() < 5 {
        return result("MySQL (partial)".into());
    }

    let seq = payload[3];
    let body = &payload[4..];
    let first = body[0];

    // Server handshake: sequence 0, protocol version 10, then a NUL-terminated
    // version string.
    if seq == 0 && first == 0x0a {
        let ver = trim_c_string(&body[1..]);
        return result(format!("MySQL Server handshake — {}", truncate(&ver, 40)));
    }

    // OK / ERR / EOF response markers.
    if first == 0x00 && seq > 0 {
        return result("MySQL OK".to_string());
    }
    if first == 0xff {
        // ERR packet: 2-byte error code follows.
        let code = if body.len() >= 3 {
            u16::from_le_bytes([body[1], body[2]])
        } else {
            0
        };
        return result(format!("MySQL Error {code}"));
    }
    if first == 0xfe && body.len() < 9 {
        return result("MySQL EOF".to_string());
    }

    // Client command phase: sequence 0, first byte is the command.
    let summary = match first {
        0x01 => "MySQL COM_QUIT".to_string(),
        0x02 => "MySQL COM_INIT_DB".to_string(),
        0x03 => format!(
            "MySQL Query — {}",
            truncate(String::from_utf8_lossy(&body[1..]).trim(), 70)
        ),
        0x04 => "MySQL COM_FIELD_LIST".to_string(),
        0x0e => "MySQL COM_PING".to_string(),
        0x16 => "MySQL COM_STMT_PREPARE".to_string(),
        0x17 => "MySQL COM_STMT_EXECUTE".to_string(),
        _ => format!("MySQL — {} byte packet (seq {seq})", payload.len()),
    };

    result(summary)
}

fn trim_c_string(body: &[u8]) -> String {
    let end = memchr::memchr(0, body).unwrap_or(body.len());
    String::from_utf8_lossy(&body[..end]).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(seq: u8, body: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        let len = body.len() as u32;
        p.push((len & 0xff) as u8);
        p.push(((len >> 8) & 0xff) as u8);
        p.push(((len >> 16) & 0xff) as u8);
        p.push(seq);
        p.extend_from_slice(body);
        p
    }

    #[test]
    fn com_query() {
        let mut body = vec![0x03];
        body.extend_from_slice(b"SELECT * FROM users");
        let p = packet(0, &body);
        let r = dissect_mysql(None, None, 50000, 3306, &p);
        assert_eq!(r.protocol, Protocol::Mysql);
        assert_eq!(r.summary, "MySQL Query — SELECT * FROM users");
    }

    #[test]
    fn server_handshake() {
        let mut body = vec![0x0a];
        body.extend_from_slice(b"8.0.32\0");
        let p = packet(0, &body);
        let r = dissect_mysql(None, None, 3306, 50000, &p);
        assert!(r.summary.starts_with("MySQL Server handshake — 8.0.32"));
    }

    #[test]
    fn error_packet() {
        let mut body = vec![0xff];
        body.extend_from_slice(&1045u16.to_le_bytes());
        let p = packet(2, &body);
        let r = dissect_mysql(None, None, 3306, 50000, &p);
        assert_eq!(r.summary, "MySQL Error 1045");
    }
}
