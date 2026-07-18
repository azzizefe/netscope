// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Structural check for MySQL X: the little-endian length must plausibly match
/// the frame and the message type must be one we know. Port 33060 sits in the
/// ephemeral range, so a port match alone would misclaim unrelated flows.
pub fn looks_like_mysqlx(p: &[u8]) -> bool {
    if p.len() < 5 {
        return false;
    }
    let len = u32::from_le_bytes([p[0], p[1], p[2], p[3]]) as usize;
    // The length counts the type byte and the payload after it.
    len >= 1 && len <= p.len().max(1) + 4 && matches!(p[4], 1..=6 | 12 | 17..=20)
}

/// Dissect a MySQL X Protocol message (TCP 33060) — the protobuf-based
/// protocol behind MySQL's document store and the X DevAPI, distinct from the
/// classic protocol on 3306. Bytes 0..4 are a little-endian length, byte 4 the
/// message type.
pub fn dissect_mysqlx(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.get(4) {
        Some(&t) => {
            let name = match t {
                1 => "CapabilitiesGet",
                2 => "CapabilitiesSet",
                4 => "AuthenticateStart",
                5 => "AuthenticateContinue",
                6 => "Close",
                12 => "StmtExecute",
                17 => "CrudFind",
                18 => "CrudInsert",
                19 => "CrudUpdate",
                20 => "CrudDelete",
                _ => "message",
            };
            format!("MySQL X {name}")
        }
        None => format!("MySQL X ({} bytes)", payload.len()),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::MysqlX,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stmt_execute() {
        let mut p = 24u32.to_le_bytes().to_vec();
        p.push(12); // StmtExecute
        let r = dissect_mysqlx(None, None, 40000, 33060, &p);
        assert_eq!(r.protocol, Protocol::MysqlX);
        assert_eq!(r.summary, "MySQL X StmtExecute");
    }
}
