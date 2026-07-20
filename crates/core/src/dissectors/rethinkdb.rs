// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a RethinkDB message (TCP 28015) — the client protocol for the
/// document database. A connection opens with a little-endian version magic.
pub fn dissect_rethinkdb(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 4 {
        let magic = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        match magic {
            0x3f61_ba36 => "RethinkDB V0.1 handshake".to_string(),
            0x5f75_e83e => "RethinkDB V0.2 handshake".to_string(),
            0x5f75_e831 => "RethinkDB V0.3 handshake".to_string(),
            0x400c_2d20 => "RethinkDB V0.4 handshake".to_string(),
            0x34c2_bdc3 => "RethinkDB V1.0 handshake".to_string(),
            _ => format!("RethinkDB query ({})", super::bytes(payload.len() as u64)),
        }
    } else {
        format!("RethinkDB ({})", super::bytes(payload.len() as u64))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Rethinkdb,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_handshake() {
        // V1.0 magic 0x34c2bdc3 in little-endian byte order.
        let r = dissect_rethinkdb(None, None, 40000, 28015, &[0xc3, 0xbd, 0xc2, 0x34]);
        assert_eq!(r.protocol, Protocol::Rethinkdb);
        assert_eq!(r.summary, "RethinkDB V1.0 handshake");
    }
}
