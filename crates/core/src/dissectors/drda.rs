// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Structural check for DRDA: byte 2 is the DDM magic 0xD0. Port 50000 falls
/// inside the ephemeral range on Linux, so an unrelated flow can easily use it
/// as a source port — the magic is what makes the claim safe.
pub fn looks_like_drda(p: &[u8]) -> bool {
    p.len() >= 10 && p[2] == 0xD0
}

/// Dissect a DRDA message (TCP 50000) — Distributed Relational Database
/// Architecture, the protocol IBM Db2 clients speak. Byte 2 is the DDM magic
/// (0xD0) and bytes 8..10 the code point naming the command.
pub fn dissect_drda(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 10 && payload[2] == 0xD0 {
        let code_point = u16::from_be_bytes([payload[8], payload[9]]);
        let name = match code_point {
            0x1041 => "EXCSAT (exchange server attributes)",
            0x106D => "ACCRDB (access database)",
            0x1443 => "SQLSTT (SQL statement)",
            0x200C => "SQLSTTVRB",
            0x2001 => "SQLCARD",
            0x2408 => "QRYDTA (query data)",
            0x200A => "PRPSQLSTT (prepare)",
            0x2006 => "OPNQRY (open query)",
            _ => "command",
        };
        format!("DRDA {name}")
    } else {
        format!("DRDA ({} bytes)", payload.len())
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Drda,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exchange_server_attributes() {
        let mut p = vec![0x00, 0x40, 0xD0, 0x41, 0x00, 0x01, 0x00, 0x3A];
        p.extend_from_slice(&0x1041u16.to_be_bytes());
        let r = dissect_drda(None, None, 40000, 50000, &p);
        assert_eq!(r.protocol, Protocol::Drda);
        assert!(r.summary.contains("EXCSAT"), "{}", r.summary);
    }
}
