// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a TFTP message (UDP 69). The first two bytes are the opcode:
/// 1 RRQ, 2 WRQ, 3 DATA, 4 ACK, 5 ERROR (RFC 1350).
pub fn dissect_tftp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = parse(payload).unwrap_or_else(|| format!("TFTP ({} bytes)", payload.len()));
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Tftp,
        summary,
    }
}

fn parse(p: &[u8]) -> Option<String> {
    if p.len() < 4 {
        return None;
    }
    let opcode = u16::from_be_bytes([p[0], p[1]]);
    let block = || u16::from_be_bytes([p[2], p[3]]);
    Some(match opcode {
        1 | 2 => {
            let rest = &p[2..];
            let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
            let name = super::truncate(&String::from_utf8_lossy(&rest[..end]), 50);
            let verb = if opcode == 1 { "Read" } else { "Write" };
            format!("TFTP {verb} Request — {name}")
        }
        3 => format!("TFTP Data — block {}", block()),
        4 => format!("TFTP Ack — block {}", block()),
        5 => format!("TFTP Error — code {}", block()),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_request() {
        let mut p = vec![0x00, 0x01];
        p.extend_from_slice(b"boot.img\0octet\0");
        let r = dissect_tftp(None, None, 40000, 69, &p);
        assert_eq!(r.protocol, Protocol::Tftp);
        assert_eq!(r.summary, "TFTP Read Request — boot.img");
    }

    #[test]
    fn data_block() {
        let r = dissect_tftp(None, None, 40000, 69, &[0x00, 0x03, 0x00, 0x07, 0xAA]);
        assert_eq!(r.summary, "TFTP Data — block 7");
    }
}
