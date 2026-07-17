// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an S7comm message (TCP 102) — the protocol Siemens S7 PLCs speak,
/// carried over TPKT + ISO-COTP. A TPKT header starts with 0x03; the S7
/// payload begins with protocol id 0x32 and a ROSCTR message class.
pub fn dissect_s7comm(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    // TPKT(4) + COTP(3 for a data TPDU) puts the S7 protocol id at offset 7.
    let summary = if payload.first() == Some(&0x03) && payload.get(7) == Some(&0x32) {
        let name = match payload.get(8) {
            Some(0x01) => "Job request",
            Some(0x02) => "Ack",
            Some(0x03) => "Ack-Data",
            Some(0x07) => "Userdata",
            _ => "message",
        };
        format!("S7comm {name}")
    } else if payload.first() == Some(&0x03) {
        "COTP / ISO-on-TCP (port 102)".to_string()
    } else {
        format!("S7comm ({} bytes)", payload.len())
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::S7comm,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_request() {
        // TPKT(0x03 00 00 1f) + COTP(02 f0 80) + S7(0x32 01 …).
        let mut p = vec![0x03, 0x00, 0x00, 0x1f, 0x02, 0xf0, 0x80];
        p.push(0x32); // S7 protocol id
        p.push(0x01); // ROSCTR: Job
        let r = dissect_s7comm(None, None, 40000, 102, &p);
        assert_eq!(r.protocol, Protocol::S7comm);
        assert_eq!(r.summary, "S7comm Job request");
    }
}
