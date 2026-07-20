// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an Oracle TNS message (TCP 1521) — Transparent Network Substrate,
/// the transport every Oracle client uses to reach the database listener.
/// Byte 4 is the packet type.
pub fn dissect_tns(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.get(4) {
        Some(&t) => {
            let name = match t {
                1 => "Connect",
                2 => "Accept",
                3 => "Acknowledge",
                4 => "Refuse",
                5 => "Redirect",
                6 => "Data",
                7 => "Null",
                9 => "Abort",
                11 => "Resend",
                12 => "Marker",
                14 => "Control",
                _ => "packet",
            };
            format!("Oracle TNS {name}")
        }
        None => format!("Oracle TNS ({})", super::bytes(payload.len() as u64)),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Tns,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect() {
        // length(2), checksum(2), type 1 (Connect).
        let r = dissect_tns(None, None, 40000, 1521, &[0x00, 0x3A, 0x00, 0x00, 0x01]);
        assert_eq!(r.protocol, Protocol::Tns);
        assert_eq!(r.summary, "Oracle TNS Connect");
    }
}
