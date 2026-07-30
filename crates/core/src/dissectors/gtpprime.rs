// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a GTP' (GTP prime) message (UDP 3386) — the charging variant of GTP
/// that ships Call Detail Records from network nodes to the billing system.
/// Byte 1 is the message type (3GPP TS 32.295).
pub fn dissect_gtpprime(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.get(1) {
        Some(&t) => {
            let name = match t {
                1 => "Echo Request",
                2 => "Echo Response",
                4 => "Node Alive Request",
                5 => "Node Alive Response",
                6 => "Redirection Request",
                7 => "Redirection Response",
                240 => "Data Record Transfer Request",
                241 => "Data Record Transfer Response",
                _ => "message",
            };
            format!("GTP' (charging) {name}")
        }
        None => "GTP' (truncated)".to_string(),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::GtpPrime,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cdr_transfer() {
        let r = dissect_gtpprime(None, None, 3386, 3386, &[0x0E, 240, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::GtpPrime);
        assert_eq!(r.summary, "GTP' (charging) Data Record Transfer Request");
    }
}
