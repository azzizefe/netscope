// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an RPKI-RTR message (TCP 323) — how a router pulls validated
/// route-origin data from an RPKI cache so it can reject BGP hijacks. Byte 1
/// is the PDU type (RFC 8210).
pub fn dissect_rpkirtr(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.get(1) {
        Some(&t) => {
            let name = match t {
                0 => "Serial Notify",
                1 => "Serial Query",
                2 => "Reset Query",
                3 => "Cache Response",
                4 => "IPv4 Prefix",
                6 => "IPv6 Prefix",
                7 => "End of Data",
                8 => "Cache Reset",
                10 => "Error Report",
                _ => "PDU",
            };
            format!("RPKI-RTR {name}")
        }
        None => "RPKI-RTR (truncated)".to_string(),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::RpkiRtr,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_response() {
        // version 1, PDU type 3 (Cache Response).
        let r = dissect_rpkirtr(None, None, 40000, 323, &[1, 3, 0, 0]);
        assert_eq!(r.protocol, Protocol::RpkiRtr);
        assert_eq!(r.summary, "RPKI-RTR Cache Response");
    }
}
