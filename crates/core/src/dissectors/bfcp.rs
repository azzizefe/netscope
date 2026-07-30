// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a BFCP message (TCP 3238) — Binary Floor Control Protocol, which
/// arbitrates who currently holds "the floor" in a conference: who may speak,
/// or who is sharing their screen. Byte 1 is the primitive (RFC 8855).
pub fn dissect_bfcp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.get(1) {
        Some(&prim) => {
            let name = match prim {
                1 => "FloorRequest",
                2 => "FloorRelease",
                3 => "FloorRequestQuery",
                4 => "FloorRequestStatus",
                5 => "UserQuery",
                6 => "UserStatus",
                7 => "FloorQuery",
                8 => "FloorStatus",
                9 => "ChairAction",
                11 => "Hello",
                13 => "Error",
                _ => "primitive",
            };
            format!("BFCP {name}")
        }
        None => "BFCP (truncated)".to_string(),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Bfcp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_request() {
        let r = dissect_bfcp(None, None, 40000, 3238, &[0x20, 0x01, 0x00, 0x08]);
        assert_eq!(r.protocol, Protocol::Bfcp);
        assert_eq!(r.summary, "BFCP FloorRequest");
    }
}
