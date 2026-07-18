// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a DHCP failover message (TCP 647) — the channel two DHCP servers
/// use to stay in sync so either can keep handing out leases if the other
/// dies. Byte 8 is the message type.
pub fn dissect_dhcpfo(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.get(8) {
        Some(&t) => {
            let name = match t {
                1 => "POOLREQ",
                2 => "POOLRESP",
                3 => "BNDUPD (binding update)",
                4 => "BNDACK",
                5 => "CONNECT",
                6 => "CONNECTACK",
                7 => "UPDREQ",
                9 => "UPDDONE",
                10 => "STATE",
                11 => "CONTACT",
                12 => "DISCONNECT",
                _ => "message",
            };
            format!("DHCP failover {name}")
        }
        None => format!("DHCP failover ({} bytes)", payload.len()),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::DhcpFailover,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_update() {
        let mut p = vec![0u8; 8];
        p.push(3); // BNDUPD
        let r = dissect_dhcpfo(None, None, 40000, 647, &p);
        assert_eq!(r.protocol, Protocol::DhcpFailover);
        assert!(r.summary.contains("BNDUPD"), "{}", r.summary);
    }
}
