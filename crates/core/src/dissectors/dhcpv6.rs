// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a DHCPv6 message (UDP 546/547). The first byte is the message type
/// and the next three are the transaction id (RFC 8415).
pub fn dissect_dhcpv6(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.first() {
        Some(&t) => {
            let name = match t {
                1 => "Solicit",
                2 => "Advertise",
                3 => "Request",
                4 => "Confirm",
                5 => "Renew",
                6 => "Rebind",
                7 => "Reply",
                8 => "Release",
                9 => "Decline",
                10 => "Reconfigure",
                11 => "Information-Request",
                12 => "Relay-Forward",
                13 => "Relay-Reply",
                _ => "message",
            };
            let is_pd = payload.get(4..).is_some_and(|opts| opts.windows(2).any(|w| w[0] == 0 && (w[1] == 25 || w[1] == 26)));
            let pd_suffix = if is_pd { " (Prefix Delegation PD)" } else { "" };
            format!("DHCPv6 {name}{pd_suffix}")
        }
        None => "DHCPv6 (empty)".to_string(),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Dhcpv6,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solicit() {
        let r = dissect_dhcpv6(None, None, 546, 547, &[0x01, 0xAB, 0xCD, 0xEF]);
        assert_eq!(r.protocol, Protocol::Dhcpv6);
        assert_eq!(r.summary, "DHCPv6 Solicit");
    }

    #[test]
    fn reply() {
        let r = dissect_dhcpv6(None, None, 547, 546, &[0x07, 0x00, 0x00, 0x01]);
        assert_eq!(r.summary, "DHCPv6 Reply");
    }
}
