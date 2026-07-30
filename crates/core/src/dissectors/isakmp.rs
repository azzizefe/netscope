// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an ISAKMP/IKE message (UDP 500, or 4500 with NAT-traversal) — the
/// key-exchange that sets up IPsec VPN tunnels. On 4500 a 4-byte zero non-ESP
/// marker precedes the header; the exchange type sits at offset 18 (RFC 7296).
pub fn dissect_isakmp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    // Strip the NAT-T non-ESP marker (four zero bytes) seen on UDP 4500.
    let body = if (src_port == 4500 || dst_port == 4500)
        && payload.len() >= 4
        && payload[..4] == [0, 0, 0, 0]
    {
        &payload[4..]
    } else {
        payload
    };
    let summary = match (body.get(17), body.get(18)) {
        (Some(&version), Some(&exch)) => {
            let ikev2 = version >> 4 == 2;
            let name = if ikev2 {
                match exch {
                    34 => "IKE_SA_INIT",
                    35 => "IKE_AUTH",
                    36 => "CREATE_CHILD_SA",
                    37 => "INFORMATIONAL",
                    _ => "exchange",
                }
            } else {
                match exch {
                    2 => "Identity Protection (Main Mode)",
                    4 => "Aggressive Mode",
                    5 => "Informational",
                    32 => "Quick Mode",
                    _ => "exchange",
                }
            };
            let ver = if ikev2 { "IKEv2" } else { "IKEv1" };
            format!("ISAKMP/{ver} {name}")
        }
        _ => "ISAKMP/IKE (truncated)".to_string(),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Isakmp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ikev2_sa_init() {
        // 16-byte SPIs, next payload, version 0x20 (IKEv2), exchange 34.
        let mut p = vec![0u8; 17];
        p.push(0x20); // version
        p.push(34); // exchange type: IKE_SA_INIT
        let r = dissect_isakmp(None, None, 500, 500, &p);
        assert_eq!(r.protocol, Protocol::Isakmp);
        assert_eq!(r.summary, "ISAKMP/IKEv2 IKE_SA_INIT");
    }
}
