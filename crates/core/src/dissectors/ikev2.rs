// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// IKEv2 Exchange Types (RFC 7296 §3.3).
fn ikev2_exchange_name(exch: u8) -> &'static str {
    match exch {
        34 => "IKE_SA_INIT",
        35 => "IKE_AUTH",
        36 => "CREATE_CHILD_SA",
        37 => "INFORMATIONAL",
        38 => "IKE_SESSION_RESUME",
        _ => "IKEv2 Exchange",
    }
}

/// Dissect an IKEv2 message (UDP 500 / 4500).
pub fn dissect_ikev2(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let body = if (src_port == 4500 || dst_port == 4500)
        && payload.len() >= 4
        && payload[..4] == [0, 0, 0, 0]
    {
        &payload[4..]
    } else {
        payload
    };

    let summary = if body.len() < 28 {
        format!("IKEv2 ({})", super::bytes(body.len() as u64))
    } else {
        let exch = body[18];
        let exch_name = ikev2_exchange_name(exch);
        let is_resp = (body[19] & 0x20) != 0;
        let role = if is_resp { "Response" } else { "Request" };

        format!("IKEv2 {exch_name} — {role}")
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Ikev2,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ikev2_sa_init() {
        let mut payload = vec![0u8; 28];
        payload[17] = 0x20; // Version 2.0
        payload[18] = 34;   // IKE_SA_INIT
        let res = dissect_ikev2(None, None, 500, 500, &payload);
        assert_eq!(res.protocol, Protocol::Ikev2);
        assert!(res.summary.contains("IKE_SA_INIT"));
    }

    #[test]
    fn test_ikev2_short_payload() {
        let payload = vec![0x00, 0x01];
        let res = dissect_ikev2(None, None, 500, 500, &payload);
        assert_eq!(res.protocol, Protocol::Ikev2);
        assert!(res.summary.contains("IKEv2 (2 bytes)"));
    }
}
