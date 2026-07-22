// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect Reliable Internet Stream Transport (RIST VSF TR-06-1 / TR-06-2, UDP 20000/20001).
pub fn dissect_rist(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 4 {
        let pt = payload.get(1).copied().unwrap_or(0);
        let kind = match pt {
            200 | 201 => "RTCP Feedback",
            204 => "ARQ NACK",
            205 => "Generic NACK / Range NACK",
            _ => "Data Stream",
        };
        format!("RIST Media Transport {kind} (PT {pt})")
    } else {
        format!("RIST Media Transport ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Rist,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rist_nack() {
        let payload = vec![0x80, 204, 0x00, 0x02];
        let r = dissect_rist(None, None, 40000, 20000, &payload);
        assert_eq!(r.protocol, Protocol::Rist);
        assert_eq!(r.summary, "RIST Media Transport ARQ NACK (PT 204)");
    }
}
