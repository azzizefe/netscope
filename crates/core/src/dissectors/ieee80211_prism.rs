// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect an IEEE80211-PRISM packet.
pub fn dissect_ieee80211_prism(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Ieee80211Prism,
        summary: format!("IEEE80211-PRISM ({})", super::bytes(payload.len() as u64)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ieee80211_prism() {
        let r = dissect_ieee80211_prism(None, None, 0, 0, b"\x00\x01");
        assert_eq!(r.protocol, Protocol::Ieee80211Prism);
    }
}
