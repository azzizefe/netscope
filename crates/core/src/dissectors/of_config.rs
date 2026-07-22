// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect OpenFlow Management & Configuration OF-CONFIG (TCP 830 / 6653).
pub fn dissect_of_config(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.contains(&b'o') && payload.contains(&b'f') && payload.contains(&b'c') {
        "OF-CONFIG Netconf message".to_string()
    } else {
        format!("OF-CONFIG ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::OfConfig,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn of_config_test() {
        let r = dissect_of_config(None, None, 40000, 6653, b"<rpc><of-config></of-config></rpc>");
        assert_eq!(r.protocol, Protocol::OfConfig);
        assert_eq!(r.summary, "OF-CONFIG Netconf message");
    }
}
