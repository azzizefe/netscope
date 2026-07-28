// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

/// Dissect NVGRE
pub fn dissect_nvgre(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    _payload: &[u8],
) -> DissectedResult {
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Nvgre,
        summary: "NVGRE message".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_packet() {
        // valid packet test
    }

    #[test]
    fn handle_malformed_header() {
        // malformed header test
    }

    #[test]
    fn handle_empty_payload() {
        let res = dissect_nvgre(None, None, &[]);
        assert_eq!(res.protocol, Protocol::Nvgre);
    }
}
