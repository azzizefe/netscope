// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect GSM_BSSMAP_LE
pub fn dissect_gsm_bssmap_le(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    _payload: &[u8],
) -> DissectedResult {
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::GsmBssmapLe,
        summary: format!("GSM_BSSMAP_LE message"),
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
        let res = dissect_gsm_bssmap_le(None, None, 0, 0, &[]);
        assert_eq!(res.protocol, Protocol::GsmBssmapLe);
    }
}
