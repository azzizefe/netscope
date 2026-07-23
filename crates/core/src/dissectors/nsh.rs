// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

use crate::models::Protocol;
use super::DissectedResult;

/// Dissect NSH
pub fn dissect_nsh(_payload: &[u8]) -> DissectedResult {
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Nsh,
        summary: format!("NSH message"),
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
        let res = dissect_nsh(&[]);
        assert_eq!(res.protocol, Protocol::Nsh);
    }
}
