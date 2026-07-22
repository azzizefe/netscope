// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a SynOptics / Nortel Discovery Protocol (SONMP / NDP) frame.
pub fn dissect_sonmp(payload: &[u8]) -> DissectedResult {
    let summary = if payload.len() >= 4 {
        format!("Nortel SONMP / NDP Announcement ({})", super::bytes(payload.len() as u64))
    } else {
        format!("Nortel SONMP ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Sonmp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sonmp_frame() {
        let payload = vec![0x0A, 0x00, 0x01, 0x02];
        let r = dissect_sonmp(&payload);
        assert_eq!(r.protocol, Protocol::Sonmp);
        assert!(r.summary.contains("Nortel SONMP"));
    }
}
