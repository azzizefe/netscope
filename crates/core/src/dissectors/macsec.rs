// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a MACsec frame (EtherType 0x88E5) — IEEE 802.1AE hop-by-hop
/// Ethernet encryption. The SecTAG's first byte is the TCI/AN; the low two
/// bits are the association number, and the encrypt bit marks the payload as
/// confidential.
pub fn dissect_macsec(payload: &[u8]) -> DissectedResult {
    let summary = match payload.first() {
        Some(&tci) => {
            let an = tci & 0x03;
            let encrypted = tci & 0x08 != 0;
            if encrypted {
                format!("MACsec — encrypted (AN {an})")
            } else {
                format!("MACsec — integrity-only (AN {an})")
            }
        }
        None => "MACsec (truncated)".to_string(),
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Macsec,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted() {
        // TCI with encrypt bit (0x08) set, AN 1.
        let r = dissect_macsec(&[0x0D, 0x00, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::Macsec);
        assert_eq!(r.summary, "MACsec — encrypted (AN 1)");
    }
}
