// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a UDLD frame (LLC/SNAP, Cisco OUI, PID 0x0111) — UniDirectional Link
/// Detection, which spots fibre links that pass traffic one way only (a failure
/// mode that can otherwise break spanning tree). The low nibble of byte 0 is
/// the opcode.
pub fn dissect_udld(body: &[u8]) -> DissectedResult {
    let summary = match body.first() {
        Some(&b) => {
            let name = match b & 0x0F {
                0 => "reserved",
                1 => "probe",
                2 => "echo",
                3 => "flush",
                _ => "message",
            };
            format!("UDLD {name}")
        }
        None => "UDLD (empty)".to_string(),
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Udld,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe() {
        let r = dissect_udld(&[0x21, 0x00]);
        assert_eq!(r.protocol, Protocol::Udld);
        assert_eq!(r.summary, "UDLD probe");
    }
}
