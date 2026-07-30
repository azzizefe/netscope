// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an H.225 call-signalling message (TCP 1720) — Q.931 call setup,
/// inherited from ISDN and carried over TPKT. This is where an H.323 call is
/// actually placed, answered and torn down.
pub fn dissect_q931(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    // TPKT(4) then Q.931: protocol discriminator 0x08, call-reference length,
    // the call reference itself, then the message type.
    let summary = if payload.len() >= 7 && payload[0] == 0x03 && payload[4] == 0x08 {
        let cr_len = payload[5] as usize;
        match payload.get(6 + cr_len) {
            Some(&mt) => {
                let name = match mt {
                    0x01 => "ALERTING",
                    0x02 => "CALL PROCEEDING",
                    0x05 => "SETUP",
                    0x07 => "CONNECT",
                    0x0F => "CONNECT ACK",
                    0x45 => "DISCONNECT",
                    0x4D => "RELEASE",
                    0x5A => "RELEASE COMPLETE",
                    0x62 => "FACILITY",
                    0x7B => "INFORMATION",
                    _ => "message",
                };
                format!("H.225/Q.931 {name}")
            }
            None => "H.225/Q.931 (truncated)".to_string(),
        }
    } else {
        format!(
            "H.225 call signalling ({})",
            super::bytes(payload.len() as u64)
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Q931,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup() {
        // TPKT, then Q.931 with a 2-byte call reference and message type SETUP.
        let p = [0x03, 0x00, 0x00, 0x20, 0x08, 0x02, 0x12, 0x34, 0x05];
        let r = dissect_q931(None, None, 40000, 1720, &p);
        assert_eq!(r.protocol, Protocol::Q931);
        assert_eq!(r.summary, "H.225/Q.931 SETUP");
    }
}
