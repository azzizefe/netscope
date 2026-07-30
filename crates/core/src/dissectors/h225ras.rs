// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an H.225 RAS message (UDP 1719) — Registration, Admission and
/// Status, how an H.323 endpoint finds its gatekeeper, registers, and asks
/// permission to place each call. The ASN.1 PER choice index in the top bits
/// of byte 0 selects the message.
pub fn dissect_h225ras(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.first() {
        Some(&b) => {
            let name = match b >> 3 {
                0 => "GatekeeperRequest",
                1 => "GatekeeperConfirm",
                2 => "GatekeeperReject",
                3 => "RegistrationRequest",
                4 => "RegistrationConfirm",
                5 => "RegistrationReject",
                6 => "UnregistrationRequest",
                8 => "AdmissionRequest",
                9 => "AdmissionConfirm",
                10 => "AdmissionReject",
                14 => "DisengageRequest",
                _ => "message",
            };
            format!("H.225 RAS {name}")
        }
        None => "H.225 RAS (empty)".to_string(),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::H225Ras,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_request() {
        // Choice index 3 in the top five bits.
        let r = dissect_h225ras(None, None, 40000, 1719, &[0x18, 0x00]);
        assert_eq!(r.protocol, Protocol::H225Ras);
        assert_eq!(r.summary, "H.225 RAS RegistrationRequest");
    }
}
