// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an EAPOL frame (EtherType 0x888E) — 802.1X port authentication,
/// including the WPA/WPA2 4-way key handshake. Byte 0 is the version, byte 1
/// the packet type (IEEE 802.1X).
pub fn dissect_eapol(payload: &[u8]) -> DissectedResult {
    // Type 0 encapsulates an EAP packet — hand it to the EAP dissector so the
    // authentication method (PEAP, TLS, …) is named rather than hidden.
    if payload.get(1) == Some(&0) && payload.len() > 4 {
        return super::eap::dissect_eap(&payload[4..]);
    }
    let summary = match payload.get(1) {
        Some(&t) => {
            let name = match t {
                0 => "EAP packet",
                1 => "Start",
                2 => "Logoff",
                3 => "Key (WPA handshake)",
                4 => "Encapsulated-ASF-Alert",
                _ => "frame",
            };
            format!("EAPOL {name}")
        }
        None => "EAPOL (truncated)".to_string(),
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Eapol,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_handshake() {
        // version 2, type 3 (Key).
        let r = dissect_eapol(&[0x02, 0x03, 0x00, 0x5F]);
        assert_eq!(r.protocol, Protocol::Eapol);
        assert_eq!(r.summary, "EAPOL Key (WPA handshake)");
    }

    #[test]
    fn start() {
        let r = dissect_eapol(&[0x01, 0x01, 0x00, 0x00]);
        assert_eq!(r.summary, "EAPOL Start");
    }
}
