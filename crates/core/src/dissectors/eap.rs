// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Name the EAP authentication method carried in a Request/Response.
fn method_name(t: u8) -> &'static str {
    match t {
        1 => "Identity",
        2 => "Notification",
        3 => "NAK",
        4 => "MD5-Challenge",
        6 => "GTC",
        13 => "TLS",
        17 => "LEAP",
        21 => "TTLS",
        25 => "PEAP",
        43 => "FAST",
        50 => "AKA'",
        _ => "method",
    }
}

/// Dissect an EAP packet (carried inside EAPOL, or RADIUS) — the negotiation
/// that decides *how* a device proves its identity on an 802.1X network or
/// enterprise Wi-Fi. Byte 0 is the code; for Request/Response byte 4 names the
/// method (RFC 3748).
pub fn dissect_eap(body: &[u8]) -> DissectedResult {
    let summary = match body.first() {
        Some(1) => format!(
            "EAP Request — {}",
            method_name(body.get(4).copied().unwrap_or(0))
        ),
        Some(2) => format!(
            "EAP Response — {}",
            method_name(body.get(4).copied().unwrap_or(0))
        ),
        Some(3) => "EAP Success".to_string(),
        Some(4) => "EAP Failure".to_string(),
        _ => format!("EAP packet ({} bytes)", body.len()),
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Eap,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peap_response() {
        // code 2 (Response), id, length(2), type 25 (PEAP).
        let r = dissect_eap(&[0x02, 0x01, 0x00, 0x06, 25]);
        assert_eq!(r.protocol, Protocol::Eap);
        assert_eq!(r.summary, "EAP Response — PEAP");
    }

    #[test]
    fn success() {
        let r = dissect_eap(&[0x03, 0x01, 0x00, 0x04]);
        assert_eq!(r.summary, "EAP Success");
    }
}
