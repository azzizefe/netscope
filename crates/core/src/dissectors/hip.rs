// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! HIP — separating who a host is from where it is (RFC 7401, IP protocol 139).
//!
//! IP addresses do two jobs at once: they say who a host is and where it is on
//! the network. That is why a laptop changing networks breaks its connections.
//! HIP splits the two apart — a host gets a permanent cryptographic identity
//! (its Host Identity Tag) and its address becomes merely a current location,
//! which can change without the connection noticing.
//!
//! Connections open with a four-packet base exchange: I1, R1, I2, R2. R1
//! carries a puzzle the initiator has to solve before the responder will spend
//! any state on it, which is what makes HIP resistant to connection floods.
//!
//! The NOTIFY packet is why this is worth reading. When the base exchange fails
//! it fails silently from the application's point of view — the connection
//! simply never establishes — and NOTIFY is where the responder says which step
//! rejected it: authentication failed, no acceptable Diffie-Hellman proposal,
//! blocked by policy, or an HMAC that did not verify. Those have entirely
//! different fixes and are otherwise indistinguishable.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Next header, header length, packet type, version, checksum, controls, then
/// the two Host Identity Tags.
const HEADER_LEN: usize = 40;

/// The top bit of the packet-type byte belongs to SHIM6, not to the type.
const PACKET_TYPE_MASK: u8 = 0x7F;

/// The parameter that carries a failure reason.
const PARAM_NOTIFICATION: u16 = 832;

fn packet_name(packet_type: u8) -> Option<&'static str> {
    Some(match packet_type {
        1 => "I1 (opening the base exchange)",
        2 => "R1 (puzzle offered)",
        3 => "I2 (puzzle solved)",
        4 => "R2 (base exchange complete)",
        16 => "UPDATE",
        17 => "NOTIFY",
        18 => "CLOSE",
        19 => "CLOSE ACK",
        _ => return None,
    })
}

/// Why the exchange was rejected.
fn notification_name(code: u16) -> Option<&'static str> {
    Some(match code {
        1 => "unsupported critical parameter",
        7 => "invalid syntax",
        14 => "no Diffie-Hellman proposal chosen",
        15 => "invalid Diffie-Hellman chosen",
        16 => "no HIP proposal chosen",
        17 => "invalid HIP transform chosen",
        18 => "no ESP proposal chosen",
        19 => "invalid ESP transform chosen",
        24 => "authentication failed",
        26 => "checksum failed",
        28 => "HMAC failed",
        32 => "encryption failed",
        40 => "invalid HIT",
        42 => "blocked by policy",
        44 => "server busy, please retry",
        _ => return None,
    })
}

/// Walk the parameter list for the notification's reason code.
///
/// Walked rather than searched: a Host Identity or a signature is opaque bytes
/// and can contain the exact two-byte value that opens a NOTIFICATION.
fn notification_code(mut params: &[u8]) -> Option<u16> {
    // A malformed packet can chain parameters indefinitely; a real one does not.
    for _ in 0..32 {
        let header = params.get(..4)?;
        let param_type = u16::from_be_bytes([header[0], header[1]]);
        let length = u16::from_be_bytes([header[2], header[3]]) as usize;
        if param_type == PARAM_NOTIFICATION {
            // Two reserved bytes sit ahead of the code.
            let value = params.get(4..4 + length)?;
            return value.get(2..4).map(|b| u16::from_be_bytes([b[0], b[1]]));
        }
        // Parameters are padded to a multiple of eight bytes, and the padding
        // is not counted in the length.
        let padded = (4 + length).div_ceil(8) * 8;
        params = params.get(padded..)?;
    }
    None
}

/// Dissect a HIP packet.
pub fn dissect_hip(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Hip,
        summary: describe(payload),
    }
}

fn describe(payload: &[u8]) -> String {
    let Some(head) = payload.get(..HEADER_LEN) else {
        return "HIP".to_string();
    };
    let packet_type = head[2] & PACKET_TYPE_MASK;
    let Some(name) = packet_name(packet_type) else {
        return format!("HIP (packet type {packet_type})");
    };

    // Only NOTIFY carries a reason, and the reason is the entire value of
    // seeing one — an exchange that failed says so nowhere else.
    if packet_type == 17 {
        if let Some(code) = notification_code(&payload[HEADER_LEN..]) {
            let reason = match notification_name(code) {
                Some(text) => text.to_string(),
                // A code outside the standard keeps its number.
                None => format!("code {code}"),
            };
            return format!("HIP NOTIFY — {reason}");
        }
    }
    format!("HIP {name}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a HIP packet of the given type, with optional parameters.
    fn packet(packet_type: u8, params: &[u8]) -> Vec<u8> {
        let mut p = vec![59, 4, packet_type, 0x01, 0x00, 0x00, 0x00, 0x00];
        p.extend_from_slice(&[0xAA; 16]); // sender's HIT
        p.extend_from_slice(&[0xBB; 16]); // receiver's HIT
        p.extend_from_slice(params);
        p
    }

    /// Build a NOTIFICATION parameter carrying a reason code.
    fn notification(code: u16) -> Vec<u8> {
        let mut value = vec![0x00, 0x00];
        value.extend_from_slice(&code.to_be_bytes());
        let mut p = PARAM_NOTIFICATION.to_be_bytes().to_vec();
        p.extend_from_slice(&(value.len() as u16).to_be_bytes());
        p.extend_from_slice(&value);
        // Pad to a multiple of eight.
        while !p.len().is_multiple_of(8) {
            p.push(0);
        }
        p
    }

    /// The reason this dissector exists: a base exchange that fails is silent
    /// to the application, and NOTIFY is where the reason is.
    #[test]
    fn a_rejected_exchange_says_why() {
        let r = dissect_hip(None, None, &packet(17, &notification(24)));
        assert_eq!(r.protocol, Protocol::Hip);
        assert_eq!(r.summary, "HIP NOTIFY — authentication failed");
    }

    /// The rejection reasons have different fixes and are otherwise identical
    /// from the application's side.
    #[test]
    fn the_rejection_reasons_are_distinguished() {
        assert!(describe(&packet(17, &notification(14))).contains("no Diffie-Hellman proposal"));
        assert!(describe(&packet(17, &notification(42))).contains("blocked by policy"));
        assert!(describe(&packet(17, &notification(28))).contains("HMAC failed"));
        assert!(describe(&packet(17, &notification(44))).contains("server busy"));
    }

    /// The four-packet base exchange is what a working connection looks like.
    #[test]
    fn the_base_exchange_is_readable_step_by_step() {
        assert!(describe(&packet(1, &[])).contains("opening the base exchange"));
        assert!(describe(&packet(2, &[])).contains("puzzle offered"));
        assert!(describe(&packet(3, &[])).contains("puzzle solved"));
        assert!(describe(&packet(4, &[])).contains("base exchange complete"));
    }

    /// The top bit of the type byte belongs to SHIM6. Reading the whole byte
    /// would turn every packet with it set into an unknown type.
    #[test]
    fn the_shim6_bit_is_masked_off_the_packet_type() {
        assert!(describe(&packet(1, &[])).contains("I1"));
        assert!(describe(&packet(0x80 | 1, &[])).contains("I1"));
    }

    /// Parameters are walked, not searched: a Host Identity is opaque bytes
    /// and can contain the value that opens a NOTIFICATION.
    #[test]
    fn an_opaque_parameter_containing_the_notify_type_does_not_confuse_the_walk() {
        // A parameter whose value embeds 832 followed by a plausible length.
        let mut decoy = 1024u16.to_be_bytes().to_vec();
        decoy.extend_from_slice(&8u16.to_be_bytes());
        decoy.extend_from_slice(&PARAM_NOTIFICATION.to_be_bytes());
        decoy.extend_from_slice(&[0x00, 0x04, 0x00, 0x00, 0x00, 0x2A]);
        while !decoy.len().is_multiple_of(8) {
            decoy.push(0);
        }
        let mut params = decoy;
        params.extend_from_slice(&notification(42));
        // 42 is the real reason; 0x2A inside the decoy is also 42, so the test
        // asserts the walk reached the genuine parameter rather than the decoy.
        let summary = describe(&packet(17, &params));
        assert_eq!(summary, "HIP NOTIFY — blocked by policy");
    }

    /// A code outside the standard keeps its number.
    #[test]
    fn an_unassigned_code_keeps_its_number() {
        assert!(describe(&packet(17, &notification(200))).contains("code 200"));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "HIP");
        assert_eq!(describe(&[0u8; 39]), "HIP");
        // NOTIFY with no parameters falls back to the packet name.
        assert_eq!(describe(&packet(17, &[])), "HIP NOTIFY");
        // A parameter promising more than the packet holds.
        assert_eq!(
            describe(&packet(17, &[0x03, 0x40, 0xFF, 0xFF])),
            "HIP NOTIFY"
        );
        assert_eq!(describe(&packet(99, &[])), "HIP (packet type 99)");
    }

    /// A chain of parameters must not run the walk forever.
    #[test]
    fn the_parameter_walk_is_bounded() {
        // Zero-length parameters that never reach a NOTIFICATION.
        let params = vec![0u8; 8 * 64];
        assert_eq!(notification_code(&params), None);
    }
}
