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
        // A key frame is one of the four messages of the WPA handshake, and
        // which one it is decides everything: where the exchange stops is what
        // says whether a client is out of range, has the wrong password, or
        // joined successfully.
        Some(&3) => match handshake_message(payload) {
            Some(text) => format!("EAPOL {text}"),
            None => "EAPOL Key (WPA handshake)".to_string(),
        },
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

/// Bits in the key information field that identify which handshake message
/// this is (IEEE 802.1X-2010 §11.9).
const KEY_INFO_PAIRWISE: u16 = 0x0008;
const KEY_INFO_INSTALL: u16 = 0x0040;
const KEY_INFO_ACK: u16 = 0x0080;
const KEY_INFO_MIC: u16 = 0x0100;
const KEY_INFO_SECURE: u16 = 0x0200;

/// Which of the four handshake messages a key frame is.
///
/// There is no message-number field — the four are told apart by which flags
/// are set, which is why a capture read without this looks like four identical
/// "key" frames. The pattern that matters when something is wrong is a
/// handshake that reaches message 2 and then restarts: the access point is
/// rejecting the integrity check, which is what a wrong password looks like.
fn handshake_message(payload: &[u8]) -> Option<String> {
    // Version, type, length (2), descriptor type, then key information.
    let info = u16::from_be_bytes([*payload.get(5)?, *payload.get(6)?]);
    // A group-key handshake reuses the same frame with the pairwise bit clear.
    if info & KEY_INFO_PAIRWISE == 0 {
        return Some(if info & KEY_INFO_ACK != 0 {
            "group key handshake 1/2".to_string()
        } else {
            "group key handshake 2/2".to_string()
        });
    }

    let ack = info & KEY_INFO_ACK != 0;
    let mic = info & KEY_INFO_MIC != 0;
    let install = info & KEY_INFO_INSTALL != 0;
    let secure = info & KEY_INFO_SECURE != 0;

    Some(match (ack, mic, install) {
        // Only the access point sends without a MIC, and only first.
        (true, false, _) => "4-way handshake 1/4 (access point offers a nonce)".to_string(),
        // The third message installs the key, which is what distinguishes it
        // from the first — both are sent by the access point with an ACK.
        (true, true, true) => "4-way handshake 3/4 (key confirmed)".to_string(),
        (true, true, false) => "4-way handshake 3/4".to_string(),
        // The client's two messages differ by the secure bit: the second is
        // sent before the keys are in place, the fourth after.
        (false, true, _) if secure => "4-way handshake 4/4 (client is joined)".to_string(),
        (false, true, _) => "4-way handshake 2/4 (client answers)".to_string(),
        _ => return None,
    })
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

    /// Build a key frame with the given key information flags.
    fn key_frame(info: u16) -> Vec<u8> {
        let mut p = vec![0x02, 0x03, 0x00, 0x5F, 0x02];
        p.extend_from_slice(&info.to_be_bytes());
        p.extend_from_slice(&[0u8; 90]);
        p
    }

    /// There is no message-number field: the four are told apart by which
    /// flags are set. Without this a capture is four identical "key" frames
    /// and the handshake cannot be followed at all.
    #[test]
    fn each_of_the_four_messages_is_identified() {
        let m1 = KEY_INFO_PAIRWISE | KEY_INFO_ACK;
        let m2 = KEY_INFO_PAIRWISE | KEY_INFO_MIC;
        let m3 =
            KEY_INFO_PAIRWISE | KEY_INFO_ACK | KEY_INFO_MIC | KEY_INFO_INSTALL | KEY_INFO_SECURE;
        let m4 = KEY_INFO_PAIRWISE | KEY_INFO_MIC | KEY_INFO_SECURE;

        assert!(dissect_eapol(&key_frame(m1)).summary.contains("1/4"));
        assert!(dissect_eapol(&key_frame(m2)).summary.contains("2/4"));
        assert!(dissect_eapol(&key_frame(m3)).summary.contains("3/4"));
        assert!(dissect_eapol(&key_frame(m4)).summary.contains("4/4"));
    }

    /// Messages 1 and 3 are both sent by the access point with an ACK; only
    /// the install bit separates them. Getting this wrong makes a completed
    /// handshake look like one that restarted.
    #[test]
    fn the_install_bit_separates_message_three_from_message_one() {
        let m1 = KEY_INFO_PAIRWISE | KEY_INFO_ACK;
        let m3 = KEY_INFO_PAIRWISE | KEY_INFO_ACK | KEY_INFO_MIC | KEY_INFO_INSTALL;
        assert!(dissect_eapol(&key_frame(m1)).summary.contains("1/4"));
        assert!(dissect_eapol(&key_frame(m3)).summary.contains("3/4"));
        assert!(!dissect_eapol(&key_frame(m3)).summary.contains("1/4"));
    }

    /// Messages 2 and 4 are both from the client with a MIC; the secure bit is
    /// what says the keys are already in place. A handshake that reaches 2 and
    /// restarts is a rejected password — reading 2 as 4 would hide that.
    #[test]
    fn the_secure_bit_separates_message_four_from_message_two() {
        let m2 = KEY_INFO_PAIRWISE | KEY_INFO_MIC;
        let m4 = KEY_INFO_PAIRWISE | KEY_INFO_MIC | KEY_INFO_SECURE;
        assert_eq!(
            dissect_eapol(&key_frame(m2)).summary,
            "EAPOL 4-way handshake 2/4 (client answers)"
        );
        assert_eq!(
            dissect_eapol(&key_frame(m4)).summary,
            "EAPOL 4-way handshake 4/4 (client is joined)"
        );
    }

    /// The group key handshake reuses the same frame with the pairwise bit
    /// clear, and must not be reported as part of the four-way exchange.
    #[test]
    fn the_group_key_handshake_is_not_confused_with_the_four_way() {
        let g1 = KEY_INFO_ACK | KEY_INFO_MIC | KEY_INFO_SECURE;
        let g2 = KEY_INFO_MIC | KEY_INFO_SECURE;
        assert_eq!(
            dissect_eapol(&key_frame(g1)).summary,
            "EAPOL group key handshake 1/2"
        );
        assert_eq!(
            dissect_eapol(&key_frame(g2)).summary,
            "EAPOL group key handshake 2/2"
        );
    }

    /// A key frame too short to hold the flags falls back rather than guessing.
    #[test]
    fn a_truncated_key_frame_does_not_guess() {
        assert_eq!(
            dissect_eapol(&[0x02, 0x03, 0x00, 0x5F]).summary,
            "EAPOL Key (WPA handshake)"
        );
    }
}
