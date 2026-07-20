// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! MKA — the negotiation that has to succeed before MACsec encrypts anything.
//!
//! MACsec encrypts a link at layer 2, but only once both ends have agreed a key.
//! MKA (IEEE 802.1X-2010) is that agreement: peers announce themselves, elect a
//! key server, and the server distributes the session key.
//!
//! The reason to read it is that failure here is quiet. If key agreement never
//! completes the link does not encrypt — and depending on configuration it
//! either carries traffic in the clear or carries nothing, with no error
//! anywhere above. The tell is in the peer lists: a peer that stays in the
//! *potential* list and never reaches the *live* list is a peer whose MKA
//! messages are arriving but whose responses are not being accepted, which is
//! almost always a mismatched connectivity association key.

use crate::models::Protocol;

use super::DissectedResult;

/// The basic parameter set is fixed-size up to the key name.
const OFFSET_KEY_SERVER_PRIORITY: usize = 1;
const OFFSET_FLAGS: usize = 2;

/// Bits in the third byte of the basic parameter set.
const FLAG_KEY_SERVER: u8 = 0x80;
const FLAG_MACSEC_DESIRED: u8 = 0x40;

/// Parameter sets that follow the basic one.
fn parameter_set_name(kind: u8) -> Option<&'static str> {
    Some(match kind {
        1 => "live peer list",
        2 => "potential peer list",
        3 => "MACsec key in use",
        4 => "distributing a session key",
        5 => "distributing a long-lived key",
        6 => "key management domain",
        7 => "announcement",
        255 => "integrity check",
        _ => return None,
    })
}

/// Dissect an MKA message. `payload` starts after the EAPOL header.
pub(crate) fn describe(payload: &[u8]) -> String {
    let Some(&priority) = payload.get(OFFSET_KEY_SERVER_PRIORITY) else {
        return "MKA".to_string();
    };
    let Some(&flags) = payload.get(OFFSET_FLAGS) else {
        return "MKA".to_string();
    };
    let role = if flags & FLAG_KEY_SERVER != 0 {
        "key server"
    } else {
        "peer"
    };
    // A sender that does not want MACsec is worth calling out: the link will
    // stay in the clear no matter how well the rest of the exchange goes.
    let wants = if flags & FLAG_MACSEC_DESIRED != 0 {
        ""
    } else {
        ", MACsec not desired"
    };

    // The basic parameter set's length is twelve bits split across two bytes,
    // and the sets that follow it are where the state lives.
    let basic_len = payload
        .get(OFFSET_FLAGS..OFFSET_FLAGS + 2)
        .map(|b| (((b[0] & 0x0F) as usize) << 8) | b[1] as usize)
        .unwrap_or(0);
    // Four bytes of header precede the body the length describes.
    let next = 4 + basic_len;
    let following = payload.get(next).and_then(|&kind| parameter_set_name(kind));

    match following {
        Some(what) => format!("MKA {role} (priority {priority}{wants}) — {what}"),
        None => format!("MKA {role} (priority {priority}{wants})"),
    }
}

/// Build the result for an MKA message lifted out of EAPOL.
pub(crate) fn result(payload: &[u8]) -> DissectedResult {
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Mka,
        summary: describe(payload),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an MKA message with a basic parameter set and one following set.
    fn mka(flags: u8, priority: u8, body_len: usize, following: Option<u8>) -> Vec<u8> {
        let mut p = vec![0x03, priority]; // MKA version, key server priority
        p.push(flags | ((body_len >> 8) as u8 & 0x0F));
        p.push(body_len as u8);
        p.extend(std::iter::repeat_n(0u8, body_len));
        if let Some(kind) = following {
            p.push(kind);
            p.extend_from_slice(&[0x00, 0x00, 0x00]);
        }
        p
    }

    /// The everyday message: a peer announcing itself and who it thinks should
    /// hold the key.
    #[test]
    fn a_message_names_the_role_and_priority() {
        let r = result(&mka(FLAG_MACSEC_DESIRED, 16, 28, None));
        assert_eq!(r.protocol, Protocol::Mka);
        assert_eq!(r.summary, "MKA peer (priority 16)");

        let r = result(&mka(FLAG_KEY_SERVER | FLAG_MACSEC_DESIRED, 0, 28, None));
        assert_eq!(r.summary, "MKA key server (priority 0)");
    }

    /// The tell for a failing association: peers that stay potential and never
    /// become live. Both lists have to be distinguishable for that to be
    /// visible at all.
    #[test]
    fn the_peer_lists_are_distinguished() {
        let live = result(&mka(FLAG_MACSEC_DESIRED, 16, 28, Some(1))).summary;
        let potential = result(&mka(FLAG_MACSEC_DESIRED, 16, 28, Some(2))).summary;
        assert!(live.ends_with("live peer list"), "{live}");
        assert!(potential.ends_with("potential peer list"), "{potential}");
    }

    /// A sender that does not want MACsec leaves the link in the clear however
    /// well the rest of the exchange goes, so it is called out.
    #[test]
    fn a_peer_not_wanting_macsec_is_called_out() {
        let summary = result(&mka(0, 16, 28, None)).summary;
        assert!(summary.contains("MACsec not desired"), "{summary}");
        assert!(!result(&mka(FLAG_MACSEC_DESIRED, 16, 28, None))
            .summary
            .contains("not desired"));
    }

    /// Key distribution is the step everything else exists to reach.
    #[test]
    fn key_distribution_is_named() {
        assert!(result(&mka(FLAG_KEY_SERVER, 0, 28, Some(4)))
            .summary
            .contains("distributing a session key"));
    }

    /// The body length is twelve bits split across two bytes. Reading only the
    /// low byte finds the wrong following set once the body exceeds 255.
    #[test]
    fn the_body_length_spans_both_bytes() {
        // A 300-byte body needs the high nibble; a low-byte-only read would
        // look at offset 48 instead and find padding.
        let r = result(&mka(FLAG_MACSEC_DESIRED, 16, 300, Some(1)));
        assert!(r.summary.ends_with("live peer list"), "{}", r.summary);
    }

    /// A set outside the standard is not given an invented meaning.
    #[test]
    fn an_unknown_parameter_set_is_not_named() {
        let r = result(&mka(FLAG_MACSEC_DESIRED, 16, 28, Some(99)));
        assert_eq!(r.summary, "MKA peer (priority 16)");
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "MKA");
        assert_eq!(describe(&[0x03]), "MKA");
        assert!(describe(&[0x03, 0x10, 0x40]).starts_with("MKA"));
    }
}
