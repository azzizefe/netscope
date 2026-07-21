// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! LoRaWAN — battery-powered sensors on a kilometres-wide radio link.
//!
//! LoRaWAN carries a few bytes at a time from devices that must run for years
//! on one battery: water meters, soil probes, parking sensors, cattle trackers.
//! The radio reaches a long way and the devices sleep almost always, and both
//! of those facts shape what goes wrong.
//!
//! ## What the header says when something is wrong
//!
//! **A device stuck on Join Request.** Joining is a two-step exchange: the
//! device sends a Join Request and the network answers with a Join Accept. A
//! capture full of Join Requests with no Accepts is a device whose keys the
//! network does not recognise, or one whose requests are arriving at a gateway
//! that cannot reach its network server. The device will retry until its
//! battery is gone, and from the device's own side there is nothing to see.
//!
//! **The frame counter.** Every frame carries one, and it exists to stop replay
//! — a receiver ignores anything not ahead of what it has seen. A device that
//! resets (or a battery change on cheap hardware) restarts its counter at zero
//! and the network then silently discards everything it sends. The device is
//! transmitting perfectly and is simply not being listened to, which is the
//! single most confusing failure on these networks.
//!
//! **ADR and the acknowledgement request.** Adaptive data rate lets the network
//! turn a device's power down when its signal is strong. `ADRACKReq` is the
//! device asking whether anyone is still there, because it has raised its power
//! as far as it can and heard nothing back.
//!
//! The payload itself is encrypted end to end, so what a sensor reported is not
//! readable here — the header is the whole of what a capture can say.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// MHDR, then the frame header: address, control, counter.
const FHDR_LEN: usize = 8;

const FTYPE_MASK: u8 = 0xE0;
/// The major version occupies the low two bits; only 0 is defined.
const MAJOR_MASK: u8 = 0x03;

const ADR: u8 = 0x80;
const ADR_ACK_REQ: u8 = 0x40;
const ACK: u8 = 0x20;
const FPENDING: u8 = 0x10;
const FOPTS_LEN_MASK: u8 = 0x0F;

fn frame_type(ftype: u8) -> Option<(&'static str, bool)> {
    // The flag says whether the message carries a frame header; the join
    // exchange does not.
    Some(match ftype {
        0 => ("Join Request", false),
        1 => ("Join Accept", false),
        2 => ("unconfirmed uplink", true),
        3 => ("unconfirmed downlink", true),
        4 => ("confirmed uplink", true),
        5 => ("confirmed downlink", true),
        7 => ("proprietary", false),
        _ => return None,
    })
}

/// Whether a payload is a LoRaWAN frame.
///
/// The major version is two bits and only zero is defined, which together with
/// a known frame type is the only structural evidence available — there is no
/// magic and the payload beyond the header is ciphertext.
pub(crate) fn looks_like_lorawan(payload: &[u8]) -> bool {
    payload.first().is_some_and(|&mhdr| {
        mhdr & MAJOR_MASK == 0 && frame_type((mhdr & FTYPE_MASK) >> 5).is_some()
    })
}

/// Dissect a LoRaWAN frame.
pub fn dissect_lorawan(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Lorawan,
        summary: describe(payload),
    }
}

fn describe(payload: &[u8]) -> String {
    let Some(&mhdr) = payload.first() else {
        return "LoRaWAN".to_string();
    };
    let Some((name, has_header)) = frame_type((mhdr & FTYPE_MASK) >> 5) else {
        return format!("LoRaWAN (frame type {})", (mhdr & FTYPE_MASK) >> 5);
    };

    if !has_header {
        return format!("LoRaWAN {name}");
    }

    let Some(header) = payload.get(1..FHDR_LEN) else {
        return format!("LoRaWAN {name}");
    };
    // The device address and counter are both little-endian, which is the
    // opposite of most of what a network capture contains.
    let address = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    let control = header[4];
    let counter = u16::from_le_bytes([header[5], header[6]]);

    let mut notes: Vec<&str> = Vec::new();
    if control & ACK != 0 {
        notes.push("ACK");
    }
    if control & ADR_ACK_REQ != 0 {
        // The device has run out of power headroom and is asking whether the
        // network is still listening at all.
        notes.push("ADRACKReq — the device is asking if anyone is still there");
    }
    if control & ADR != 0 {
        notes.push("ADR");
    }
    if control & FPENDING != 0 {
        notes.push("more data pending");
    }
    let options = control & FOPTS_LEN_MASK;

    let mut summary = format!("LoRaWAN {name} — device {address:08X}, counter {counter}");
    if !notes.is_empty() {
        summary.push_str(&format!(" [{}]", notes.join(", ")));
    }
    if options > 0 {
        summary.push_str(&format!(" +{options}B MAC commands"));
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a LoRaWAN data frame.
    fn frame(ftype: u8, address: u32, control: u8, counter: u16) -> Vec<u8> {
        let mut v = vec![ftype << 5];
        v.extend_from_slice(&address.to_le_bytes());
        v.push(control);
        v.extend_from_slice(&counter.to_le_bytes());
        v.extend_from_slice(&[0x01, 0xAA, 0xBB]); // port and ciphertext
        v
    }

    /// The reason this dissector exists: a device retrying a join forever is
    /// invisible from the device's own side, and obvious here.
    #[test]
    fn the_join_exchange_is_visible() {
        let r = dissect_lorawan(None, None, 1700, 1700, &[0x00, 0xAA, 0xBB]);
        assert_eq!(r.protocol, Protocol::Lorawan);
        assert_eq!(r.summary, "LoRaWAN Join Request");
        assert_eq!(
            describe(&[0x20, 0xAA, 0xBB]),
            "LoRaWAN Join Accept",
            "a join accept is what a stuck device never receives"
        );
    }

    /// The counter is what a network silently discards frames on, so it is
    /// reported on every data frame.
    #[test]
    fn the_frame_counter_is_reported() {
        let r = dissect_lorawan(None, None, 0, 0, &frame(2, 0x2601_1F5A, 0, 1234));
        assert_eq!(
            r.summary,
            "LoRaWAN unconfirmed uplink — device 26011F5A, counter 1234"
        );
        // A counter back at zero is what a reset device sends, and what the
        // network will ignore.
        assert!(describe(&frame(2, 0x2601_1F5A, 0, 0)).contains("counter 0"));
    }

    /// The address and counter are little-endian — the opposite of most of
    /// what a capture contains, so reading them big-endian is the easy mistake.
    #[test]
    fn the_address_and_counter_are_little_endian() {
        let r = describe(&frame(2, 0x0000_0001, 0, 1));
        assert!(r.contains("device 00000001"), "{r}");
        assert!(r.contains("counter 1"), "{r}");
    }

    /// The control byte is what says the device has run out of headroom.
    #[test]
    fn the_control_flags_are_reported() {
        let asking = describe(&frame(2, 1, ADR | ADR_ACK_REQ, 5));
        assert!(
            asking.contains("asking if anyone is still there"),
            "{asking}"
        );
        assert!(describe(&frame(3, 1, ACK, 5)).contains("ACK"));
        assert!(describe(&frame(3, 1, FPENDING, 5)).contains("more data pending"));
    }

    /// The options length shares the control byte with the flags, so reading
    /// it whole reports MAC commands on every frame that sets any flag.
    #[test]
    fn the_options_length_is_taken_from_its_own_nibble() {
        assert!(describe(&frame(2, 1, ADR | 3, 5)).contains("+3B MAC commands"));
        // Flags set but no options: nothing to report.
        assert!(!describe(&frame(2, 1, ADR, 5)).contains("MAC commands"));
    }

    /// Confirmed and unconfirmed traffic differ in whether the network must
    /// answer, which is the difference between a chatty device and a quiet one.
    #[test]
    fn the_frame_types_are_distinguished() {
        assert!(describe(&frame(4, 1, 0, 1)).contains("confirmed uplink"));
        assert!(describe(&frame(3, 1, 0, 1)).contains("unconfirmed downlink"));
    }

    /// There is no magic, so recognition rests on the version bits being zero
    /// and the frame type being one the standard defines.
    #[test]
    fn recognition_rests_on_the_version_and_frame_type() {
        assert!(looks_like_lorawan(&[0x40]));
        assert!(looks_like_lorawan(&[0x00]));
        // Frame type 6 is reserved.
        assert!(!looks_like_lorawan(&[0xC0]));
        // A major version other than zero is not this protocol.
        assert!(!looks_like_lorawan(&[0x41]));
        assert!(!looks_like_lorawan(&[]));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "LoRaWAN");
        // A data frame whose header has not arrived.
        assert_eq!(describe(&[0x40, 0x01]), "LoRaWAN unconfirmed uplink");
        assert_eq!(describe(&[0xC0]), "LoRaWAN (frame type 6)");
    }
}
