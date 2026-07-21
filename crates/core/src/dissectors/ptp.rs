// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! PTP — IEEE 1588 precision time, and the 802.1AS profile that TSN runs on.
//!
//! Ordinary time sync gets a machine's clock within milliseconds. PTP gets it
//! within nanoseconds, by timestamping in hardware and measuring the path delay
//! rather than assuming it. That is the difference between "roughly the same
//! time" and a substation deciding which breaker tripped first, or a rack of
//! audio interfaces staying sample-aligned.
//!
//! ## gPTP is a profile, not a different protocol
//!
//! IEEE 802.1AS — generalised PTP, the clock that time-sensitive networking is
//! built on — is the *same wire format*. It is a restricted profile of 1588:
//! peer delay only, a fixed set of messages, Ethernet transport. Wireshark
//! reports it as PTPv2 as well, flagging the profile rather than naming a
//! separate protocol, which is why netscope does not mint a second protocol
//! for it either.
//!
//! What marks it is the top nibble of the first byte — `majorSdoId`, which
//! shares that byte with the message type:
//!
//! * `1` — a gPTP domain (802.1AS).
//! * `2` — CMLDS, the common mean link delay service.
//!
//! **Only over Ethernet.** The same nibble on a UDP-carried message does not
//! mean gPTP, because 802.1AS has no UDP transport. Reporting it there would
//! claim a profile from a field that cannot carry one.
//!
//! Why the distinction earns its place: on a TSN network, a device speaking
//! plain PTP where everything else speaks gPTP will exchange messages happily
//! and never join the timing domain. Both ends look busy; the sync just never
//! happens.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Name the PTP message from the low nibble of byte 0 (IEEE 1588).
fn message_name(payload: &[u8]) -> &'static str {
    match payload.first().map(|b| b & 0x0F) {
        Some(0x0) => "Sync",
        Some(0x1) => "Delay_Req",
        Some(0x2) => "Pdelay_Req",
        Some(0x3) => "Pdelay_Resp",
        Some(0x8) => "Follow_Up",
        Some(0x9) => "Delay_Resp",
        Some(0xA) => "Pdelay_Resp_Follow_Up",
        Some(0xB) => "Announce",
        Some(0xC) => "Signaling",
        Some(0xD) => "Management",
        _ => "message",
    }
}

/// The profile named by `majorSdoId`, the top nibble of the first byte.
///
/// Only meaningful over Ethernet — 802.1AS has no UDP transport.
fn profile(payload: &[u8]) -> Option<&'static str> {
    match payload.first().map(|b| b >> 4) {
        Some(1) => Some("gPTP / 802.1AS"),
        Some(2) => Some("CMLDS"),
        _ => None,
    }
}

/// The timing domain, which separates independent clock hierarchies sharing a
/// wire. Two domains on one network are two clocks that never agree, by design.
fn domain(payload: &[u8]) -> Option<u8> {
    payload.get(4).copied()
}

fn summarise(payload: &[u8], over_ethernet: bool) -> String {
    let message = message_name(payload);
    let domain = domain(payload)
        .map(|d| format!(", domain {d}"))
        .unwrap_or_default();
    match profile(payload).filter(|_| over_ethernet) {
        Some(name) => format!("PTP {message} ({name}{domain})"),
        None => format!("PTP {message} (IEEE 1588 time sync{domain})"),
    }
}

/// Dissect a PTP frame carried directly on Ethernet (EtherType 0x88F7).
pub fn dissect_ptp_l2(payload: &[u8]) -> DissectedResult {
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Ptp,
        summary: summarise(payload, true),
    }
}

/// Dissect a PTP message carried over UDP (ports 319 event / 320 general).
pub fn dissect_ptp_udp(
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
        protocol: Protocol::Ptp,
        // 802.1AS is Ethernet-only, so the profile nibble is not read here.
        summary: summarise(payload, false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a PTPv2 header with the given profile nibble, message type and
    /// domain.
    fn ptp(major_sdo_id: u8, message: u8, domain: u8) -> Vec<u8> {
        vec![
            (major_sdo_id << 4) | message,
            0x02, // versionPTP
            0x00,
            0x2C, // message length
            domain,
        ]
    }

    #[test]
    fn sync_over_ethernet() {
        let r = dissect_ptp_l2(&[0x00, 0x02, 0x00, 0x2c]);
        assert_eq!(r.protocol, Protocol::Ptp);
        assert!(r.summary.starts_with("PTP Sync"), "{}", r.summary);
    }

    #[test]
    fn announce_over_udp() {
        let r = dissect_ptp_udp(None, None, 320, 320, &[0x0B, 0x02]);
        assert!(r.summary.starts_with("PTP Announce"), "{}", r.summary);
    }

    #[test]
    fn the_message_types_are_named() {
        assert!(dissect_ptp_l2(&ptp(0, 0x0, 0)).summary.contains("PTP Sync"));
        assert!(dissect_ptp_l2(&ptp(0, 0xB, 0))
            .summary
            .contains("PTP Announce"));
        assert!(dissect_ptp_l2(&ptp(0, 0x2, 0))
            .summary
            .contains("PTP Pdelay_Req"));
    }

    /// The reason the profile is worth reporting: a device speaking plain PTP
    /// on a gPTP network exchanges messages and never joins the timing domain.
    #[test]
    fn gptp_is_distinguished_from_plain_ptp() {
        let gptp = dissect_ptp_l2(&ptp(1, 0x0, 0)).summary;
        let plain = dissect_ptp_l2(&ptp(0, 0x0, 0)).summary;
        assert_eq!(gptp, "PTP Sync (gPTP / 802.1AS, domain 0)");
        assert_eq!(plain, "PTP Sync (IEEE 1588 time sync, domain 0)");
    }

    #[test]
    fn the_link_delay_service_is_named() {
        assert!(dissect_ptp_l2(&ptp(2, 0x2, 0)).summary.contains("CMLDS"));
    }

    /// 802.1AS has no UDP transport, so the same nibble over UDP does not mean
    /// gPTP. Reporting it there would claim a profile the field cannot carry.
    #[test]
    fn the_profile_is_not_claimed_over_udp() {
        let summary = dissect_ptp_udp(None, None, 319, 319, &ptp(1, 0x0, 0)).summary;
        assert!(!summary.contains("802.1AS"), "{summary}");
        assert!(summary.contains("IEEE 1588"), "{summary}");
    }

    /// The profile and the message type share a byte. Reading the whole byte
    /// as either one turns every gPTP message into an unrecognised one.
    #[test]
    fn the_profile_and_message_type_share_a_byte() {
        let frame = ptp(1, 0xB, 0);
        assert_eq!(frame[0], 0x1B, "one byte carries both");
        let summary = dissect_ptp_l2(&frame).summary;
        assert!(summary.contains("Announce"), "{summary}");
        assert!(summary.contains("gPTP"), "{summary}");
    }

    /// Two domains on one wire are two clock hierarchies that never agree.
    #[test]
    fn the_domain_is_reported() {
        assert!(dissect_ptp_l2(&ptp(1, 0x0, 0)).summary.contains("domain 0"));
        assert!(dissect_ptp_l2(&ptp(1, 0x0, 7)).summary.contains("domain 7"));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(
            dissect_ptp_l2(&[]).summary,
            "PTP message (IEEE 1588 time sync)"
        );
        // A header with no domain byte reports what it has.
        assert_eq!(dissect_ptp_l2(&[0x10]).summary, "PTP Sync (gPTP / 802.1AS)");
        assert_eq!(
            dissect_ptp_udp(None, None, 319, 319, &[0x00]).summary,
            "PTP Sync (IEEE 1588 time sync)"
        );
    }
}
