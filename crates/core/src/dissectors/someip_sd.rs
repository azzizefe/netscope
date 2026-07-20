// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! SOME/IP service discovery — how a car's ECUs find each other.
//!
//! Before any SOME/IP call can happen, the ECU providing a service has to
//! announce it and the ones wanting it have to subscribe. That negotiation is
//! this protocol, and it is where the interesting failures live: a function
//! that "doesn't work" usually means the offer never arrived or the
//! subscription was refused, neither of which shows up in the calls themselves
//! because there are none.
//!
//! The field that carries the meaning is the time-to-live, and it is easy to
//! overlook. An `OfferService` with a TTL of zero is not an offer — it is the
//! withdrawal of one, the message an ECU sends as it goes away. Likewise a
//! subscribe with TTL zero is an unsubscribe, and an acknowledgement with TTL
//! zero is a refusal. Reading the entry type without the TTL reports the exact
//! opposite of what happened.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// The SOME/IP header that precedes every service discovery payload.
const SOMEIP_HEADER: usize = 16;
/// Flags, three reserved bytes, then the length of the entries array.
const OFFSET_ENTRIES_LEN: usize = SOMEIP_HEADER + 4;
const OFFSET_FIRST_ENTRY: usize = OFFSET_ENTRIES_LEN + 4;
/// Every entry is the same size, whatever its type.
const ENTRY_LEN: usize = 16;

/// A reboot flag tells receivers the sender lost its state, so everything they
/// thought was subscribed no longer is.
const FLAG_REBOOT: u8 = 0x80;

/// What an entry is doing, once the time-to-live has been taken into account.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Action {
    Find,
    Offer,
    /// An offer with no time to live: the service is going away.
    StopOffer,
    Subscribe,
    Unsubscribe,
    SubscribeAck,
    /// An acknowledgement with no time to live: the subscription was refused.
    SubscribeNack,
    Unknown(u8),
}

impl Action {
    fn describe(&self) -> String {
        match self {
            Action::Find => "looking for".to_string(),
            Action::Offer => "offering".to_string(),
            Action::StopOffer => "withdrawing".to_string(),
            Action::Subscribe => "subscribing to".to_string(),
            Action::Unsubscribe => "unsubscribing from".to_string(),
            Action::SubscribeAck => "accepted subscription to".to_string(),
            Action::SubscribeNack => "refused subscription to".to_string(),
            Action::Unknown(t) => format!("entry type 0x{t:02x} for"),
        }
    }
}

/// Classify an entry from its type and time-to-live.
///
/// The TTL is what separates an offer from a withdrawal, so the two are decided
/// together rather than the type being trusted on its own.
pub(crate) fn classify(entry_type: u8, ttl: u32) -> Action {
    let expiring = ttl == 0;
    match (entry_type, expiring) {
        (0x00, _) => Action::Find,
        (0x01, false) => Action::Offer,
        (0x01, true) => Action::StopOffer,
        (0x06, false) => Action::Subscribe,
        (0x06, true) => Action::Unsubscribe,
        (0x07, false) => Action::SubscribeAck,
        (0x07, true) => Action::SubscribeNack,
        (other, _) => Action::Unknown(other),
    }
}

/// One decoded entry.
struct Entry {
    action: Action,
    service: u16,
    instance: u16,
}

fn read_entry(payload: &[u8], at: usize) -> Option<Entry> {
    let e = payload.get(at..at + ENTRY_LEN)?;
    let service = u16::from_be_bytes([e[4], e[5]]);
    let instance = u16::from_be_bytes([e[6], e[7]]);
    // The time to live is three bytes, not four.
    let ttl = u32::from_be_bytes([0, e[9], e[10], e[11]]);
    Some(Entry {
        action: classify(e[0], ttl),
        service,
        instance,
    })
}

/// Dissect a SOME/IP-SD message. `payload` starts at the SOME/IP header.
pub fn dissect_someip_sd(
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
        protocol: Protocol::SomeIpSd,
        summary: describe(payload),
    }
}

fn describe(payload: &[u8]) -> String {
    let Some(&flags) = payload.get(SOMEIP_HEADER) else {
        return "SOME/IP-SD (service discovery)".to_string();
    };
    // A reboot means every subscription the receivers hold is now stale, which
    // explains a burst of re-subscription that would otherwise look unprompted.
    let reboot = if flags & FLAG_REBOOT != 0 {
        " after reboot"
    } else {
        ""
    };

    let entries_len = payload
        .get(OFFSET_ENTRIES_LEN..OFFSET_ENTRIES_LEN + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)
        .unwrap_or(0);
    let count = entries_len / ENTRY_LEN;
    if count == 0 {
        return format!("SOME/IP-SD — no entries{reboot}");
    }

    let Some(first) = read_entry(payload, OFFSET_FIRST_ENTRY) else {
        return format!("SOME/IP-SD — {count} entries{reboot}");
    };

    // A message can carry several entries. Naming the first and counting the
    // rest keeps the summary to one line without hiding that there were more.
    let more = if count > 1 {
        format!(" (+{} more)", count - 1)
    } else {
        String::new()
    };
    format!(
        "SOME/IP-SD {} service 0x{:04x} instance 0x{:04x}{more}{reboot}",
        first.action.describe(),
        first.service,
        first.instance
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a service discovery message carrying the given entries.
    fn message(flags: u8, entries: &[(u8, u16, u16, u32)]) -> Vec<u8> {
        let mut p = vec![0u8; SOMEIP_HEADER];
        // The SOME/IP header of an SD message names the discovery service.
        p[0..2].copy_from_slice(&0xFFFFu16.to_be_bytes());
        p[2..4].copy_from_slice(&0x8100u16.to_be_bytes());
        p.push(flags);
        p.extend_from_slice(&[0u8; 3]); // reserved
        p.extend_from_slice(&((entries.len() * ENTRY_LEN) as u32).to_be_bytes());
        for &(entry_type, service, instance, ttl) in entries {
            p.push(entry_type);
            p.extend_from_slice(&[0, 0, 0]); // option indices and counts
            p.extend_from_slice(&service.to_be_bytes());
            p.extend_from_slice(&instance.to_be_bytes());
            p.push(1); // major version
            p.extend_from_slice(&ttl.to_be_bytes()[1..4]); // TTL is three bytes
            p.extend_from_slice(&[0u8; 4]); // minor version
        }
        p.extend_from_slice(&0u32.to_be_bytes()); // options array length
        p
    }

    /// The everyday case: an ECU announcing what it can do.
    #[test]
    fn an_offer_names_the_service() {
        let p = message(0, &[(0x01, 0x1234, 0x0001, 3)]);
        let r = dissect_someip_sd(None, None, 30490, 30490, &p);
        assert_eq!(r.protocol, Protocol::SomeIpSd);
        assert_eq!(
            r.summary,
            "SOME/IP-SD offering service 0x1234 instance 0x0001"
        );
    }

    /// The whole reason this dissector exists. The entry type is identical to
    /// an offer; only the time-to-live says the service is going away, and
    /// reading the type alone reports the exact opposite of what happened.
    #[test]
    fn a_zero_ttl_offer_is_a_withdrawal_not_an_offer() {
        let p = message(0, &[(0x01, 0x1234, 0x0001, 0)]);
        let summary = dissect_someip_sd(None, None, 1, 30490, &p).summary;
        assert_eq!(
            summary,
            "SOME/IP-SD withdrawing service 0x1234 instance 0x0001"
        );
        assert!(
            !summary.contains("offering"),
            "reported a withdrawal as an offer"
        );
    }

    /// The same trap on the subscription side, both directions.
    #[test]
    fn a_zero_ttl_subscription_is_an_unsubscribe_or_a_refusal() {
        assert_eq!(classify(0x06, 10), Action::Subscribe);
        assert_eq!(classify(0x06, 0), Action::Unsubscribe);
        assert_eq!(classify(0x07, 10), Action::SubscribeAck);
        assert_eq!(classify(0x07, 0), Action::SubscribeNack);

        let p = message(0, &[(0x07, 0x0042, 0x0001, 0)]);
        assert_eq!(
            dissect_someip_sd(None, None, 1, 30490, &p).summary,
            "SOME/IP-SD refused subscription to service 0x0042 instance 0x0001"
        );
    }

    /// A refused subscription is why a function silently does nothing — there
    /// are no calls to see, because none were ever allowed.
    #[test]
    fn a_find_is_distinguished_from_a_subscribe() {
        let p = message(0, &[(0x00, 0x1234, 0xFFFF, 3)]);
        assert!(dissect_someip_sd(None, None, 1, 30490, &p)
            .summary
            .contains("looking for"));
    }

    /// The time-to-live is three bytes, not four. Reading four would pull in
    /// the major version and make every entry look non-zero.
    #[test]
    fn the_ttl_is_three_bytes_wide() {
        // A TTL whose low three bytes are zero must still read as expiring even
        // though the byte before it (the major version) is 1.
        let p = message(0, &[(0x01, 0x1234, 0x0001, 0)]);
        assert!(dissect_someip_sd(None, None, 1, 30490, &p)
            .summary
            .contains("withdrawing"));
        // And a large TTL that fits in three bytes is read whole.
        let p = message(0, &[(0x01, 0x1234, 0x0001, 0x00FF_FFFF)]);
        assert!(dissect_someip_sd(None, None, 1, 30490, &p)
            .summary
            .contains("offering"));
    }

    /// A reboot invalidates every subscription the receivers hold, which
    /// explains a burst of re-subscription that otherwise looks unprompted.
    #[test]
    fn a_reboot_is_called_out() {
        let p = message(FLAG_REBOOT, &[(0x01, 0x1234, 0x0001, 3)]);
        assert!(dissect_someip_sd(None, None, 1, 30490, &p)
            .summary
            .ends_with("after reboot"));
    }

    /// Several entries travel in one message; the count must not be lost.
    #[test]
    fn additional_entries_are_counted() {
        let p = message(
            0,
            &[
                (0x01, 0x1234, 0x0001, 3),
                (0x01, 0x5678, 0x0001, 3),
                (0x01, 0x9ABC, 0x0001, 3),
            ],
        );
        assert_eq!(
            dissect_someip_sd(None, None, 1, 30490, &p).summary,
            "SOME/IP-SD offering service 0x1234 instance 0x0001 (+2 more)"
        );
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(
            dissect_someip_sd(None, None, 1, 30490, &[0u8; 16]).summary,
            "SOME/IP-SD (service discovery)"
        );
        let mut p = message(0, &[(0x01, 1, 1, 3)]);
        p.truncate(OFFSET_FIRST_ENTRY + 4);
        assert!(dissect_someip_sd(None, None, 1, 30490, &p)
            .summary
            .contains("1 entries"));
    }
}
