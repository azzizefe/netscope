// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! TCAP, and the MAP operation inside it.
//!
//! TCAP (ITU-T Q.773) is the transaction layer of the SS7 stack: it pairs a
//! request with its answer across the network. On its own it says little — the
//! interesting part is the *operation code* in the component it carries, which
//! comes from MAP (3GPP TS 29.002) and names what is actually being asked.
//!
//! That operation code is why this dissector goes as deep as it does. A capture
//! full of "TCAP Begin" tells you nothing; `sendRoutingInfoForSM` tells you
//! someone is resolving where to deliver a text message, and
//! `anyTimeInterrogation` tells you someone is asking where a subscriber
//! physically is. Those two are the classic SS7 location-tracking and
//! SMS-interception operations, so naming them is the whole point.
//!
//! TCAP is BER-encoded. We walk only the outer tags rather than doing a full
//! ASN.1 decode: message type, then into the component portion, then the first
//! component's operation code.

/// TCAP message types — the outer BER tag (Q.773 §3).
fn message_name(tag: u8) -> Option<&'static str> {
    Some(match tag {
        0x62 => "Begin",
        0x64 => "End",
        0x65 => "Continue",
        0x67 => "Abort",
        0x61 => "Unidirectional",
        _ => return None,
    })
}

/// Component types (Q.773 §3.2).
fn component_name(tag: u8) -> Option<&'static str> {
    Some(match tag {
        0xA1 => "Invoke",
        0xA2 => "ReturnResultLast",
        0xA3 => "ReturnError",
        0xA4 => "Reject",
        0xA7 => "ReturnResultNotLast",
        _ => return None,
    })
}

/// MAP operation codes (3GPP TS 29.002 §17.5). These name the actual mobile
/// network operation being performed.
fn map_operation(code: u8) -> Option<&'static str> {
    Some(match code {
        2 => "updateLocation",
        3 => "cancelLocation",
        4 => "provideRoamingNumber",
        5 => "noteSubscriberDataModified",
        6 => "resumeCallHandling",
        7 => "insertSubscriberData",
        8 => "deleteSubscriberData",
        9 => "sendParameters",
        10 => "registerSS",
        11 => "eraseSS",
        12 => "activateSS",
        13 => "deactivateSS",
        14 => "interrogateSS",
        16 => "registerPassword",
        17 => "getPassword",
        18 => "processUnstructuredSS-Data",
        19 => "releaseResources",
        20 => "mt-ForwardSM-VGCS",
        21 => "sendRoutingInfo",
        22 => "updateGprsLocation",
        23 => "sendRoutingInfoForGprs",
        24 => "failureReport",
        25 => "noteMsPresentForGprs",
        29 => "sendEndSignal",
        31 => "processAccessSignalling",
        32 => "forwardAccessSignalling",
        37 => "reset",
        38 => "forwardCheckSS-Indication",
        39 => "prepareGroupCall",
        40 => "sendGroupCallEndSignal",
        42 => "processGroupCallSignalling",
        43 => "forwardGroupCallSignalling",
        44 => "checkIMEI",
        45 => "mt-ForwardSM",
        46 => "sendRoutingInfoForSM",
        47 => "mo-ForwardSM",
        48 => "reportSM-DeliveryStatus",
        50 => "activateTraceMode",
        51 => "deactivateTraceMode",
        55 => "sendIMSI",
        56 => "sendAuthenticationInfo",
        57 => "restoreData",
        58 => "sendRoutingInfoForLCS",
        59 => "subscriberLocationReport",
        60 => "sendRoutingInfoForSM-2",
        62 => "provideSubscriberLocation",
        63 => "sendRoutingInfoForLCS-2",
        64 => "provideSubscriberInfo",
        67 => "anyTimeInterrogation",
        69 => "ss-InvocationNotification",
        70 => "anyTimeSubscriptionInterrogation",
        71 => "anyTimeModification",
        72 => "noteSubscriberDataModified-2",
        83 => "purgeMS",
        _ => return None,
    })
}

/// One BER element: its tag, and the value bytes.
struct BerElement<'a> {
    tag: u8,
    value: &'a [u8],
}

/// Read one BER element from the front of `data`.
///
/// Handles both the short form (length in one byte, high bit clear) and the
/// long form (low bits say how many bytes hold the length). Indefinite length
/// is not used by TCAP over SCCP and is rejected.
fn read_ber(data: &[u8]) -> Option<BerElement<'_>> {
    let tag = *data.first()?;
    let first_len = *data.get(1)? as usize;
    let (len, header) = if first_len & 0x80 == 0 {
        (first_len, 2)
    } else {
        let count = first_len & 0x7F;
        // 0 means indefinite length; more than 4 bytes is beyond anything real.
        if count == 0 || count > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..count {
            len = (len << 8) | *data.get(2 + i)? as usize;
        }
        (len, 2 + count)
    };
    let value = data.get(header..header.checked_add(len)?)?;
    Some(BerElement { tag, value })
}

/// Walk the elements of a BER sequence, returning the first with `want_tag`.
fn find_ber(mut data: &[u8], want_tag: u8) -> Option<&[u8]> {
    while !data.is_empty() {
        let el = read_ber(data)?;
        if el.tag == want_tag {
            return Some(el.value);
        }
        // Advance past this element: its value plus however long its header was.
        let consumed = (el.value.as_ptr() as usize) - (data.as_ptr() as usize) + el.value.len();
        data = data.get(consumed..)?;
    }
    None
}

/// The component portion tag inside a TCAP message (Q.773).
const COMPONENT_PORTION: u8 = 0x6C;
/// The operation-code tag inside an Invoke component.
const OPERATION_CODE: u8 = 0x02;

/// Describe a TCAP message, or `None` if this is not TCAP.
///
/// Returned rather than built into a `DissectedResult` because SCCP calls this
/// to decide whether the more specific TCAP label applies to the packet.
pub(crate) fn describe(payload: &[u8]) -> Option<String> {
    let outer = read_ber(payload)?;
    let msg = message_name(outer.tag)?;

    // The component portion is optional — an Abort or an empty Continue has none.
    let Some(components) = find_ber(outer.value, COMPONENT_PORTION) else {
        return Some(format!("TCAP {msg}"));
    };
    let Some(component) = read_ber(components) else {
        return Some(format!("TCAP {msg}"));
    };
    let Some(kind) = component_name(component.tag) else {
        return Some(format!("TCAP {msg}"));
    };

    // Inside the component: the invoke id, then the operation code. Both are
    // plain INTEGERs, so take the second one.
    let mut rest = component.value;
    let mut opcode = None;
    let mut integers = 0;
    while let Some(el) = read_ber(rest) {
        if el.tag == OPERATION_CODE {
            integers += 1;
            if integers == 2 {
                opcode = el.value.first().copied();
                break;
            }
        }
        let consumed = (el.value.as_ptr() as usize) - (rest.as_ptr() as usize) + el.value.len();
        match rest.get(consumed..) {
            Some(next) if !next.is_empty() => rest = next,
            _ => break,
        }
    }

    Some(match opcode {
        Some(code) => match map_operation(code) {
            Some(name) => format!("TCAP {msg} {kind} — {name}"),
            None => format!("TCAP {msg} {kind} — operation {code}"),
        },
        None => format!("TCAP {msg} {kind}"),
    })
}

// This module has no `dissect_*` entry point of its own. SCCP calls
// [`describe`] and labels the packet, because SCCP is what knows the routing
// context the summary needs. A second entry point here would be an untested
// code path free to drift from the one that runs.

#[cfg(test)]
pub(crate) mod test_helpers {
    /// Wrap `value` in a BER element with the given tag (short form only,
    /// which is all these tests need).
    pub fn ber(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut v = vec![tag, value.len() as u8];
        v.extend_from_slice(value);
        v
    }

    /// Build a TCAP message carrying one Invoke of the given MAP operation.
    pub fn tcap_invoke(msg_tag: u8, opcode: u8) -> Vec<u8> {
        let invoke_id = ber(0x02, &[1]);
        let op = ber(0x02, &[opcode]);
        let mut component_body = invoke_id;
        component_body.extend_from_slice(&op);
        let component = ber(0xA1, &component_body);
        let portion = ber(0x6C, &component);
        // A transaction id precedes the component portion in a real message.
        let mut body = ber(0x48, &[0x11, 0x22, 0x33, 0x44]);
        body.extend_from_slice(&portion);
        ber(msg_tag, &body)
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::{ber, tcap_invoke};
    use super::*;

    /// The operation that resolves where to deliver a text message — one of the
    /// two operations SS7 interception abuse is built on.
    #[test]
    fn names_send_routing_info_for_sm() {
        let p = tcap_invoke(0x62, 46);
        assert_eq!(
            describe(&p).as_deref(),
            Some("TCAP Begin Invoke — sendRoutingInfoForSM")
        );
    }

    /// The other one: asking the network where a subscriber physically is.
    #[test]
    fn names_any_time_interrogation() {
        let p = tcap_invoke(0x62, 67);
        assert_eq!(
            describe(&p).as_deref(),
            Some("TCAP Begin Invoke — anyTimeInterrogation")
        );
    }

    #[test]
    fn names_update_location() {
        let p = tcap_invoke(0x62, 2);
        assert_eq!(
            describe(&p).as_deref(),
            Some("TCAP Begin Invoke — updateLocation")
        );
    }

    #[test]
    fn end_message_with_a_result() {
        let invoke_id = ber(0x02, &[1]);
        let op = ber(0x02, &[46]);
        let mut body = invoke_id;
        body.extend_from_slice(&op);
        let component = ber(0xA2, &body); // ReturnResultLast
        let portion = ber(0x6C, &component);
        let p = ber(0x64, &portion);
        assert_eq!(
            describe(&p).as_deref(),
            Some("TCAP End ReturnResultLast — sendRoutingInfoForSM")
        );
    }

    #[test]
    fn message_without_a_component_portion() {
        let p = ber(0x67, &ber(0x49, &[0x11, 0x22])); // Abort, transaction id only
        assert_eq!(describe(&p).as_deref(), Some("TCAP Abort"));
    }

    #[test]
    fn unknown_operation_reports_its_code() {
        let p = tcap_invoke(0x62, 200);
        assert_eq!(
            describe(&p).as_deref(),
            Some("TCAP Begin Invoke — operation 200")
        );
    }

    /// `describe` returning None is what tells SCCP the data is not TCAP, so a
    /// foreign payload must not be claimed.
    #[test]
    fn non_tcap_payload_is_not_claimed() {
        assert_eq!(describe(&[0xFF, 0x00]), None);
        assert_eq!(describe(&[]), None);
        assert_eq!(describe(b"GET / HTTP/1.1"), None);
    }

    /// A length that runs past the buffer must fail cleanly, not panic or read
    /// out of bounds.
    #[test]
    fn truncated_lengths_are_rejected() {
        assert_eq!(describe(&[0x62, 0x7F, 0x00]), None);
        // Long-form length claiming four bytes that are not there.
        assert_eq!(describe(&[0x62, 0x84, 0xFF]), None);
        // Indefinite length is not valid here.
        assert_eq!(describe(&[0x62, 0x80, 0x00, 0x00]), None);
    }

    /// A foreign payload must yield nothing, which is how SCCP learns the data
    /// was not TCAP and keeps its own label.
    #[test]
    fn a_foreign_payload_is_not_described() {
        assert!(describe(&tcap_invoke(0x62, 46)).is_some());
        assert!(describe(&[0xFF]).is_none());
    }
}
