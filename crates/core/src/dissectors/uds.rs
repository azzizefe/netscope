// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! UDS — the diagnostic language inside a DoIP message (ISO 14229).
//!
//! DoIP is the envelope; this is the letter. A capture that says "diagnostic
//! message" over and over has told you nothing, because every interesting
//! difference — reading a fault code, unlocking an ECU, starting a firmware
//! write — is one byte further in.
//!
//! Two exchanges are worth recognising on sight. `SecurityAccess` is an ECU
//! being unlocked, and its refusals say whether a key was wrong or an attempt
//! limit was hit. `RequestDownload` followed by `TransferData` is a firmware
//! write in progress, which is the most consequential thing that can happen on
//! a vehicle network.

/// Services. Restricted to those defined by the standard; manufacturers add
/// their own in a reserved range, and guessing at those would be inventing.
fn service_name(service: u8) -> Option<&'static str> {
    Some(match service {
        0x10 => "start diagnostic session",
        0x11 => "reset ECU",
        0x14 => "clear fault codes",
        0x19 => "read fault codes",
        0x22 => "read data",
        0x23 => "read memory",
        0x27 => "security access",
        0x28 => "control communication",
        0x2E => "write data",
        0x2F => "control input/output",
        0x31 => "run routine",
        0x34 => "request download",
        0x35 => "request upload",
        0x36 => "transfer data",
        0x37 => "end transfer",
        0x3E => "tester present",
        0x85 => "control fault-code setting",
        0x87 => "link control",
        _ => return None,
    })
}

/// Why a request was refused. These matter more than the requests: a session
/// that goes nowhere is usually a string of these.
fn refusal_reason(code: u8) -> Option<&'static str> {
    Some(match code {
        0x10 => "general reject",
        0x11 => "service not supported",
        0x12 => "sub-function not supported",
        0x13 => "wrong message length",
        0x22 => "conditions not correct",
        0x24 => "request out of sequence",
        0x31 => "request out of range",
        0x33 => "security access denied",
        0x35 => "invalid key",
        0x36 => "too many failed attempts",
        0x37 => "required delay not elapsed",
        0x72 => "programming failure",
        0x78 => "busy, response pending",
        0x7E => "service not allowed in this session",
        0x7F => "sub-function not allowed in this session",
        _ => return None,
    })
}

/// A reply's service byte is the request's plus this.
const RESPONSE_OFFSET: u8 = 0x40;
/// A refusal uses this service byte whatever was asked.
const NEGATIVE_RESPONSE: u8 = 0x7F;

/// Describe a UDS payload — the bytes after the DoIP addresses.
///
/// Returns nothing when the service is not one the standard defines, so the
/// caller can fall back to naming the envelope rather than inventing a verb.
pub(crate) fn describe(payload: &[u8]) -> Option<String> {
    let &service = payload.first()?;

    if service == NEGATIVE_RESPONSE {
        let asked = payload.get(1).copied()?;
        let code = payload.get(2).copied().unwrap_or(0);
        let what = service_name(asked)
            .map(|n| n.to_string())
            .unwrap_or_else(|| format!("service 0x{asked:02X}"));
        return Some(match refusal_reason(code) {
            Some(reason) => format!("UDS {what} refused — {reason}"),
            None => format!("UDS {what} refused — code 0x{code:02X}"),
        });
    }

    // A reply carries the request's service plus 0x40.
    let (requested, is_reply) = if service >= RESPONSE_OFFSET
        && service_name(service.wrapping_sub(RESPONSE_OFFSET)).is_some()
    {
        (service.wrapping_sub(RESPONSE_OFFSET), true)
    } else {
        (service, false)
    };
    let name = service_name(requested)?;
    let direction = if is_reply { " — response" } else { "" };

    // Security access alternates between asking for a seed and returning a key,
    // told apart by whether the sub-function is odd.
    if requested == 0x27 {
        if let Some(&sub) = payload.get(1) {
            let step = if sub % 2 == 1 { "seed request" } else { "key" };
            return Some(format!("UDS security access — {step}{direction}"));
        }
    }

    // A download or upload request is the opening of a firmware write, which is
    // worth naming as such rather than as a generic service.
    if matches!(requested, 0x34 | 0x35) {
        let what = if requested == 0x34 {
            "download to ECU"
        } else {
            "upload from ECU"
        };
        return Some(format!("UDS {what} requested{direction}"));
    }

    // Reading or writing a data identifier: the identifier is what was read.
    if matches!(requested, 0x22 | 0x2E) {
        if let Some(bytes) = payload.get(1..3) {
            let id = u16::from_be_bytes([bytes[0], bytes[1]]);
            return Some(format!("UDS {name} 0x{id:04X}{direction}"));
        }
    }

    Some(format!("UDS {name}{direction}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The everyday request-and-reply, which DoIP alone showed as two
    /// identical "diagnostic message" lines.
    #[test]
    fn a_request_and_its_reply_are_distinguished() {
        assert_eq!(
            describe(&[0x22, 0xF1, 0x90]).unwrap(),
            "UDS read data 0xF190"
        );
        assert_eq!(
            describe(&[0x62, 0xF1, 0x90, 0x01]).unwrap(),
            "UDS read data 0xF190 — response"
        );
    }

    /// Unlocking an ECU alternates seed and key; the sub-function's parity is
    /// what says which half of the exchange this is.
    #[test]
    fn security_access_distinguishes_seed_from_key() {
        assert_eq!(
            describe(&[0x27, 0x01]).unwrap(),
            "UDS security access — seed request"
        );
        assert_eq!(
            describe(&[0x27, 0x02]).unwrap(),
            "UDS security access — key"
        );
        assert_eq!(
            describe(&[0x67, 0x01]).unwrap(),
            "UDS security access — seed request — response"
        );
    }

    /// A refused unlock says whether the key was wrong or the ECU has stopped
    /// accepting attempts — a very different situation.
    #[test]
    fn a_refusal_gives_its_reason() {
        assert_eq!(
            describe(&[0x7F, 0x27, 0x35]).unwrap(),
            "UDS security access refused — invalid key"
        );
        assert_eq!(
            describe(&[0x7F, 0x27, 0x36]).unwrap(),
            "UDS security access refused — too many failed attempts"
        );
        assert_eq!(
            describe(&[0x7F, 0x22, 0x33]).unwrap(),
            "UDS read data refused — security access denied"
        );
    }

    /// The most consequential thing that can happen on a vehicle network, and
    /// it deserves to be named rather than left as "service 0x34".
    #[test]
    fn a_firmware_write_is_named_as_one() {
        assert_eq!(
            describe(&[0x34, 0x00, 0x44]).unwrap(),
            "UDS download to ECU requested"
        );
        assert_eq!(
            describe(&[0x35, 0x00, 0x44]).unwrap(),
            "UDS upload from ECU requested"
        );
        assert_eq!(describe(&[0x36, 0x01]).unwrap(), "UDS transfer data");
    }

    /// Reading and clearing fault codes is the routine reason for a session.
    #[test]
    fn fault_code_services_are_named() {
        assert_eq!(
            describe(&[0x19, 0x02, 0xFF]).unwrap(),
            "UDS read fault codes"
        );
        assert_eq!(
            describe(&[0x14, 0xFF, 0xFF, 0xFF]).unwrap(),
            "UDS clear fault codes"
        );
        assert_eq!(describe(&[0x3E, 0x00]).unwrap(), "UDS tester present");
    }

    /// Manufacturers define their own services in a reserved range. Returning
    /// nothing lets the caller name the envelope rather than invent a verb.
    #[test]
    fn an_unknown_service_is_not_given_a_name() {
        assert!(describe(&[0xBA, 0x01]).is_none());
        assert!(describe(&[]).is_none());
        // A refusal is still readable even when the refused service is unknown.
        assert_eq!(
            describe(&[0x7F, 0xBA, 0x11]).unwrap(),
            "UDS service 0xBA refused — service not supported"
        );
    }

    /// A refusal code outside the standard keeps its number rather than being
    /// mapped to whichever reason was nearest.
    #[test]
    fn an_unknown_refusal_code_keeps_its_number() {
        assert_eq!(
            describe(&[0x7F, 0x22, 0xA5]).unwrap(),
            "UDS read data refused — code 0xA5"
        );
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[0x22]).unwrap(), "UDS read data");
        assert_eq!(describe(&[0x27]).unwrap(), "UDS security access");
        assert!(describe(&[0x7F]).is_none());
    }
}
