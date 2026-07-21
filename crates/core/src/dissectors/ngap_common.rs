// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! The header shared by the 3GPP "application protocol" family — NGAP, S1AP,
//! XnAP, F1AP, E1AP and the rest.
//!
//! Every one of them defines its top-level PDU the same way (see 3GPP TS 38.413
//! §9.4 for NGAP, TS 36.413 §9.4 for S1AP — the ASN.1 is copy-paste across the
//! family):
//!
//! ```text
//! NGAP-PDU ::= CHOICE {
//!     initiatingMessage    InitiatingMessage,
//!     successfulOutcome    SuccessfulOutcome,
//!     unsuccessfulOutcome  UnsuccessfulOutcome
//! }
//! InitiatingMessage ::= SEQUENCE {
//!     procedureCode  ProcedureCode,   -- INTEGER (0..255)
//!     criticality    Criticality,     -- ENUMERATED { reject, ignore, notify }
//!     value          ANY
//! }
//! ```
//!
//! Under aligned PER that lays out as: a 2-bit choice index in the top of the
//! first byte, then the procedure code in the whole second byte, then a 2-bit
//! criticality. The `value` beyond that is a full ASN.1 PER decode, which we do
//! not attempt — the message type and procedure name are what identify a packet
//! in a list, and they sit in these first two bytes.

/// Which of the three PDU alternatives this message is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MessageKind {
    Initiating,
    SuccessfulOutcome,
    UnsuccessfulOutcome,
}

impl MessageKind {
    /// The suffix shown after the procedure name. An initiating message reads
    /// naturally on its own ("InitialContextSetup"), so it gets no suffix.
    pub fn suffix(self) -> &'static str {
        match self {
            MessageKind::Initiating => "",
            MessageKind::SuccessfulOutcome => " (success)",
            MessageKind::UnsuccessfulOutcome => " (failure)",
        }
    }
}

/// The decoded common header.
pub(crate) struct ApPdu<'a> {
    pub kind: MessageKind,
    pub procedure_code: u8,
    pub criticality: &'static str,
    #[allow(dead_code)]
    pub value: &'a [u8],
}

/// Decode Aligned PER length determinant (ITU-T X.691 §11.9).
///
/// Returns `Some((length, bytes_consumed))` on success.
pub(crate) fn decode_length(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()?;
    if first & 0x80 == 0 {
        // Short form: 0LLLLLLL (1 byte)
        Some((first as usize, 1))
    } else if first & 0xC0 == 0x80 {
        // Long form: 10LLLLLL LLLLLLLL (2 bytes)
        let second = *data.get(1)?;
        let len = (((first & 0x3F) as usize) << 8) | (second as usize);
        Some((len, 2))
    } else {
        // Fragmented form: 11000nnn (nnn blocks of 16K octets)
        let n = (first & 0x07) as usize;
        if (1..=4).contains(&n) {
            Some((n * 16384, 1))
        } else {
            None
        }
    }
}

/// Parse the common header. Returns `None` when the payload is too
/// short or the choice index names an alternative that does not exist.
pub(crate) fn parse(payload: &[u8]) -> Option<ApPdu<'_>> {
    let first = *payload.first()?;
    let procedure_code = *payload.get(1)?;
    // The choice index occupies the top 2 bits of the first byte.
    let kind = match first >> 6 {
        0 => MessageKind::Initiating,
        1 => MessageKind::SuccessfulOutcome,
        2 => MessageKind::UnsuccessfulOutcome,
        // 3 is not a defined alternative — the payload is not one of these PDUs.
        _ => return None,
    };
    // Criticality is the next enumerated field, in the top 2 bits of byte 2.
    let criticality = match payload.get(2).map(|b| b >> 6) {
        Some(0) => "reject",
        Some(1) => "ignore",
        Some(2) => "notify",
        _ => "unknown",
    };

    // Aligned PER: the open type 'value' follows criticality (byte 2) and padding,
    // starting at byte 3. It begins with an APER length determinant.
    let value = if let Some(sub) = payload.get(3..) {
        if let Some((len, header)) = decode_length(sub) {
            let start = 3 + header;
            payload.get(start..start + len)?
        } else {
            if !sub.is_empty() {
                return None;
            }
            &[][..]
        }
    } else {
        &[][..]
    };

    Some(ApPdu {
        kind,
        procedure_code,
        criticality,
        value,
    })
}

/// Render the standard summary line for one of these protocols.
///
/// `name` is the protocol label ("NGAP"), `procedure` maps a procedure code to
/// its name. Unknown codes still produce a useful line — a new 3GPP release
/// adds procedures faster than any dissector tracks them, and "procedure 61" is
/// far more use than "unparsed".
pub(crate) fn summarize(
    name: &str,
    payload: &[u8],
    procedure: fn(u8) -> Option<&'static str>,
) -> String {
    let Some(pdu) = parse(payload) else {
        return format!("{name} ({})", super::bytes(payload.len() as u64));
    };
    match procedure(pdu.procedure_code) {
        Some(proc_name) => format!("{name} {proc_name}{}", pdu.kind.suffix()),
        None => format!(
            "{name} procedure {}{} [{}]",
            pdu.procedure_code,
            pdu.kind.suffix(),
            pdu.criticality
        ),
    }
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::MessageKind;

    /// Build a minimal PDU header for the given kind and procedure code.
    pub fn ap_pdu(kind: MessageKind, procedure_code: u8) -> Vec<u8> {
        let choice = match kind {
            MessageKind::Initiating => 0u8,
            MessageKind::SuccessfulOutcome => 1,
            MessageKind::UnsuccessfulOutcome => 2,
        };
        // choice index in the top 2 bits, procedure code, then criticality=reject.
        vec![choice << 6, procedure_code, 0x00, 0x00]
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::ap_pdu;
    use super::*;

    fn procedures(code: u8) -> Option<&'static str> {
        match code {
            15 => Some("InitialContextSetup"),
            _ => None,
        }
    }

    #[test]
    fn initiating_message_has_no_suffix() {
        let p = ap_pdu(MessageKind::Initiating, 15);
        assert_eq!(
            summarize("NGAP", &p, procedures),
            "NGAP InitialContextSetup"
        );
    }

    #[test]
    fn outcomes_are_labelled() {
        let ok = ap_pdu(MessageKind::SuccessfulOutcome, 15);
        assert_eq!(
            summarize("NGAP", &ok, procedures),
            "NGAP InitialContextSetup (success)"
        );
        let bad = ap_pdu(MessageKind::UnsuccessfulOutcome, 15);
        assert_eq!(
            summarize("NGAP", &bad, procedures),
            "NGAP InitialContextSetup (failure)"
        );
    }

    /// A release we don't track still has to say something useful.
    #[test]
    fn unknown_procedure_code_still_reports_the_number() {
        let p = ap_pdu(MessageKind::Initiating, 200);
        assert_eq!(
            summarize("NGAP", &p, procedures),
            "NGAP procedure 200 [reject]"
        );
    }

    #[test]
    fn reserved_choice_index_is_rejected() {
        assert!(parse(&[0xC0, 0x0F, 0x00]).is_none());
    }

    #[test]
    fn truncated_payload_is_rejected() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[0x00]).is_none());
        assert_eq!(summarize("NGAP", &[0x00], procedures), "NGAP (1 byte)");
    }

    #[test]
    fn criticality_is_decoded() {
        assert_eq!(parse(&[0x00, 0x0F, 0x00]).unwrap().criticality, "reject");
        assert_eq!(parse(&[0x00, 0x0F, 0x40]).unwrap().criticality, "ignore");
        assert_eq!(parse(&[0x00, 0x0F, 0x80]).unwrap().criticality, "notify");
    }

    #[test]
    fn length_determinant_is_decoded() {
        // Short form: 5 bytes
        let mut p1 = vec![0x00, 0x0F, 0x00];
        p1.extend_from_slice(&[5]); // Short form length = 5
        p1.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55]);
        let res1 = parse(&p1).unwrap();
        assert_eq!(res1.value, &[0x11, 0x22, 0x33, 0x44, 0x55]);

        // Long form: 258 bytes
        let mut p2 = vec![0x00, 0x0F, 0x00];
        let val: u16 = 0x8000 | 258;
        p2.extend_from_slice(&val.to_be_bytes()); // Long form length = 258
        let body = vec![0xAA; 258];
        p2.extend_from_slice(&body);
        let res2 = parse(&p2).unwrap();
        assert_eq!(res2.value, &body[..]);
    }
}
