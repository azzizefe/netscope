// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! BSSGP — where a cell tells the core network it cannot cope.
//!
//! Between a GSM/GPRS base station subsystem and the SGSN sits BSS GPRS
//! Protocol. It carries user data in both directions, but the reason to read it
//! is the other traffic: this is the layer where a cell and the core negotiate
//! how much they can actually handle, and where they say when they cannot.
//!
//! ## Flow control is the interesting half
//!
//! The radio side has far less capacity than the wire side, and it varies with
//! how many subscribers are in the cell and how good their signal is. So the BSS
//! continuously tells the SGSN what it can accept — per cell (`FLOW-CONTROL-BVC`)
//! and per subscriber (`FLOW-CONTROL-MS`). A flow-control message whose
//! acknowledgement never arrives is a cell that will keep sending at the old
//! rate, and the overflow lands as `LLC-DISCARDED`: user data the network
//! accepted and then threw away. Nothing above sees a loss; a subscriber sees a
//! stalled download.
//!
//! ## The cause values name what actually broke
//!
//! `STATUS` carries a cause, and the causes are unusually specific about whose
//! fault it is. `Processor overload` and `SGSN congestion` are the core running
//! out of capacity. `Cell traffic congestion` is the radio side. `Equipment
//! failure` is hardware. `BVCI unknown` and `BVCI blocked` are configuration:
//! one side is addressing a cell the other does not have, or has taken out of
//! service. These lead to entirely different teams.
//!
//! ## BVC-RESET is not routine
//!
//! A BVC reset re-establishes the context for a cell, dropping the state for
//! every subscriber on it. Repeated resets for one cell mean it keeps losing its
//! context — subscribers there are re-attaching over and over, which looks to
//! them like intermittent loss of data service.

/// The information element that carries a cause.
const IEI_CAUSE: u8 = 0x07;
/// The information element that names the cell.
const IEI_BVCI: u8 = 0x04;

fn pdu_name(pdu: u8) -> Option<&'static str> {
    Some(match pdu {
        0x00 => "downlink data",
        0x01 => "uplink data",
        0x02 => "radio access capability",
        0x06 => "paging (packet-switched)",
        0x07 => "paging (circuit-switched)",
        0x0A => "radio status",
        0x0B => "suspend",
        0x0C => "suspend ack",
        0x0D => "suspend NACK",
        0x0E => "resume",
        0x0F => "resume ack",
        0x10 => "resume NACK",
        0x20 => "BVC BLOCK — a cell going out of service",
        0x21 => "BVC block ack",
        0x22 => "BVC RESET — a cell's context is being rebuilt",
        0x23 => "BVC reset ack",
        0x24 => "BVC unblock",
        0x25 => "BVC unblock ack",
        0x26 => "flow control (cell)",
        0x27 => "flow control ack (cell)",
        0x28 => "flow control (subscriber)",
        0x29 => "flow control ack (subscriber)",
        0x2A => "flush link layer",
        0x2B => "flush link layer ack",
        0x2C => "LLC DISCARDED — user data was thrown away",
        0x2D => "flow control (packet flow)",
        0x2E => "flow control ack (packet flow)",
        0x40 => "invoke trace",
        0x41 => "status",
        0x42 => "OVERLOAD — the SGSN is asking for less traffic",
        _ => return None,
    })
}

/// The causes, which are specific about which side of the network broke.
fn cause_name(cause: u8) -> Option<&'static str> {
    Some(match cause {
        0x00 => "processor overload",
        0x01 => "equipment failure",
        0x02 => "transit network service failure",
        0x03 => "transmission capacity restored",
        0x04 => "unknown subscriber",
        0x05 => "BVCI unknown — one side is addressing a cell the other has not",
        0x06 => "cell traffic congestion",
        0x07 => "SGSN congestion",
        0x08 => "operations and maintenance intervention",
        0x09 => "BVCI blocked",
        0x0A => "packet flow creation failed",
        0x0B => "packet flow pre-empted",
        0x0C => "quality profile no longer supported",
        _ => return None,
    })
}

/// Describe a BSSGP message.
///
/// There is no standalone entry point: BSSGP is always carried inside an
/// [`super::nsip`] data PDU.
pub(crate) fn describe(payload: &[u8]) -> String {
    let Some(&pdu) = payload.first() else {
        return "BSSGP (0 bytes)".to_string();
    };
    let Some(name) = pdu_name(pdu) else {
        return format!("BSSGP PDU {pdu:#04x}");
    };

    // The elements after the type are TLVs, and two of them carry the whole
    // diagnosis: which cell, and what went wrong.
    let mut cell = None;
    let mut cause = None;
    for (iei, value) in elements(&payload[1..]) {
        match iei {
            IEI_BVCI if value.len() >= 2 => {
                cell = Some(u16::from_be_bytes([value[0], value[1]]));
            }
            IEI_CAUSE if !value.is_empty() => cause = Some(value[0]),
            _ => {}
        }
    }

    let cell = cell
        .map(|bvci| format!(" for cell {bvci}"))
        .unwrap_or_default();
    let cause = cause
        .map(|c| {
            let named = cause_name(c)
                .map(str::to_string)
                .unwrap_or_else(|| format!("cause {c:#04x}"));
            format!(" — {named}")
        })
        .unwrap_or_default();

    format!("BSSGP {name}{cell}{cause}")
}

/// Walk the TLV elements, skipping anything malformed rather than guessing.
///
/// BSSGP uses a one-byte identifier and a length that is one byte when its top
/// bit is set and two bytes otherwise — the extension bit. Assuming one byte
/// always reads the next element's identifier as data, and the walk desynchronises
/// from there on.
fn elements(mut data: &[u8]) -> Vec<(u8, &[u8])> {
    let mut found = Vec::new();
    while data.len() >= 2 {
        let iei = data[0];
        let (length, header) = if data[1] & 0x80 != 0 {
            ((data[1] & 0x7F) as usize, 2)
        } else {
            match data.get(2) {
                Some(&low) => ((((data[1] & 0x7F) as usize) << 8) | low as usize, 3),
                None => break,
            }
        };
        let Some(value) = data.get(header..header + length) else {
            break;
        };
        found.push((iei, value));
        data = &data[header + length..];
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A short-form element: the length's top bit is set.
    fn short(iei: u8, value: &[u8]) -> Vec<u8> {
        let mut v = vec![iei, 0x80 | value.len() as u8];
        v.extend_from_slice(value);
        v
    }

    /// A long-form element: two length bytes, top bit clear.
    fn long(iei: u8, value: &[u8]) -> Vec<u8> {
        let len = value.len();
        let mut v = vec![iei, ((len >> 8) & 0x7F) as u8, (len & 0xFF) as u8];
        v.extend_from_slice(value);
        v
    }

    fn message(pdu: u8, elements: &[Vec<u8>]) -> Vec<u8> {
        let mut v = vec![pdu];
        for e in elements {
            v.extend_from_slice(e);
        }
        v
    }

    /// The reason this dissector exists: the cause says which side of the
    /// network broke, and those go to different teams.
    #[test]
    fn a_status_names_the_cell_and_the_cause() {
        let summary = describe(&message(
            0x41,
            &[short(IEI_BVCI, &[0x00, 0x2A]), short(IEI_CAUSE, &[0x07])],
        ));
        assert_eq!(summary, "BSSGP status for cell 42 — SGSN congestion");
    }

    /// Core congestion, radio congestion and a configuration mismatch are
    /// three different investigations.
    #[test]
    fn the_causes_separate_the_core_from_the_radio_from_the_configuration() {
        let with = |cause| describe(&message(0x41, &[short(IEI_CAUSE, &[cause])]));
        assert!(with(0x07).contains("SGSN congestion"));
        assert!(with(0x06).contains("cell traffic congestion"));
        assert!(with(0x01).contains("equipment failure"));
        assert!(with(0x05).contains("addressing a cell the other has not"));
    }

    /// Discarded data is loss the layers above never see.
    #[test]
    fn discarded_data_is_called_out() {
        assert!(describe(&message(0x2C, &[])).contains("thrown away"));
    }

    /// A reset drops the state for every subscriber on the cell.
    #[test]
    fn the_disruptive_messages_are_marked() {
        assert!(describe(&message(0x22, &[])).contains("context is being rebuilt"));
        assert!(describe(&message(0x20, &[])).contains("going out of service"));
        assert!(describe(&message(0x42, &[])).contains("asking for less traffic"));
    }

    /// Flow control per cell and per subscriber are different messages.
    #[test]
    fn the_flow_control_scopes_are_distinguished() {
        assert_eq!(describe(&message(0x26, &[])), "BSSGP flow control (cell)");
        assert_eq!(
            describe(&message(0x28, &[])),
            "BSSGP flow control (subscriber)"
        );
        assert_eq!(
            describe(&message(0x2D, &[])),
            "BSSGP flow control (packet flow)"
        );
    }

    /// The length is one byte when its top bit is set and two when it is not.
    /// Assuming one byte reads the next element's identifier as data, and every
    /// element after that is misread.
    #[test]
    fn the_length_extension_bit_keeps_the_walk_aligned() {
        // A long-form element followed by the one that carries the cause.
        let m = message(0x41, &[long(0x0B, &[0xAA; 4]), short(IEI_CAUSE, &[0x06])]);
        assert!(
            describe(&m).contains("cell traffic congestion"),
            "{}",
            describe(&m)
        );
    }

    /// The elements can arrive in either order.
    #[test]
    fn the_elements_are_found_in_any_order() {
        let a = describe(&message(
            0x41,
            &[short(IEI_CAUSE, &[0x06]), short(IEI_BVCI, &[0x00, 0x09])],
        ));
        let b = describe(&message(
            0x41,
            &[short(IEI_BVCI, &[0x00, 0x09]), short(IEI_CAUSE, &[0x06])],
        ));
        assert_eq!(a, b);
        assert!(a.contains("cell 9"), "{a}");
    }

    #[test]
    fn an_unknown_pdu_reports_its_number() {
        assert_eq!(describe(&message(0x77, &[])), "BSSGP PDU 0x77");
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "BSSGP (0 bytes)");
        // An element whose length runs past the message is dropped, not read.
        assert_eq!(describe(&[0x41, IEI_CAUSE, 0xFF]), "BSSGP status");
        assert_eq!(describe(&[0x41, IEI_BVCI]), "BSSGP status");
        assert_eq!(describe(&[0xFF; 6]), "BSSGP PDU 0xff");
    }
}
