// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! iSER — iSCSI with the data path handed to RDMA (RFC 7145).
//!
//! Ordinary iSCSI copies every block through the kernel twice. iSER keeps
//! iSCSI's commands and responses but moves the *data* onto RDMA: the initiator
//! advertises a memory region and the target reads from or writes to it
//! directly. All-flash arrays and NVMe gateways use it because the copying is
//! what costs, not the protocol.
//!
//! The split is what makes a capture confusing. Commands appear as iSER
//! messages carrying an ordinary iSCSI PDU, but the blocks those commands move
//! never appear at all — they travel as RDMA READ and WRITE operations against
//! the advertised region, which is a different opcode on a different packet. A
//! capture showing commands and no data is not a broken transfer; that is how
//! iSER is supposed to look.
//!
//! ## What is worth reading
//!
//! The header advertises which memory regions the target may touch — a write
//! region, a read region, or neither. Those tags are how a command becomes a
//! transfer, and a command that advertises neither is one the target cannot
//! move data for.
//!
//! The reject flag is the failure: the target refusing the message outright,
//! before iSCSI's own status codes get a chance to say anything.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Opcode and flags, three reserved bytes, then the write and read region
/// descriptors.
const HEADER_LEN: usize = 28;

/// Flags in the low nibble of the first byte.
const FLAG_WRITE_STAG: u8 = 0x08;
const FLAG_READ_STAG: u8 = 0x04;
const FLAG_REJECT: u8 = 0x01;

/// What the message is, from the high nibble.
fn opcode_name(opcode: u8) -> Option<&'static str> {
    Some(match opcode {
        0x1 => "iSCSI control",
        0x2 => "Hello",
        0x3 => "HelloReply",
        _ => return None,
    })
}

/// Whether a payload is an iSER header.
///
/// iSER and SMB Direct both ride on RDMA SEND and neither carries a protocol
/// identifier — which service a queue pair was connected for is established by
/// the connection manager, not repeated in every packet. So recognition has to
/// come from the header's own shape: a defined opcode, and the three reserved
/// bytes after it actually being zero. That is weak evidence on its own, which
/// is why the caller only offers RDMA SEND payloads to it.
pub(crate) fn looks_like_iser(payload: &[u8]) -> bool {
    let Some(head) = payload.get(..4) else {
        return false;
    };
    opcode_name(head[0] >> 4).is_some() && head[1..4] == [0, 0, 0]
}

/// Dissect an iSER message, reporting the iSCSI PDU inside a control message.
pub fn dissect_iser(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let base = DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Iser,
        summary: String::new(),
    };

    let Some(&first) = payload.first() else {
        return DissectedResult {
            summary: "iSER".into(),
            ..base
        };
    };
    let opcode = first >> 4;
    let flags = first & 0x0F;
    let Some(name) = opcode_name(opcode) else {
        return DissectedResult {
            summary: format!("iSER (opcode {opcode})"),
            ..base
        };
    };

    // A reject is the target refusing the message outright, ahead of anything
    // iSCSI's own status field could report.
    if flags & FLAG_REJECT != 0 {
        return DissectedResult {
            summary: format!("iSER {name} — rejected by the target"),
            ..base
        };
    }

    // Which memory regions the target has been given access to. A command
    // advertising neither cannot move data, whatever it asks for.
    let regions = match (flags & FLAG_WRITE_STAG != 0, flags & FLAG_READ_STAG != 0) {
        (true, true) => " [read and write regions advertised]",
        (true, false) => " [write region advertised]",
        (false, true) => " [read region advertised]",
        (false, false) => "",
    };

    // A control message carries a whole iSCSI PDU, and that is the answer —
    // iSER is the envelope. The blocks themselves never appear here.
    if opcode == 0x1 {
        if let Some(pdu) = payload.get(HEADER_LEN..).filter(|p| !p.is_empty()) {
            let inner = super::iscsi::dissect_iscsi(src_ip, dst_ip, src_port, dst_port, pdu);
            return DissectedResult {
                summary: format!("iSER{regions} · {}", inner.summary),
                ..base
            };
        }
    }

    DissectedResult {
        summary: format!("iSER {name}{regions}"),
        ..base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an iSER header, optionally followed by an iSCSI PDU.
    fn iser(opcode: u8, flags: u8, pdu: &[u8]) -> Vec<u8> {
        let mut v = vec![(opcode << 4) | flags, 0, 0, 0];
        v.extend_from_slice(&[0u8; HEADER_LEN - 4]);
        v.extend_from_slice(pdu);
        v
    }

    /// The reason this dissector exists: the command is here and readable, and
    /// what it does to the disk is an iSCSI PDU inside the envelope.
    #[test]
    fn a_control_message_reports_the_iscsi_pdu_inside_it() {
        // iSCSI opcode 0x01: SCSI Command.
        let r = dissect_iser(None, None, 0, 0, &iser(0x1, 0, &[0x01, 0x00]));
        assert_eq!(r.protocol, Protocol::Iser);
        assert!(r.summary.starts_with("iSER · "), "{}", r.summary);
        assert!(r.summary.contains("SCSI"), "{}", r.summary);
    }

    /// The advertised regions are what turn a command into a transfer.
    #[test]
    fn the_advertised_regions_are_reported() {
        let write = dissect_iser(None, None, 0, 0, &iser(0x1, FLAG_WRITE_STAG, &[0x01]));
        assert!(write.summary.contains("write region"), "{}", write.summary);

        let both = dissect_iser(
            None,
            None,
            0,
            0,
            &iser(0x1, FLAG_WRITE_STAG | FLAG_READ_STAG, &[0x01]),
        );
        assert!(
            both.summary.contains("read and write regions"),
            "{}",
            both.summary
        );

        // Neither is not an error, but it is not advertised either.
        let none = dissect_iser(None, None, 0, 0, &iser(0x2, 0, &[]));
        assert_eq!(none.summary, "iSER Hello");
    }

    /// A reject is the target refusing before iSCSI's own status can speak.
    #[test]
    fn a_reject_is_reported_ahead_of_the_inner_pdu() {
        let r = dissect_iser(None, None, 0, 0, &iser(0x1, FLAG_REJECT, &[0x01, 0x00]));
        assert_eq!(r.summary, "iSER iSCSI control — rejected by the target");
    }

    #[test]
    fn the_handshake_messages_are_named() {
        assert_eq!(
            dissect_iser(None, None, 0, 0, &iser(0x2, 0, &[])).summary,
            "iSER Hello"
        );
        assert_eq!(
            dissect_iser(None, None, 0, 0, &iser(0x3, 0, &[])).summary,
            "iSER HelloReply"
        );
    }

    /// iSER carries no protocol identifier, so recognition rests on a defined
    /// opcode plus the reserved bytes actually being reserved. That is weak on
    /// its own, which is why only RDMA SEND payloads are offered to it.
    #[test]
    fn recognition_needs_a_defined_opcode_and_zeroed_reserved_bytes() {
        assert!(looks_like_iser(&iser(0x1, 0, &[])));
        assert!(looks_like_iser(&iser(0x3, FLAG_REJECT, &[])));
        // An opcode the standard does not define.
        assert!(!looks_like_iser(&iser(0x7, 0, &[])));
        // Reserved bytes carrying data means this is not an iSER header.
        let mut dirty = iser(0x1, 0, &[]);
        dirty[2] = 0x55;
        assert!(!looks_like_iser(&dirty));
        assert!(!looks_like_iser(&[0x10]));
        assert!(!looks_like_iser(&[]));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(dissect_iser(None, None, 0, 0, &[]).summary, "iSER");
        assert_eq!(
            dissect_iser(None, None, 0, 0, &[0x70]).summary,
            "iSER (opcode 7)"
        );
        // A control message whose PDU has not arrived falls back to the name.
        assert_eq!(
            dissect_iser(None, None, 0, 0, &iser(0x1, 0, &[])).summary,
            "iSER iSCSI control"
        );
    }
}
