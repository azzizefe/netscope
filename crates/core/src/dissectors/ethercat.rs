// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 azzizefe. All rights reserved.
use crate::models::Protocol;

use super::DissectedResult;

/// Name the EtherCAT datagram command (the byte after the 2-byte header).
fn command_name(cmd: u8) -> &'static str {
    match cmd {
        0 => "NOP",
        1 => "APRD (auto-inc read)",
        2 => "APWR (auto-inc write)",
        4 => "FPRD (configured read)",
        5 => "FPWR (configured write)",
        7 => "BRD (broadcast read)",
        8 => "BWR (broadcast write)",
        10 => "LRD (logical read)",
        11 => "LWR (logical write)",
        12 => "LRW (logical read/write)",
        _ => "command",
    }
}

/// EtherCAT frame types, from the top four bits of the 2-byte header.
const FRAME_TYPE_DATAGRAMS: u16 = 1;
const FRAME_TYPE_MAILBOX: u16 = 4;

/// Mailbox protocol, from the low nibble of the sixth mailbox-header byte.
const MBOX_COE: u8 = 3;
const MBOX_FOE: u8 = 4;

/// The mailbox header is six bytes ahead of the protocol data.
const MBOX_HEADER: usize = 6;

/// Dissect an EtherCAT frame (EtherType 0x88A4) — a real-time industrial
/// fieldbus that passes a frame down a chain of slaves.
///
/// The 2-byte header is little-endian: the low eleven bits are the length and
/// the top four are the frame type. Type 1 is the datagram stream that carries
/// cyclic process data; type 4 is the mailbox, which is how acyclic services
/// travel — configuration, firmware, diagnostics.
///
/// The distinction matters because a mailbox frame is not EtherCAT's own
/// protocol at all. It is an envelope, and the protocol inside is named by one
/// nibble of the mailbox header (ETG.1000 §5.6): CoE is the CANopen object
/// dictionary, FoE is a file transfer. Reporting either as "EtherCAT" hides a
/// firmware push behind a fieldbus label.
pub fn dissect_ethercat(payload: &[u8]) -> DissectedResult {
    let frame_type = payload
        .get(..2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]) >> 12);

    if frame_type == Some(FRAME_TYPE_MAILBOX) {
        if let Some(inner) = mailbox(&payload[2..]) {
            return inner;
        }
    }
    // Clock registers are addressed by a datagram, so only a datagram frame is
    // examined for them — a mailbox body could otherwise land in the register
    // range by coincidence.
    if frame_type == Some(FRAME_TYPE_DATAGRAMS) {
        if let Some(dc) = distributed_clocks(&payload[2..]) {
            return dc;
        }
    }

    let summary = match (frame_type, payload.get(2)) {
        (Some(FRAME_TYPE_MAILBOX), _) => "EtherCAT mailbox".to_string(),
        (_, Some(&cmd)) => format!("EtherCAT {}", command_name(cmd)),
        (_, None) => "EtherCAT (truncated)".to_string(),
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Ethercat,
        summary,
    }
}

/// The slave registers that hold the distributed-clock configuration
/// (ETG.1000 §5.3). A write here is a line being synchronised.
const DC_REGISTERS: std::ops::RangeInclusive<u16> = 0x0900..=0x09FF;

/// A datagram header is ten bytes ahead of its data.
const DATAGRAM_HEADER: usize = 10;

/// Recognise a datagram addressed at the distributed-clock registers.
///
/// Distributed clocks are what make an EtherCAT line isochronous — every slave
/// agreeing on the same time to sub-microsecond accuracy. When that drifts,
/// motion goes out of sync, and the drift is written here. An ordinary
/// register write and a clock adjustment look identical until the address is
/// read, which is why this keys on the offset rather than the command.
fn distributed_clocks(datagram: &[u8]) -> Option<DissectedResult> {
    let header = datagram.get(..DATAGRAM_HEADER)?;
    // Bytes 4-5 are the address offset — which register the command addresses.
    let offset = u16::from_le_bytes([header[4], header[5]]);
    if !DC_REGISTERS.contains(&offset) {
        return None;
    }
    let data = datagram.get(DATAGRAM_HEADER..)?;
    Some(
        super::ethercat_distributed_clocks::dissect_ethercat_distributed_clocks(
            None, None, 0, 0, data,
        ),
    )
}

/// Hand a mailbox message to whichever protocol its type nibble names.
///
/// Returns `None` when the header is short or the protocol is one nothing here
/// decodes, so the caller falls back to reporting a mailbox and no more —
/// guessing at an unknown mailbox type would attribute a service to the wrong
/// protocol entirely.
fn mailbox(body: &[u8]) -> Option<DissectedResult> {
    let header = body.get(..MBOX_HEADER)?;
    // Byte 5: low nibble is the protocol, high nibble a rolling counter.
    match header[5] & 0x0F {
        MBOX_COE => Some(super::ethercat_beckhoff_mdp::dissect_ethercat_beckhoff_mdp(
            None,
            None,
            0,
            0,
            &body[MBOX_HEADER..],
        )),
        MBOX_FOE => Some(super::ethercat_foe_detail::dissect_ethercat_foe_detail(
            None,
            None,
            0,
            0,
            &body[MBOX_HEADER..],
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a mailbox frame carrying `protocol` and `body`.
    fn mbox_frame(protocol: u8, body: &[u8]) -> Vec<u8> {
        // Frame header: type 4 in the top nibble, length in the low bits.
        let hdr = (FRAME_TYPE_MAILBOX << 12) | (body.len() + MBOX_HEADER) as u16;
        let mut f = hdr.to_le_bytes().to_vec();
        f.extend_from_slice(&(body.len() as u16).to_le_bytes()); // mailbox length
        f.extend_from_slice(&[0x00, 0x00]); // address
        f.push(0x00); // channel + priority
        f.push(protocol); // protocol nibble, counter 0
        f.extend_from_slice(body);
        f
    }

    #[test]
    fn logical_rw() {
        // Frame type 1 (datagrams), then command 12 (LRW).
        let r = dissect_ethercat(&[0x10, 0x10, 12, 0x00]);
        assert_eq!(r.protocol, Protocol::Ethercat);
        assert!(r.summary.contains("LRW"), "{}", r.summary);
    }

    /// A firmware transfer is the thing worth catching here — it used to read
    /// as an ordinary EtherCAT frame, which says nothing about a device having
    /// its firmware replaced.
    #[test]
    fn a_file_transfer_is_lifted_out_of_the_mailbox() {
        let foe = mbox_frame(MBOX_FOE, &[0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
        let r = dissect_ethercat(&foe);
        assert_eq!(r.protocol, Protocol::EthercatFoeDetail);
        assert!(r.summary.contains("FoE"), "{}", r.summary);
    }

    /// CoE is the object dictionary — configuration reads and writes.
    #[test]
    fn a_coe_access_is_lifted_out_of_the_mailbox() {
        let coe = mbox_frame(MBOX_COE, &[0x60, 0x00, 0x01, 0x02, 0, 0, 0, 0]);
        assert_eq!(
            dissect_ethercat(&coe).protocol,
            Protocol::EthercatBeckhoffMdp
        );
    }

    /// A mailbox protocol nothing here decodes stays a mailbox rather than
    /// being handed to whichever decoder happened to be listed first.
    #[test]
    fn an_unknown_mailbox_protocol_is_not_guessed_at() {
        // 2 is EoE, which no dissector here claims.
        let eoe = mbox_frame(2, &[0u8; 8]);
        let r = dissect_ethercat(&eoe);
        assert_eq!(r.protocol, Protocol::Ethercat);
        assert_eq!(r.summary, "EtherCAT mailbox");
    }

    /// A truncated mailbox header is not read past.
    #[test]
    fn a_truncated_mailbox_does_not_panic() {
        let hdr = ((FRAME_TYPE_MAILBOX << 12) | 4).to_le_bytes();
        let r = dissect_ethercat(&[hdr[0], hdr[1], 0x01]);
        assert_eq!(r.protocol, Protocol::Ethercat);
    }

    /// Build a datagram frame addressing register `offset`.
    fn datagram(cmd: u8, offset: u16, data: &[u8]) -> Vec<u8> {
        let hdr = (FRAME_TYPE_DATAGRAMS << 12) | (DATAGRAM_HEADER + data.len()) as u16;
        let mut f = hdr.to_le_bytes().to_vec();
        f.push(cmd);
        f.push(0); // index
        f.extend_from_slice(&[0x00, 0x00]); // ADP
        f.extend_from_slice(&offset.to_le_bytes()); // ADO
        f.extend_from_slice(&(data.len() as u16).to_le_bytes());
        f.extend_from_slice(&[0x00, 0x00]); // IRQ
        f.extend_from_slice(data);
        f
    }

    /// A clock adjustment and an ordinary register write are the same command
    /// — only the address tells them apart, and drift going out of tolerance
    /// is what desynchronises a motion line.
    #[test]
    fn a_write_to_the_clock_registers_is_read_as_a_clock_adjustment() {
        let dc = datagram(5, 0x0920, &[0x03, 0x00, 0x0F, 0x42, 0x40, 0x0A, 0x00, 0x64]);
        let r = dissect_ethercat(&dc);
        assert_eq!(r.protocol, Protocol::EthercatDistributedClocks);

        // The same command at an ordinary register stays an EtherCAT write.
        let plain = datagram(5, 0x0130, &[0u8; 8]);
        let r = dissect_ethercat(&plain);
        assert_eq!(r.protocol, Protocol::Ethercat);
        assert!(r.summary.contains("FPWR"), "{}", r.summary);
    }

    /// A mailbox frame is never read as a datagram, so its bytes cannot land
    /// in the clock-register range by coincidence.
    #[test]
    fn a_mailbox_is_not_examined_for_clock_registers() {
        let coe = mbox_frame(MBOX_COE, &[0x60, 0x00, 0x01, 0x02, 0, 0, 0, 0]);
        assert_eq!(
            dissect_ethercat(&coe).protocol,
            Protocol::EthercatBeckhoffMdp
        );
    }
}
