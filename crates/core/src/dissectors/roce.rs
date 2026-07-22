// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! RoCE — one machine reading and writing another's memory (EtherType 0x8915).
//!
//! RDMA over Converged Ethernet lets a host put data straight into a remote
//! machine's memory without either kernel being involved. Storage fabrics, HPC
//! interconnects and NVMe-over-Fabrics all run on it, and the appeal is exactly
//! that nothing in the operating system sees the transfer.
//!
//! Which is also the problem. When an RDMA operation fails there is no socket
//! to return an error on and no syscall to fail: the application sees a
//! completion-queue entry with a status if it looks, and otherwise sees data
//! that quietly never arrived.
//!
//! ## The field worth reading
//!
//! An Acknowledge carries a **syndrome** in its extended header, and it is
//! either an acknowledgement or a negative one saying precisely what went
//! wrong:
//!
//! * **PSN sequence error** — a packet was lost and the receiver wants a
//!   retransmit from that point. A steady trickle is a lossy fabric; on RoCE
//!   that usually means priority flow control is missing on some hop.
//! * **Remote access error** — the memory region was not registered for this
//!   operation, or the key did not match. That is a software fault, not a
//!   network one, and it is the one most often misread as packet loss.
//! * **Remote operational error** — the far side's adapter failed the request.
//! * **RNR NAK** — receiver not ready: no buffer was posted. The occasional one
//!   is ordinary flow control; a stream of them is an application that cannot
//!   keep up.
//!
//! Nothing else in a capture separates those, and they have entirely different
//! fixes — one is a switch configuration, one is a bug.

use crate::models::Protocol;

use super::DissectedResult;

/// The Base Transport Header, after which an extended header may follow.
const BTH_LEN: usize = 12;

/// The transport service lives in the top three bits of the opcode.
fn transport_service(opcode: u8) -> &'static str {
    match opcode >> 5 {
        0 => "RC",
        1 => "UC",
        2 => "RD",
        3 => "UD",
        _ => "reserved",
    }
}

/// The operation, from the low five bits.
fn operation(opcode: u8) -> &'static str {
    match opcode & 0x1F {
        0x00 => "SEND First",
        0x01 => "SEND Middle",
        0x02 => "SEND Last",
        0x03 => "SEND Last with Immediate",
        0x04 => "SEND Only",
        0x05 => "SEND Only with Immediate",
        0x06 => "RDMA WRITE First",
        0x07 => "RDMA WRITE Middle",
        0x08 => "RDMA WRITE Last",
        0x09 => "RDMA WRITE Last with Immediate",
        0x0A => "RDMA WRITE Only",
        0x0B => "RDMA WRITE Only with Immediate",
        0x0C => "RDMA READ Request",
        0x0D => "RDMA READ Response First",
        0x0E => "RDMA READ Response Middle",
        0x0F => "RDMA READ Response Last",
        0x10 => "RDMA READ Response Only",
        0x11 => "Acknowledge",
        0x12 => "ATOMIC Acknowledge",
        0x13 => "Compare & Swap",
        0x14 => "Fetch & Add",
        _ => "operation",
    }
}

/// Whether this opcode is followed by an ACK extended header.
fn carries_aeth(opcode: u8) -> bool {
    matches!(opcode & 0x1F, 0x11 | 0x12)
}

/// Decode the syndrome byte of an ACK extended header.
///
/// Two bits select what kind of answer this is and five carry its value, so
/// reading the byte whole turns every acknowledgement into a different number
/// and loses the distinction between an ACK and a NAK entirely.
fn syndrome(byte: u8) -> String {
    let value = byte & 0x1F;
    match (byte & 0x60) >> 5 {
        0 => "acknowledged".to_string(),
        1 => "RNR NAK — receiver not ready, no buffer posted".to_string(),
        3 => match value {
            0 => "NAK — PSN sequence error, a packet was lost".to_string(),
            1 => "NAK — invalid request".to_string(),
            2 => "NAK — remote access error, the memory region was not usable".to_string(),
            3 => "NAK — remote operational error".to_string(),
            4 => "NAK — invalid RD request".to_string(),
            // A code outside the standard keeps its number rather than being
            // mapped to the nearest one that happens to exist.
            other => format!("NAK — code {other}"),
        },
        _ => "reserved syndrome".to_string(),
    }
}

/// Dissect a RoCE frame.
pub fn dissect_roce(payload: &[u8]) -> DissectedResult {
    let base = DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Roce,
        summary: String::new(),
    };
    let Some(&opcode) = payload.first() else {
        return DissectedResult {
            summary: "RoCE (empty)".into(),
            ..base
        };
    };

    let service = transport_service(opcode);
    let what = operation(opcode);

    // The destination queue pair identifies the connection, and is the only way
    // to tell two transfers between the same pair of hosts apart.
    let queue_pair = payload
        .get(5..8)
        .map(|b| u32::from_be_bytes([0, b[0], b[1], b[2]]));

    // An acknowledgement's syndrome is the whole reason to read one.
    if carries_aeth(opcode) {
        if let Some(&s) = payload.get(BTH_LEN) {
            return DissectedResult {
                summary: match queue_pair {
                    Some(qp) => format!("RoCE {service} {what} [QP {qp}] — {}", syndrome(s)),
                    None => format!("RoCE {service} {what} — {}", syndrome(s)),
                },
                ..base
            };
        }
    }

    // A SEND carries an upper-layer message. Which one is settled when the
    // queue pair is connected, not repeated per packet, so there is nothing
    // here that names the protocol — only iSER is offered a look, and only
    // because its header has reserved bytes that must be zero. Anything less
    // distinctive than that stays unclaimed rather than guessed at.
    if is_send(opcode) {
        if let Some(body) = payload.get(BTH_LEN..) {
            if super::iser::looks_like_iser(body) {
                let inner = super::iser::dissect_iser(None, None, 0, 0, body);
                return DissectedResult {
                    summary: match queue_pair {
                        Some(qp) => format!("RoCE {service} [QP {qp}] · {}", inner.summary),
                        None => format!("RoCE {service} · {}", inner.summary),
                    },
                    protocol: inner.protocol,
                    ..base
                };
            }
            if super::smb_direct::looks_like_smb_direct(body) {
                let inner = super::smb_direct::dissect_smb_direct(None, None, 0, 0, body);
                return DissectedResult {
                    summary: match queue_pair {
                        Some(qp) => format!("RoCE {service} [QP {qp}] · {}", inner.summary),
                        None => format!("RoCE {service} · {}", inner.summary),
                    },
                    protocol: inner.protocol,
                    ..base
                };
            }
            if super::srp_rdma::looks_like_srp_rdma(body) {
                let inner = super::srp_rdma::dissect_srp_rdma(None, None, 0, 0, body);
                return DissectedResult {
                    summary: match queue_pair {
                        Some(qp) => format!("RoCE {service} [QP {qp}] · {}", inner.summary),
                        None => format!("RoCE {service} · {}", inner.summary),
                    },
                    protocol: inner.protocol,
                    ..base
                };
            }
            if super::nvmeof::looks_like_nvmeof(body) {
                let inner = super::nvmeof::dissect_nvmeof(None, None, 0, 0, body);
                return DissectedResult {
                    summary: match queue_pair {
                        Some(qp) => format!("RoCE {service} [QP {qp}] · {}", inner.summary),
                        None => format!("RoCE {service} · {}", inner.summary),
                    },
                    protocol: inner.protocol,
                    ..base
                };
            }
        }
    }

    DissectedResult {
        summary: match queue_pair {
            Some(qp) => format!("RoCE {service} {what} [QP {qp}]"),
            None => format!("RoCE {service} {what}"),
        },
        ..base
    }
}

/// Whether this opcode carries an upper-layer message rather than raw memory
/// traffic. Only the "only" and "first" forms open a message.
fn is_send(opcode: u8) -> bool {
    matches!(opcode & 0x1F, 0x00 | 0x04 | 0x05)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a BTH, optionally followed by an ACK extended header.
    fn bth(opcode: u8, queue_pair: u32, aeth: Option<u8>) -> Vec<u8> {
        let mut v = vec![opcode, 0x00, 0x00, 0x00, 0x00];
        v.extend_from_slice(&queue_pair.to_be_bytes()[1..]); // 24-bit destination QP
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // ackreq + PSN
        if let Some(s) = aeth {
            v.push(s);
            v.extend_from_slice(&[0x00, 0x00, 0x01]); // message sequence number
        }
        v
    }

    /// The original test, kept: the opcode still names the operation.
    #[test]
    fn rdma_read_request() {
        let r = dissect_roce(&[0x0C, 0x40, 0xFF, 0xFF]);
        assert_eq!(r.protocol, Protocol::Roce);
        assert!(r.summary.contains("RDMA READ Request"), "{}", r.summary);
    }

    /// The reason this dissector goes past the opcode: an RDMA failure has no
    /// socket to report on, so the syndrome is the only account of it.
    #[test]
    fn a_negative_acknowledgement_says_what_went_wrong() {
        // NAK with code 2: remote access error.
        let r = dissect_roce(&bth(0x11, 5, Some(0x60 | 2)));
        assert_eq!(r.protocol, Protocol::Roce);
        assert_eq!(
            r.summary,
            "RoCE RC Acknowledge [QP 5] — NAK — remote access error, the memory region was not usable"
        );
    }

    /// The failures have entirely different fixes — one is a switch
    /// configuration, one is a software bug — so they must be distinguishable.
    #[test]
    fn the_failure_reasons_are_distinguished() {
        let nak = |code: u8| dissect_roce(&bth(0x11, 1, Some(0x60 | code))).summary;
        assert!(nak(0).contains("PSN sequence error"));
        assert!(nak(1).contains("invalid request"));
        assert!(nak(3).contains("remote operational error"));
        // RNR is a different syndrome kind, not a NAK code.
        let rnr = dissect_roce(&bth(0x11, 1, Some(0x20))).summary;
        assert!(rnr.contains("receiver not ready"), "{rnr}");
    }

    /// A successful acknowledgement must not read as a failure.
    #[test]
    fn a_positive_acknowledgement_is_not_a_nak() {
        let ok = dissect_roce(&bth(0x11, 1, Some(0x00))).summary;
        assert!(ok.contains("acknowledged"), "{ok}");
        assert!(!ok.contains("NAK"), "{ok}");
    }

    /// The syndrome is two fields in one byte. Read whole, an acknowledgement
    /// and a NAK carrying the same low bits become the same number.
    ///
    /// The bit-7 cases are the ones that matter and were missing at first:
    /// trying to break this by shifting the whole byte (`byte >> 5` instead of
    /// `(byte & 0x60) >> 5`) failed to break anything, because every test
    /// payload happened to leave the top bit clear. Bit 7 is reserved and
    /// belongs to neither field, so a sender setting it must not change how the
    /// syndrome reads — which is exactly what an unmasked shift would do.
    #[test]
    fn the_syndrome_is_split_into_kind_and_value() {
        assert!(syndrome(0x02).contains("acknowledged"));
        assert!(syndrome(0x62).contains("remote access error"));

        // The same two syndromes with the reserved top bit set.
        assert!(syndrome(0x82).contains("acknowledged"));
        assert!(syndrome(0xE2).contains("remote access error"));
        // And an RNR NAK, which sits between them.
        assert!(syndrome(0xA0).contains("receiver not ready"));
    }

    /// The transport service is the top three bits of the same byte that
    /// carries the operation.
    #[test]
    fn the_transport_service_is_read_from_the_opcode() {
        assert!(dissect_roce(&bth(0x0C, 1, None))
            .summary
            .contains("RC RDMA READ Request"));
        // 0x2C is the same operation on an unreliable connection.
        assert!(dissect_roce(&bth(0x2C, 1, None))
            .summary
            .contains("UC RDMA READ Request"));
        assert!(dissect_roce(&bth(0x64, 1, None))
            .summary
            .contains("UD SEND Only"));
    }

    /// The queue pair is what separates two transfers between the same hosts.
    #[test]
    fn the_queue_pair_is_reported() {
        let r = dissect_roce(&bth(0x04, 0x00AB_CDEF, None));
        assert!(r.summary.contains("[QP 11259375]"), "{}", r.summary);
    }

    /// A code outside the standard keeps its number.
    #[test]
    fn an_unassigned_nak_code_keeps_its_number() {
        assert!(syndrome(0x60 | 9).contains("code 9"));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(dissect_roce(&[]).summary, "RoCE (empty)");
        // An opcode with no queue pair yet.
        assert_eq!(dissect_roce(&[0x04]).summary, "RoCE RC SEND Only");
        // An acknowledgement whose syndrome byte has not arrived.
        let short = bth(0x11, 7, None);
        assert_eq!(dissect_roce(&short).summary, "RoCE RC Acknowledge [QP 7]");
    }

    /// SMB Direct payloads carried over SEND are dissected and reported.
    #[test]
    fn smb_direct_payload() {
        // Build an SMBD negotiate request payload (min=1, max=1, reserved=0, credits=10, pref_send=1024, pref_recv=1024).
        let mut smbd = vec![];
        smbd.extend_from_slice(&1u16.to_le_bytes()); // MinVersion
        smbd.extend_from_slice(&1u16.to_le_bytes()); // MaxVersion
        smbd.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        smbd.extend_from_slice(&10u16.to_le_bytes()); // CreditsRequested
        smbd.extend_from_slice(&1024u32.to_le_bytes()); // PreferredSendSize
        smbd.extend_from_slice(&1024u32.to_le_bytes()); // PreferredReceiveSize
        smbd.resize(20, 0);

        let mut payload = bth(0x04, 12, None); // RC SEND Only, QP 12
        payload.extend_from_slice(&smbd);

        let r = dissect_roce(&payload);
        assert!(r.summary.contains("SMB Direct"), "{}", r.summary);
        assert!(r.summary.contains("Negotiate"), "{}", r.summary);
        assert!(r.summary.contains("[QP 12]"), "{}", r.summary);
    }
}
