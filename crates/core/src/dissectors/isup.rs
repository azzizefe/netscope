// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// ISUP message types (ITU-T Q.763 §1.0). These are the states of a telephone
/// call as it is set up, answered and released between switches.
fn message_name(t: u8) -> Option<&'static str> {
    Some(match t {
        0x01 => "IAM (Initial Address)",
        0x02 => "SAM (Subsequent Address)",
        0x03 => "INR (Information Request)",
        0x04 => "INF (Information)",
        0x05 => "COT (Continuity)",
        0x06 => "ACM (Address Complete)",
        0x07 => "CON (Connect)",
        0x08 => "FOT (Forward Transfer)",
        0x09 => "ANM (Answer)",
        0x0C => "REL (Release)",
        0x10 => "RLC (Release Complete)",
        0x11 => "CCR (Continuity Check Request)",
        0x12 => "RSC (Reset Circuit)",
        0x13 => "BLO (Blocking)",
        0x14 => "UBL (Unblocking)",
        0x15 => "BLA (Blocking Ack)",
        0x16 => "UBA (Unblocking Ack)",
        0x17 => "GRS (Circuit Group Reset)",
        0x18 => "CGB (Circuit Group Blocking)",
        0x19 => "CGU (Circuit Group Unblocking)",
        0x1A => "CGBA (Circuit Group Blocking Ack)",
        0x1B => "CGUA (Circuit Group Unblocking Ack)",
        0x2C => "CPG (Call Progress)",
        0x2D => "USR (User-to-User)",
        0x2E => "UCIC (Unequipped Circuit)",
        0x2F => "CFN (Confusion)",
        0x31 => "OLM (Overload)",
        0x32 => "CRG (Charge Information)",
        0x36 => "NRM (Network Resource Management)",
        0x37 => "FAC (Facility)",
        0x38 => "UPT (User Part Test)",
        0x39 => "UPA (User Part Available)",
        0x3B => "IDR (Identification Request)",
        0x3C => "IRS (Identification Response)",
        0x3D => "SGM (Segmentation)",
        _ => return None,
    })
}

/// Dissect an ISUP message. ISUP rides inside M3UA (service indicator 5) rather
/// than on a port of its own, so it is reached from the M3UA dissector.
///
/// The message begins with a 2-byte circuit identification code — which
/// physical or logical trunk the call is on — followed by the message type.
pub fn dissect_isup(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 3 {
        format!("ISUP ({})", super::bytes(payload.len() as u64))
    } else {
        // The circuit identification code is little-endian, unlike most of SS7.
        let cic = u16::from_le_bytes([payload[0], payload[1]]) & 0x0FFF;
        match message_name(payload[2]) {
            Some(name) => format!("ISUP {name} — CIC {cic}"),
            None => format!("ISUP message 0x{:02x} — CIC {cic}", payload[2]),
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Isup,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_address_starts_a_call() {
        let r = dissect_isup(None, None, 2905, 2905, &[0x2A, 0x00, 0x01, 0x00]);
        assert_eq!(r.protocol, Protocol::Isup);
        assert_eq!(r.summary, "ISUP IAM (Initial Address) — CIC 42");
    }

    #[test]
    fn answer_and_release() {
        let r = dissect_isup(None, None, 2905, 2905, &[0x01, 0x00, 0x09]);
        assert_eq!(r.summary, "ISUP ANM (Answer) — CIC 1");
        let r = dissect_isup(None, None, 2905, 2905, &[0x01, 0x00, 0x0C]);
        assert_eq!(r.summary, "ISUP REL (Release) — CIC 1");
    }

    /// The circuit code is little-endian and only 12 bits wide; reading it as
    /// big-endian or a full 16 bits would report the wrong trunk.
    #[test]
    fn circuit_code_is_little_endian_and_masked() {
        let r = dissect_isup(None, None, 2905, 2905, &[0x34, 0x02, 0x01]);
        assert_eq!(r.summary, "ISUP IAM (Initial Address) — CIC 564");
        // The top four bits belong to the spare field and must be masked off.
        let r = dissect_isup(None, None, 2905, 2905, &[0x01, 0xF0, 0x09]);
        assert_eq!(r.summary, "ISUP ANM (Answer) — CIC 1");
    }

    #[test]
    fn unknown_type_reports_its_byte() {
        let r = dissect_isup(None, None, 2905, 2905, &[0x01, 0x00, 0x7E]);
        assert_eq!(r.summary, "ISUP message 0x7e — CIC 1");
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_isup(None, None, 2905, 2905, &[0x01, 0x00]);
        assert_eq!(r.summary, "ISUP (2 bytes)");
    }
}
