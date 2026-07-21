// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an IEC 60870-5-104 message (TCP 2404) — SCADA telecontrol for power
/// grids. Each APCI starts with 0x68; the first control octet's low bits select
/// the frame format (I / S / U).
pub fn dissect_iec104(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 3 && payload[0] == 0x68 {
        let ctrl = payload[2];
        if ctrl & 0x01 == 0 {
            // An I-frame carries an ASDU, which is where the telecontrol
            // content is — what was measured, or which breaker was commanded
            // and whether the substation accepted. The APCI is six bytes.
            match payload.get(6..).and_then(super::iec_asdu::parse) {
                Some(asdu) => format!("IEC 104 {}", super::iec_asdu::describe(&asdu)),
                None => "IEC 60870-5-104 I-frame (information)".to_string(),
            }
        } else if ctrl & 0x03 == 0x01 {
            "IEC 60870-5-104 S-frame (supervisory)".to_string()
        } else {
            "IEC 60870-5-104 U-frame (control)".to_string()
        }
    } else {
        format!("IEC-104 ({})", super::bytes(payload.len() as u64))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Iec104,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An I-frame now reports the telecontrol content rather than just its
    /// frame format — including a refused command, which is the whole point.
    #[test]
    fn an_information_frame_reports_the_asdu_inside_it() {
        // APCI: start, length, four control octets with the I-frame bit clear.
        let mut p = vec![0x68, 0x0E, 0x00, 0x00, 0x00, 0x00];
        // ASDU: single command, one object, activation confirmed + negative.
        p.extend_from_slice(&[45, 1, 7 | 0x40, 0x00, 0x0C, 0x00]);
        let r = dissect_iec104(None, None, 2404, 40000, &p);
        assert_eq!(r.protocol, Protocol::Iec104);
        assert_eq!(
            r.summary,
            "IEC 104 station 12 — single command REFUSED (activation confirmed, negative)"
        );
    }

    /// A frame too short to hold an ASDU falls back to naming the format
    /// rather than reading whatever follows as one.
    #[test]
    fn an_information_frame_without_an_asdu_names_the_format() {
        let p = vec![0x68, 0x04, 0x00, 0x00, 0x00, 0x00];
        let r = dissect_iec104(None, None, 2404, 40000, &p);
        assert_eq!(r.summary, "IEC 60870-5-104 I-frame (information)");
    }

    #[test]
    fn info_frame() {
        // Start 0x68, length, control octet 0x00 (I-frame).
        let r = dissect_iec104(
            None,
            None,
            40000,
            2404,
            &[0x68, 0x04, 0x00, 0x00, 0x00, 0x00],
        );
        assert_eq!(r.protocol, Protocol::Iec104);
        assert!(r.summary.contains("I-frame"), "{}", r.summary);
    }
}
