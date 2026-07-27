// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! ISDN User Part (ISUP) dissector.
//!
//! ISUP carries call-setup and teardown signalling within SS7 networks. It
//! rides inside MTP3 and is the layer that actually places, answers and
//! tears down a telephone call.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

pub fn dissect_isup(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    if payload.len() < 2 {
        return DissectedResult {
            src_addr: src_ip,
            dst_addr: dst_ip,
            src_port: Some(src_port),
            dst_port: Some(dst_port),
            protocol: Protocol::Isup,
            summary: "ISUP — truncated".into(),
        };
    }
    // CIC is in the first two bytes (lower 12 bits in some variants).
    let cic = u16::from_be_bytes([payload[0], payload[1]]) & 0x0FFF;
    let msg_type = *payload.get(2).unwrap_or(&0);
    let name = isup_message_name(msg_type);
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Isup,
        summary: format!("ISUP {name} (CIC {cic})"),
    }
}

fn isup_message_name(code: u8) -> &'static str {
    match code {
        1 => "IAM",
        2 => "SAM",
        3 => "INR",
        4 => "COX",
        5 => "EXM",
        6 => "ACM",
        7 => "CON",
        8 => "FOT",
        9 => "ANM",
        10 => "CPG",
        11 => "USIS",
        12 => "UBL",
        13 => "BLO",
        14 => "BLA",
        15 => "UBA",
        16 => "RES",
        17 => "RESET",
        18 => "UBLK",
        19 => "UCIC",
        20 => "CCR",
        21 => "RSC",
        22 => "GRS",
        23 => "CGB",
        24 => "CGU",
        25 => "CGQA",
        26 => "CQR",
        27 => "GRA",
        28 => "SGM",
        29 => "CFN",
        30 => "LPA",
        31 => "OPR",
        32 => "IDR",
        33 => "IRS",
        34 => "LOP",
        35 => "PAM",
        36 => "PRI",
        37 => "FAA",
        38 => "FRJ",
        39 => "FAR",
        40 => "RLC",
        41 => "REL",
        _ => "unknown ISUP message",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_isup_iam() {
        let payload = [0x00, 0x01, 0x01]; // CIC 1, IAM
        let r = dissect_isup(None, None, 0, 0, &payload);
        assert!(r.summary.contains("IAM"));
        assert!(r.summary.contains("CIC 1"));
    }

    #[test]
    fn test_isup_truncated() {
        let r = dissect_isup(None, None, 0, 0, &[0x00]);
        assert!(r.summary.contains("truncated"));
    }
}
