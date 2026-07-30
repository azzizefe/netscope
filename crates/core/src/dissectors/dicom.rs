// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a DICOM message (TCP 104/11112) — the protocol medical imaging
/// devices (scanners, PACS) use to exchange studies. Byte 0 is the PDU type
/// (DICOM PS3.8).
pub fn dissect_dicom(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.first() {
        Some(&t) => {
            let name = match t {
                0x01 => "A-ASSOCIATE-RQ",
                0x02 => "A-ASSOCIATE-AC",
                0x03 => "A-ASSOCIATE-RJ",
                0x04 => "P-DATA-TF (image data)",
                0x05 => "A-RELEASE-RQ",
                0x06 => "A-RELEASE-RP",
                0x07 => "A-ABORT",
                _ => "PDU",
            };
            format!("DICOM {name}")
        }
        None => "DICOM (empty)".to_string(),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Dicom,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn associate_request() {
        let r = dissect_dicom(None, None, 40000, 104, &[0x01, 0x00, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::Dicom);
        assert_eq!(r.summary, "DICOM A-ASSOCIATE-RQ");
    }
}
