// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an iSCSI PDU (TCP 3260) — SCSI storage commands over TCP, so disks
/// live on the network. The low 6 bits of byte 0 are the opcode (RFC 7143).
pub fn dissect_iscsi(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.first() {
        Some(&b) => {
            let name = match b & 0x3F {
                0x00 => "NOP-Out",
                0x01 => "SCSI Command",
                0x03 => "Login Request",
                0x04 => "Text Request",
                0x05 => "Data-Out",
                0x06 => "Logout Request",
                0x20 => "NOP-In",
                0x21 => "SCSI Response",
                0x23 => "Login Response",
                0x25 => "Data-In",
                _ => "PDU",
            };
            format!("iSCSI {name}")
        }
        None => "iSCSI (empty)".to_string(),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Iscsi,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_request() {
        let r = dissect_iscsi(None, None, 40000, 3260, &[0x03, 0x00, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::Iscsi);
        assert_eq!(r.summary, "iSCSI Login Request");
    }
}
