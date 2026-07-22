// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect EtherCAT CoE/FoE/SoE Mailbox Protocol (UDP 34980).
pub fn dissect_ethercat_mailbox(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 6 {
        let length = u16::from_le_bytes([payload[0], payload[1]]);
        let mb_type = payload[5] & 0x0F;
        format!("EtherCAT Mailbox type {} (len {})", mb_type, length)
    } else {
        format!("EtherCAT Mailbox ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::EthercatMailbox,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ethercat_mailbox_test() {
        let r = dissect_ethercat_mailbox(None, None, 40000, 34980, b"\x08\x00\x00\x00\x00\x03\x00\x00");
        assert_eq!(r.protocol, Protocol::EthercatMailbox);
        assert!(r.summary.contains("EtherCAT Mailbox type"));
    }
}
