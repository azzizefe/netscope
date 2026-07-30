// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an SMP PDU (Bluetooth L2CAP CID 0x0006) — the Security Manager
/// Protocol, which pairs and bonds two BLE devices and negotiates how the link
/// is protected. Pairing is where BLE's security is won or lost, so the
/// exchange is worth reading.
pub fn dissect_smp(body: &[u8]) -> DissectedResult {
    let summary = match body.first() {
        Some(&code) => {
            let name = match code {
                0x01 => "Pairing Request",
                0x02 => "Pairing Response",
                0x03 => "Pairing Confirm",
                0x04 => "Pairing Random",
                0x05 => "Pairing Failed",
                0x06 => "Encryption Information",
                0x08 => "Identity Information",
                0x0A => "Signing Information",
                0x0B => "Security Request",
                0x0C => "Pairing Public Key",
                0x0D => "Pairing DHKey Check",
                _ => "PDU",
            };
            format!("SMP {name} (BLE pairing)")
        }
        None => "SMP (empty)".to_string(),
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Smp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_request() {
        let r = dissect_smp(&[0x01, 0x03, 0x00, 0x01]);
        assert_eq!(r.protocol, Protocol::Smp);
        assert!(r.summary.contains("Pairing Request"), "{}", r.summary);
    }
}
