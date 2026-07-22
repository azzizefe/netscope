// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Check if payload looks like an NVMe over Fabrics capsule/PDU.
pub(crate) fn looks_like_nvmeof(payload: &[u8]) -> bool {
    if payload.len() < 4 {
        return false;
    }
    matches!(payload[0], 0x00..=0x07 | 0x09)
}

/// Dissect an NVMe/TCP PDU (TCP 4420) or NVMe-oF RDMA capsule — NVMe over Fabrics,
/// which puts modern flash storage on the network with far less overhead than iSCSI. Byte 0 is
/// the PDU/Capsule type.
pub fn dissect_nvmeof(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.first() {
        Some(&t) => {
            let name = match t {
                0x00 => "Initialize Connection Request",
                0x01 => "Initialize Connection Response",
                0x02 => "Host to Controller Terminate",
                0x03 => "Controller to Host Terminate",
                0x04 => "Command Capsule",
                0x05 => "Response Capsule",
                0x06 => "Host to Controller Data",
                0x07 => "Controller to Host Data",
                0x09 => "Ready to Transfer",
                _ => "PDU",
            };
            format!("NVMe/TCP {name}")
        }
        None => format!("NVMe/TCP ({})", super::bytes(payload.len() as u64)),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::NvmeOf,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_capsule() {
        let r = dissect_nvmeof(None, None, 40000, 4420, &[0x04, 0x00, 0x48, 0x00]);
        assert_eq!(r.protocol, Protocol::NvmeOf);
        assert_eq!(r.summary, "NVMe/TCP Command Capsule");
    }
}
