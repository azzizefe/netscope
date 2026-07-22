// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a pNFS (Parallel NFS — RFC 5661 layout operations) message.
pub fn dissect_pnfs(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    op: u32,
    payload: &[u8],
) -> DissectedResult {
    let op_name = match op {
        45 => "LAYOUTGET",
        46 => "LAYOUTCOMMIT",
        47 => "LAYOUTRETURN",
        48 => "GETDEVICEINFO",
        49 => "GETDEVICELIST",
        50 => "BACKCHANNEL_CTL",
        51 => "BIND_CONN_TO_SESSION",
        _ => "pNFS Operation",
    };

    let summary = format!("pNFS {op_name} ({})", super::bytes(payload.len() as u64));

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::PNfs,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pnfs_layoutget() {
        let r = dissect_pnfs(None, None, 2049, 2049, 45, &[0x00, 0x01]);
        assert_eq!(r.protocol, Protocol::PNfs);
        assert!(r.summary.contains("pNFS LAYOUTGET"));
    }
}
