// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Name a well-known ONC RPC program number (used by NFS and friends).
fn program_name(prog: u32) -> &'static str {
    match prog {
        100000 => "Portmap",
        100003 => "NFS",
        100005 => "Mount",
        100021 => "NLM (lock manager)",
        100024 => "status",
        100227 => "NFS ACL",
        _ => "RPC",
    }
}

/// Try to read (msg_type, program) from an RPC message starting at `off`.
/// `msg_type` 0 is a CALL (program follows), 1 is a REPLY.
fn parse(payload: &[u8], off: usize) -> Option<(u32, u32)> {
    let mt = u32::from_be_bytes([
        *payload.get(off + 4)?,
        *payload.get(off + 5)?,
        *payload.get(off + 6)?,
        *payload.get(off + 7)?,
    ]);
    match mt {
        0 => {
            let prog = u32::from_be_bytes([
                *payload.get(off + 12)?,
                *payload.get(off + 13)?,
                *payload.get(off + 14)?,
                *payload.get(off + 15)?,
            ]);
            Some((0, prog))
        }
        1 => Some((1, 0)),
        _ => None,
    }
}

/// Dissect an ONC RPC message (Portmap 111, NFS 2049, …). Over TCP the message
/// is prefixed by a 4-byte record marker, so we try both offsets (RFC 5531).
pub fn dissect_rpc(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    // TCP prefixes a record marker; UDP does not — try offset 4 then 0.
    let parsed = parse(payload, 4).or_else(|| parse(payload, 0));
    let summary = match parsed {
        Some((0, prog)) => format!("{} call", program_name(prog)),
        Some((1, _)) => "RPC reply".to_string(),
        _ => format!("ONC RPC ({} bytes)", payload.len()),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Rpc,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nfs_call_over_tcp() {
        // 4-byte record marker, then xid(4), msg_type 0 (CALL), rpcvers(4),
        // program 100003 (NFS).
        let mut p = vec![0x80, 0x00, 0x00, 0x64]; // record marker
        p.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]); // xid
        p.extend_from_slice(&0u32.to_be_bytes()); // msg_type CALL
        p.extend_from_slice(&2u32.to_be_bytes()); // rpcvers
        p.extend_from_slice(&100003u32.to_be_bytes()); // program NFS
        let r = dissect_rpc(None, None, 40000, 2049, &p);
        assert_eq!(r.protocol, Protocol::Rpc);
        assert_eq!(r.summary, "NFS call");
    }
}
