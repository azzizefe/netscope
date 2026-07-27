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
        1298437 => "GlusterFS",
        100005 => "Mount",
        100021 => "NLM (lock manager)",
        100024 => "status",
        100227 => "NFS ACL",
        _ => "RPC",
    }
}

/// The call header after the transaction id and message type: RPC version,
/// program, program version, procedure.
struct Call {
    program: u32,
    /// Absent when the capture was snapped short of the full call header.
    detail: Option<(u32, u32)>,
}

fn be32(payload: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *payload.get(at)?,
        *payload.get(at + 1)?,
        *payload.get(at + 2)?,
        *payload.get(at + 3)?,
    ]))
}

/// Try to read a call or reply from an RPC message starting at `off`.
///
/// `msg_type` 0 is a CALL, which is the one that names what is being asked;
/// 1 is a REPLY, which carries only a status.
fn parse(payload: &[u8], off: usize) -> Option<(u32, Option<Call>)> {
    match be32(payload, off + 4)? {
        0 => Some((
            0,
            Some(Call {
                program: be32(payload, off + 12)?,
                // The version and procedure sit further in, and a short snap
                // length can cut them off. The program alone is still useful.
                detail: be32(payload, off + 16).zip(be32(payload, off + 20)),
            }),
        )),
        1 => Some((1, None)),
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
        // The program alone says little: whether a call is a LOOKUP or a WRITE
        // is the question worth answering, so hand the numbers on.
        Some((0, Some(call))) => {
            if call.program == 0x4000_0000 {
                let proc_num = call.detail.map(|(_, p)| p).unwrap_or(0);
                return super::nfs_callback::dissect_nfs_callback(src_ip, dst_ip, src_port, dst_port, proc_num, payload);
            }
            if let Some((protocol, summary)) = call.detail.and_then(|(version, procedure)| {
                super::nfs::describe(call.program, version, procedure)
            }) {
                return DissectedResult {
                    src_addr: src_ip,
                    dst_addr: dst_ip,
                    src_port: Some(src_port),
                    dst_port: Some(dst_port),
                    protocol,
                    summary,
                };
            }
            format!("{} call", program_name(call.program))
        }
        Some((1, _)) => "RPC reply".to_string(),
        _ => format!("ONC RPC ({})", super::bytes(payload.len() as u64)),
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

    /// The whole point of the hand-off: a full call header should name the
    /// operation, not merely the program.
    #[test]
    fn full_call_header_names_the_operation() {
        let mut p = vec![0x80, 0x00, 0x00, 0x64]; // record marker
        p.extend_from_slice(&1u32.to_be_bytes()); // xid
        p.extend_from_slice(&0u32.to_be_bytes()); // msg_type: CALL
        p.extend_from_slice(&2u32.to_be_bytes()); // rpcvers
        p.extend_from_slice(&100_003u32.to_be_bytes()); // program: NFS
        p.extend_from_slice(&3u32.to_be_bytes()); // version
        p.extend_from_slice(&7u32.to_be_bytes()); // procedure: WRITE
        let r = dissect_rpc(None, None, 40000, 2049, &p);
        assert_eq!(r.protocol, Protocol::Nfs);
        assert_eq!(r.summary, "NFS v3 WRITE");
    }

    /// A capture snapped before the procedure number should still report the
    /// program rather than giving up on the packet.
    #[test]
    fn short_snap_falls_back_to_the_program() {
        let mut p = vec![0x80, 0x00, 0x00, 0x64];
        p.extend_from_slice(&1u32.to_be_bytes());
        p.extend_from_slice(&0u32.to_be_bytes());
        p.extend_from_slice(&2u32.to_be_bytes());
        p.extend_from_slice(&100_003u32.to_be_bytes()); // program, then nothing
        let r = dissect_rpc(None, None, 40000, 2049, &p);
        assert_eq!(r.protocol, Protocol::Rpc);
        assert_eq!(r.summary, "NFS call");
    }

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
