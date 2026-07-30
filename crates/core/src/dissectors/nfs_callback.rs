// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an NFSv4 Callback (RFC 3530 / RFC 5661 backchannel) message.
pub fn dissect_nfs_callback(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    proc_num: u32,
    payload: &[u8],
) -> DissectedResult {
    let proc_name = match proc_num {
        0 => "CB_NULL",
        1 => "CB_COMPOUND",
        _ => "Callback Procedure",
    };

    let summary = if payload.len() >= 4 {
        let cb_op = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let op_str = match cb_op {
            3 => "CB_GETATTR",
            4 => "CB_RECALL",
            5 => "CB_LAYOUTRECALL",
            6 => "CB_NOTIFY",
            7 => "CB_PUSH_DELEG",
            8 => "CB_RECALL_ANY",
            11 => "CB_SEQUENCE",
            _ => "CB Operation",
        };
        format!("NFSv4 Callback {proc_name} · {op_str}")
    } else {
        format!("NFSv4 Callback {proc_name}")
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::NfsCb,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nfs_cb_recall() {
        let payload = vec![0x00, 0x00, 0x00, 0x04]; // CB_RECALL
        let r = dissect_nfs_callback(None, None, 2049, 2049, 1, &payload);
        assert_eq!(r.protocol, Protocol::NfsCb);
        assert_eq!(r.summary, "NFSv4 Callback CB_COMPOUND · CB_RECALL");
    }

    #[test]
    fn test_nfs_cb_null() {
        let r = dissect_nfs_callback(None, None, 2049, 2049, 0, &[]);
        assert_eq!(r.protocol, Protocol::NfsCb);
        assert_eq!(r.summary, "NFSv4 Callback CB_NULL");
    }
}
