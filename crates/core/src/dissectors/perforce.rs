// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect Perforce (P4) version control protocol messages (TCP 1666).
pub fn dissect_perforce(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if let Ok(s) = std::str::from_utf8(payload) {
        if s.contains("func=") || s.contains("cmp=") {
            if let Some(pos) = s.find("func=") {
                let func_str = s[pos + 5..].split('\0').next().unwrap_or("unknown");
                format!("Perforce (P4) func={func_str}")
            } else {
                "Perforce (P4) Command".to_string()
            }
        } else {
            format!("Perforce (P4) ({})", super::bytes(payload.len() as u64))
        }
    } else {
        format!("Perforce (P4) ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Perforce,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_perforce_func() {
        let payload = b"cmp=0\0func=user-sync\0client=myclient\0";
        let r = dissect_perforce(None, None, 40000, 1666, payload);
        assert_eq!(r.protocol, Protocol::Perforce);
        assert_eq!(r.summary, "Perforce (P4) func=user-sync");
    }
}
