// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an MSRP message (TCP 2855) — the Message Session Relay Protocol that
/// carries instant messages and file transfers in SIP/IMS sessions. Each frame
/// is `MSRP <transaction-id> <method-or-status>`.
pub fn dissect_msrp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let line = super::first_text_line(payload);
    let summary = if line.starts_with("MSRP ") {
        // "MSRP <tid> SEND" (request) or "MSRP <tid> 200 OK" (response).
        let what = line.split_whitespace().nth(2).unwrap_or("");
        format!("MSRP {what}")
    } else {
        format!("MSRP data ({})", super::bytes(payload.len() as u64))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Msrp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send() {
        let r = dissect_msrp(None, None, 40000, 2855, b"MSRP d93kswow SEND\r\n");
        assert_eq!(r.protocol, Protocol::Msrp);
        assert_eq!(r.summary, "MSRP SEND");
    }
}
