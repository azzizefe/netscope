// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect TANGO Controls System CORBA IIOP Protocol (TCP 10000).
pub fn dissect_tango_controls(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"GIOP") {
        "TANGO Controls GIOP/IIOP frame".to_string()
    } else {
        format!("TANGO Controls ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::TangoControls,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tango_test() {
        let r = dissect_tango_controls(None, None, 40000, 10000, b"GIOP\x01\x02\x00\x00\x00\x00\x00\x10");
        assert_eq!(r.protocol, Protocol::TangoControls);
        assert_eq!(r.summary, "TANGO Controls GIOP/IIOP frame");
    }
}
