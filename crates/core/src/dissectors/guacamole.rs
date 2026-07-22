// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect Apache Guacamole Protocol (TCP 4822).
pub fn dissect_guacamole(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"6.select,") || payload.starts_with(b"4.args,") || payload.starts_with(b"7.connect,") {
        "Guacamole instruction".to_string()
    } else {
        format!("Guacamole Protocol ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Guacamole,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guacamole_test() {
        let r = dissect_guacamole(None, None, 40000, 4822, b"6.select,3.vnc;");
        assert_eq!(r.protocol, Protocol::Guacamole);
        assert_eq!(r.summary, "Guacamole instruction");
    }
}
