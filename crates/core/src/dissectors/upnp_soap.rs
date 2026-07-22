// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect UPnP SOAP Device Control (TCP 49152).
pub fn dissect_upnp_soap(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"POST /") && payload.contains(&b'S') && payload.contains(&b'O') {
        "UPnP SOAP control action".to_string()
    } else {
        format!("UPnP SOAP ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::UpnpSoap,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upnp_soap_test() {
        let r = dissect_upnp_soap(None, None, 40000, 49152, b"POST /ctl/IPConn HTTP/1.1\r\nSOAPACTION: urn:schemas-upnp-org:service:WANIPConnection:1#GetStatus\r\n");
        assert_eq!(r.protocol, Protocol::UpnpSoap);
        assert_eq!(r.summary, "UPnP SOAP control action");
    }
}
