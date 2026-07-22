// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect TR-069 / CWMP (CPE WAN Management Protocol, TCP 7547 / 8080 SOAP).
pub fn dissect_cwmp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if let Ok(s) = std::str::from_utf8(payload) {
        if s.contains("cwmp:Inform") {
            "TR-069 CWMP Inform Request".into()
        } else if s.contains("cwmp:GetParameterValues") {
            "TR-069 CWMP GetParameterValues".into()
        } else if s.contains("cwmp:SetParameterValues") {
            "TR-069 CWMP SetParameterValues".into()
        } else if s.contains("cwmp:Download") {
            "TR-069 CWMP Download Request".into()
        } else if s.contains("cwmp:") {
            "TR-069 CWMP Message".into()
        } else {
            format!("TR-069 CWMP ({})", super::bytes(payload.len() as u64))
        }
    } else {
        format!("TR-069 CWMP ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Cwmp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cwmp_inform() {
        let payload = b"POST /cwmp HTTP/1.1\r\n\r\n<cwmp:Inform><Device>Router</Device></cwmp:Inform>";
        let r = dissect_cwmp(None, None, 40000, 7547, payload);
        assert_eq!(r.protocol, Protocol::Cwmp);
        assert_eq!(r.summary, "TR-069 CWMP Inform Request");
    }
}
