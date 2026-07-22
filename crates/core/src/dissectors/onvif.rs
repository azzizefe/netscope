// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect ONVIF IP camera SOAP management traffic (TCP 80/8080/8000).
pub fn dissect_onvif(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if let Ok(s) = std::str::from_utf8(payload) {
        if s.contains("GetProfiles") {
            "ONVIF GetProfiles Request".into()
        } else if s.contains("GetStreamUri") {
            "ONVIF GetStreamUri Request".into()
        } else if s.contains("GetDeviceInformation") {
            "ONVIF GetDeviceInformation Request".into()
        } else if s.contains("onvif.org") {
            "ONVIF SOAP Message".into()
        } else {
            format!("ONVIF ({})", super::bytes(payload.len() as u64))
        }
    } else {
        format!("ONVIF ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Onvif,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_onvif_get_profiles() {
        let payload = b"POST /onvif/device_service HTTP/1.1\r\n\r\n<s:Envelope xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\"><tds:GetProfiles/></s:Envelope>";
        let r = dissect_onvif(None, None, 40000, 80, payload);
        assert_eq!(r.protocol, Protocol::Onvif);
        assert_eq!(r.summary, "ONVIF GetProfiles Request");
    }
}
