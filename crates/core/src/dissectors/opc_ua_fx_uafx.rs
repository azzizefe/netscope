use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_opc_ua_fx_uafx(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "OPC UA FX UAFX (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("UAFX") || raw.contains("uafx") || raw.contains("OPC UA FX") {
            let end = raw.len().min(80);
            format!("OPC UA FX UAFX: {}", &raw[..end])
        } else if raw.contains("FieldExchange") || raw.contains("field_xchg") {
            let end = raw.len().min(80);
            format!("OPC UA FX UAFX: {}", &raw[..end])
        } else {
            format!("OPC UA FX UAFX ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::OpcUaFxUafx,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opc_ua_fx_uafx_frame() {
        let buf = b"UAFX:OPCUA:FieldExchange:tsn:cycle=500us";
        let r = dissect_opc_ua_fx_uafx(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::OpcUaFxUafx);
        assert!(r.summary.contains("UAFX"));
    }

    #[test]
    fn test_opc_ua_fx_uafx_malformed() {
        let buf = b"short";
        let r = dissect_opc_ua_fx_uafx(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
