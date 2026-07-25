use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_ocpp_2_1(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "OCPP 2.1 (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("OCPP") || raw.contains("ocpp") || raw.contains("ChargePoint") {
            let end = raw.len().min(80);
            format!("OCPP 2.1: {}", &raw[..end])
        } else if raw.contains("BootNotification") || raw.contains("Authorize") || raw.contains("Transaction") {
            format!("OCPP 2.1: {}", &raw[..raw.len().min(80)])
        } else {
            format!("OCPP 2.1 ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Ocpp21,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ocpp_2_1_boot() {
        let buf = b"OCPP:BootNotification:chargePointVendor=EVTec";
        let r = dissect_ocpp_2_1(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::Ocpp21);
        assert!(r.summary.contains("OCPP"));
    }

    #[test]
    fn test_ocpp_2_1_malformed() {
        let buf = b"short";
        let r = dissect_ocpp_2_1(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
