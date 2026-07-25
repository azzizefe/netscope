use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_iec_61850_mms(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "IEC 61850 MMS (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("MMS") || raw.contains("mms") || raw.contains("61850") {
            let end = raw.len().min(80);
            format!("IEC 61850 MMS: {}", &raw[..end])
        } else if raw.contains("confirmedRequest") || raw.contains("readVariable") {
            format!("IEC 61850 MMS: {}", &raw[..raw.len().min(80)])
        } else {
            format!("IEC 61850 MMS ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Iec61850Mms,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iec_61850_mms_request() {
        let buf = b"MMS:confirmedRequest:readVariable:LLN0";
        let r = dissect_iec_61850_mms(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::Iec61850Mms);
        assert!(r.summary.contains("MMS"));
    }

    #[test]
    fn test_iec_61850_mms_malformed() {
        let buf = b"short";
        let r = dissect_iec_61850_mms(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
