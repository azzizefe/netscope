use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_iec_61850_goose(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "IEC 61850 GOOSE (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("GOOSE") || raw.contains("goose") || raw.contains("gocb") {
            let end = raw.len().min(80);
            format!("IEC 61850 GOOSE: {}", &raw[..end])
        } else if raw.contains("stNum") || raw.contains("sqNum") || raw.contains("dataSet") {
            format!("IEC 61850 GOOSE: {}", &raw[..raw.len().min(80)])
        } else {
            format!("IEC 61850 GOOSE ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Iec61850Goose,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iec_61850_goose_message() {
        let buf = b"GOOSE:gocb:stNum=1:sqNum=42:dataSet=DS_LLN0";
        let r = dissect_iec_61850_goose(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::Iec61850Goose);
        assert!(r.summary.contains("GOOSE"));
    }

    #[test]
    fn test_iec_61850_goose_malformed() {
        let buf = b"short";
        let r = dissect_iec_61850_goose(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
