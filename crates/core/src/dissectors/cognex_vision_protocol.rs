use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_cognex_vision_protocol(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Cognex Vision (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("Cognex") || raw.contains("InSight") || raw.contains("cognex") {
            let end = raw.len().min(80);
            format!("Cognex Vision: {}", &raw[..end])
        } else if raw.contains("image_data") || raw.contains("inspection_result") {
            format!("Cognex Vision: {}", &raw[..raw.len().min(80)])
        } else {
            format!("Cognex Vision ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::CognexVisionProtocol,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cognex_vision_inspection() {
        let buf = b"Cognex InSight:inspection_result:pass";
        let r = dissect_cognex_vision_protocol(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::CognexVisionProtocol);
        assert!(r.summary.contains("Cognex"));
    }

    #[test]
    fn test_cognex_vision_malformed() {
        let buf = b"short";
        let r = dissect_cognex_vision_protocol(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
