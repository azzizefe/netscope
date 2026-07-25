use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_seeed_grove_vision_ai(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Seeed Grove Vision AI (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("Grove") || raw.contains("seeed") || raw.contains("vision_ai") {
            let end = raw.len().min(80);
            format!("Seeed Grove Vision AI: {}", &raw[..end])
        } else if raw.contains("object_detection") || raw.contains("classification") {
            format!("Seeed Grove Vision AI: {}", &raw[..raw.len().min(80)])
        } else {
            format!("Seeed Grove Vision AI ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SeeedGroveVisionAi,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seeed_grove_vision_ai_detection() {
        let buf = b"Grove vision_ai:object_detection:person";
        let r = dissect_seeed_grove_vision_ai(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::SeeedGroveVisionAi);
        assert!(r.summary.contains("Grove"));
    }

    #[test]
    fn test_seeed_grove_vision_ai_malformed() {
        let buf = b"short";
        let r = dissect_seeed_grove_vision_ai(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
