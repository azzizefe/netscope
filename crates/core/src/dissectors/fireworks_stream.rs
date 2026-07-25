use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_fireworks_stream(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Fireworks Stream (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("fireworks") && (raw.contains("stream") || raw.contains("inference")) {
            let end = raw.len().min(80);
            format!("Fireworks Stream: {}", &raw[..end])
        } else if raw.contains("choices") && raw.contains("delta") && raw.contains("x-request-id") {
            let end = raw.len().min(80);
            format!("Fireworks Stream: {}", &raw[..end])
        } else {
            format!("Fireworks Stream ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::FireworksStream,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fireworks_stream_sse() {
        let buf = b"fireworks:stream:data:{\"choices\":[{\"delta\":{\"content\":\"fast\"}}]}";
        let r = dissect_fireworks_stream(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::FireworksStream);
        assert!(r.summary.contains("Fireworks Stream"));
    }

    #[test]
    fn test_fireworks_stream_malformed() {
        let buf = b"short";
        let r = dissect_fireworks_stream(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
