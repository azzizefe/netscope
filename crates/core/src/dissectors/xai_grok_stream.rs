use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_xai_grok_stream(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "xAI Grok Stream (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("grok") && (raw.contains("stream") || raw.contains("xai")) {
            let end = raw.len().min(80);
            format!("xAI Grok Stream: {}", &raw[..end])
        } else if raw.contains("choices") && raw.contains("delta") && raw.contains("grok") {
            let end = raw.len().min(80);
            format!("xAI Grok Stream: {}", &raw[..end])
        } else {
            format!("xAI Grok Stream ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::XaiGrokStream,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xai_grok_stream_sse() {
        let buf = b"grok:stream:data:{\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}";
        let r = dissect_xai_grok_stream(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::XaiGrokStream);
        assert!(r.summary.contains("Grok Stream"));
    }

    #[test]
    fn test_xai_grok_stream_malformed() {
        let buf = b"short";
        let r = dissect_xai_grok_stream(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
