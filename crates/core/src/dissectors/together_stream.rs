use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_together_stream(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Together AI Stream (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("together") && (raw.contains("stream") || raw.contains("inference")) {
            let end = raw.len().min(80);
            format!("Together AI Stream: {}", &raw[..end])
        } else if raw.contains("choices") && raw.contains("delta") && raw.contains("together") {
            let end = raw.len().min(80);
            format!("Together AI Stream: {}", &raw[..end])
        } else {
            format!("Together AI Stream ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::TogetherStream,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_together_ai_stream_sse() {
        let buf = b"together:stream:data:{\"choices\":[{\"delta\":{\"content\":\"world\"}}]}";
        let r = dissect_together_stream(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::TogetherStream);
        assert!(r.summary.contains("Together AI"));
    }

    #[test]
    fn test_together_ai_stream_malformed() {
        let buf = b"short";
        let r = dissect_together_stream(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
