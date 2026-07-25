use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_cohere_stream_v2(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Cohere Stream v2 (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("cohere") && (raw.contains("stream") || raw.contains("generation")) {
            let end = raw.len().min(80);
            format!("Cohere Stream v2: {}", &raw[..end])
        } else if raw.contains("text:") && raw.contains("finish_reason") {
            let end = raw.len().min(80);
            format!("Cohere Stream v2: {}", &raw[..end])
        } else {
            format!("Cohere Stream v2 ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::CohereStreamV2,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cohere_stream_v2_event() {
        let buf = b"cohere:stream:text:hello:finish_reason=complete";
        let r = dissect_cohere_stream_v2(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::CohereStreamV2);
        assert!(r.summary.contains("Cohere Stream"));
    }

    #[test]
    fn test_cohere_stream_v2_malformed() {
        let buf = b"short";
        let r = dissect_cohere_stream_v2(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
