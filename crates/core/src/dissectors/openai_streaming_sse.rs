use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_openai_streaming_sse(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 6 {
        "OpenAI Streaming SSE (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.starts_with("data: ") {
            let trimmed = raw.trim_start_matches("data: ").trim();
            let preview = if trimmed.len() > 60 {
                format!("{}...", &trimmed[..60])
            } else {
                trimmed.to_string()
            };
            format!("OpenAI Streaming SSE: {}", preview)
        } else {
            let preview = if raw.len() > 60 {
                format!("{}...", &raw[..60])
            } else {
                raw.to_string()
            };
            format!("OpenAI Streaming SSE: {}", preview)
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::OpenaiStreamingSse,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openai_streaming_sse_data() {
        let buf = b"data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n";
        let r = dissect_openai_streaming_sse(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::OpenaiStreamingSse);
        assert!(r.summary.contains("Hello"));
    }

    #[test]
    fn test_openai_streaming_sse_malformed() {
        let buf = b"data:";
        let r = dissect_openai_streaming_sse(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
