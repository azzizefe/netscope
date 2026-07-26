use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

fn extract_delta(payload: &[u8]) -> Option<String> {
    let raw = String::from_utf8_lossy(payload);
    let trimmed = raw.trim();
    if trimmed == "[DONE]" || trimmed == "data: [DONE]" {
        return None;
    }
    let json_str = trimmed
        .strip_prefix("data: ")
        .or_else(|| trimmed.strip_prefix("data:"))
        .map(|s| s.trim())
        .unwrap_or(trimmed);
    if json_str == "[DONE]" {
        return None;
    }
    let val: serde_json::Value = serde_json::from_str(json_str).ok()?;
    let token = val
        .get("choices")?
        .as_array()?
        .first()?
        .get("delta")?
        .get("content")?
        .as_str()?;
    if token.is_empty() { None } else { Some(token.to_string()) }
}

fn is_done(payload: &[u8]) -> bool {
    let raw = String::from_utf8_lossy(payload);
    let trimmed = raw.trim();
    trimmed == "[DONE]" || trimmed == "data: [DONE]"
}

pub fn dissect_openai_streaming_sse(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 6 {
        "OpenAI Streaming SSE (malformed)".into()
    } else if is_done(payload) {
        "OpenAI Streaming SSE: [DONE]".into()
    } else if let Some(token) = extract_delta(payload) {
        let preview = super::truncate(&token, 80);
        format!("OpenAI Streaming SSE: token:\"{}\"", preview)
    } else {
        let raw = String::from_utf8_lossy(payload);
        let preview = super::truncate(&raw, 60);
        format!("OpenAI Streaming SSE: {}", preview)
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
    fn test_openai_streaming_sse_done() {
        let buf = b"data: [DONE]\n\n";
        let r = dissect_openai_streaming_sse(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::OpenaiStreamingSse);
        assert!(r.summary.contains("[DONE]"));
    }

    #[test]
    fn test_openai_streaming_sse_malformed() {
        let buf = b"data:";
        let r = dissect_openai_streaming_sse(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }

    #[test]
    fn test_openai_streaming_sse_empty_delta() {
        let buf = b"data: {\"choices\":[{\"delta\":{}}]}";
        let r = dissect_openai_streaming_sse(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::OpenaiStreamingSse);
    }

    #[test]
    fn test_openai_streaming_sse_no_data_prefix() {
        let buf = b"{\"choices\":[{\"delta\":{\"content\":\"direct\"}}]}";
        let r = dissect_openai_streaming_sse(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::OpenaiStreamingSse);
        assert!(r.summary.contains("direct"));
    }
}
