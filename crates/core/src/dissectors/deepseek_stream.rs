use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

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
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

fn is_done(payload: &[u8]) -> bool {
    let raw = String::from_utf8_lossy(payload);
    let trimmed = raw.trim();
    trimmed == "[DONE]" || trimmed == "data: [DONE]"
}

pub fn dissect_deepseek_stream(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "DeepSeek Stream (malformed)".into()
    } else if is_done(payload) {
        "DeepSeek Stream: [DONE]".into()
    } else if let Some(token) = extract_delta(payload) {
        let preview = super::truncate(&token, 80);
        format!("DeepSeek Stream: token:\"{}\"", preview)
    } else {
        let raw = String::from_utf8_lossy(payload);
        let preview = super::truncate(&raw, 60);
        format!("DeepSeek Stream: {}", preview)
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::DeepseekStream,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deepseek_stream_delta() {
        let buf = b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n";
        let r = dissect_deepseek_stream(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::DeepseekStream);
        assert!(r.summary.contains("hi"));
    }

    #[test]
    fn test_deepseek_stream_done() {
        let buf = b"data: [DONE]\n\n";
        let r = dissect_deepseek_stream(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::DeepseekStream);
        assert!(r.summary.contains("[DONE]"));
    }

    #[test]
    fn test_deepseek_stream_malformed() {
        let buf = b"short";
        let r = dissect_deepseek_stream(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
