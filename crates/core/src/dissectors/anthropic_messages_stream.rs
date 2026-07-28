use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

fn extract_delta(payload: &[u8]) -> Option<String> {
    let raw = String::from_utf8_lossy(payload);
    let trimmed = raw.trim();
    let json_str = trimmed
        .strip_prefix("data: ")
        .or_else(|| trimmed.strip_prefix("data:"))
        .map(|s| s.trim())
        .unwrap_or(trimmed);
    let val: serde_json::Value = serde_json::from_str(json_str).ok()?;
    let event_type = val.get("type")?.as_str()?;
    if event_type != "content_block_delta" {
        return None;
    }
    let token = val.get("delta")?.get("text")?.as_str()?;
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

fn is_stop(payload: &[u8]) -> bool {
    let raw = String::from_utf8_lossy(payload);
    let trimmed = raw.trim();
    let json_str = trimmed
        .strip_prefix("data: ")
        .or_else(|| trimmed.strip_prefix("data:"))
        .map(|s| s.trim())
        .unwrap_or(trimmed);
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(json_str) {
        val.get("type").and_then(|t| t.as_str()) == Some("message_stop")
    } else {
        false
    }
}

pub fn dissect_anthropic_messages_stream(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 6 {
        "Anthropic Messages Stream (malformed)".into()
    } else if is_stop(payload) {
        "Anthropic Messages Stream: [message_stop]".into()
    } else if let Some(token) = extract_delta(payload) {
        let preview = super::truncate(&token, 80);
        format!("Anthropic Messages Stream: token:\"{}\"", preview)
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.starts_with("data:") {
            let preview = super::truncate(&raw, 60);
            format!("Anthropic Messages Stream: {}", preview)
        } else {
            format!("Anthropic Messages Stream {}B", payload.len())
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::AnthropicMessagesStream,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anthropic_messages_stream_delta() {
        let buf = b"data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"Hello\"}}\n\n";
        let r = dissect_anthropic_messages_stream(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::AnthropicMessagesStream);
        assert!(r.summary.contains("Hello"));
    }

    #[test]
    fn test_anthropic_messages_stream_stop() {
        let buf = b"data: {\"type\":\"message_stop\"}\n\n";
        let r = dissect_anthropic_messages_stream(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::AnthropicMessagesStream);
        assert!(r.summary.contains("message_stop"));
    }

    #[test]
    fn test_anthropic_messages_stream_start() {
        let buf = b"data: {\"type\":\"message_start\"}\n\n";
        let r = dissect_anthropic_messages_stream(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::AnthropicMessagesStream);
        assert!(r.summary.contains("message_start"));
    }

    #[test]
    fn test_anthropic_messages_stream_malformed() {
        let buf = b"data:";
        let r = dissect_anthropic_messages_stream(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
