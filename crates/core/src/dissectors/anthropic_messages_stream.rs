use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_anthropic_messages_stream(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 6 {
        "Anthropic Messages Stream (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.starts_with("data:") || raw.contains("\"type\":\"content_block_delta\"") {
            let end = raw.len().min(80);
            format!("Anthropic Messages Stream: {}", &raw[..end])
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
        assert!(r.summary.contains("content_block_delta"));
    }

    #[test]
    fn test_anthropic_messages_stream_malformed() {
        let buf = b"data:";
        let r = dissect_anthropic_messages_stream(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
