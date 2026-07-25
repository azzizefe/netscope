use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_anthropic_stream_evt(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Anthropic Stream Event (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("event:") && (raw.contains("message_start") || raw.contains("message_delta") || raw.contains("message_stop")) {
            let end = raw.len().min(80);
            format!("Anthropic Stream: {}", &raw[..end])
        } else if raw.contains("content_block") && (raw.contains("delta") || raw.contains("stop")) {
            let end = raw.len().min(80);
            format!("Anthropic Stream: {}", &raw[..end])
        } else {
            format!("Anthropic Stream ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::AnthropicStreamEvt,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anthropic_stream_event() {
        let buf = b"event: message_delta\ndata: {\"delta\":{\"text\":\"world\"}}";
        let r = dissect_anthropic_stream_evt(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::AnthropicStreamEvt);
        assert!(r.summary.contains("Anthropic Stream"));
    }

    #[test]
    fn test_anthropic_stream_malformed() {
        let buf = b"short";
        let r = dissect_anthropic_stream_evt(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
