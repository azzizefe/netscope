use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_openai_chat_stream(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "OpenAI Chat Stream (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("data:") && (raw.contains("[DONE]") || raw.contains("chat.completion")) {
            let end = raw.len().min(80);
            format!("OpenAI Chat Stream: {}", &raw[..end])
        } else if raw.contains("choices") && raw.contains("delta") && raw.contains("finish_reason") {
            let end = raw.len().min(80);
            format!("OpenAI Chat Stream: {}", &raw[..end])
        } else {
            format!("OpenAI Chat Stream ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::OpenaiChatStream,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openai_chat_stream_sse() {
        let buf = b"data: {\"choices\":[{\"delta\":{\"content\":\"hello\"},\"finish_reason\":null}]}";
        let r = dissect_openai_chat_stream(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::OpenaiChatStream);
        assert!(r.summary.contains("Chat Stream"));
    }

    #[test]
    fn test_openai_chat_stream_malformed() {
        let buf = b"short";
        let r = dissect_openai_chat_stream(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
