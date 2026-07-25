use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_mistral_chat_stream(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Mistral Chat Stream (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("mistral") && (raw.contains("stream") || raw.contains("chat")) {
            let end = raw.len().min(80);
            format!("Mistral Chat Stream: {}", &raw[..end])
        } else if raw.contains("choices") && raw.contains("delta") && raw.contains("mistral") {
            let end = raw.len().min(80);
            format!("Mistral Chat Stream: {}", &raw[..end])
        } else {
            format!("Mistral Chat Stream ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::MistralChatStream,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mistral_chat_stream_sse() {
        let buf = b"mistral:data:{\"choices\":[{\"delta\":{\"content\":\"bonjour\"}}]}";
        let r = dissect_mistral_chat_stream(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::MistralChatStream);
        assert!(r.summary.contains("Mistral Chat"));
    }

    #[test]
    fn test_mistral_chat_stream_malformed() {
        let buf = b"short";
        let r = dissect_mistral_chat_stream(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
