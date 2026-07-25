use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_openai_moderation_async(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "OpenAI Moderation Async (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("moderation") || raw.contains("/v1/moderations") {
            let end = raw.len().min(80);
            format!("OpenAI Moderation Async: {}", &raw[..end])
        } else if raw.contains("categories") || raw.contains("category_scores") {
            format!("OpenAI Moderation Async: {}", &raw[..raw.len().min(80)])
        } else {
            format!("OpenAI Moderation Async ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::OpenaiModerationAsync,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openai_moderation_async_request() {
        let buf = b"{\"input\":\"test text\",\"categories\":[\"hate\",\"violence\"]}";
        let r = dissect_openai_moderation_async(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::OpenaiModerationAsync);
        assert!(r.summary.contains("categories"));
    }

    #[test]
    fn test_openai_moderation_async_malformed() {
        let buf = b"short";
        let r = dissect_openai_moderation_async(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
