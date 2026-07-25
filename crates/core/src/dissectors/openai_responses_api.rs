use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_openai_responses_api(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "OpenAI Responses API (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("responses") && (raw.contains("stream") || raw.contains("output")) {
            let end = raw.len().min(80);
            format!("OpenAI Responses API: {}", &raw[..end])
        } else if raw.contains("data:") && raw.contains("type:") && raw.contains("response") {
            let end = raw.len().min(80);
            format!("OpenAI Responses API: {}", &raw[..end])
        } else {
            format!("OpenAI Responses API ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::OpenaiResponsesApi,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openai_responses_api_stream() {
        let buf = b"data: {\"type\":\"response\",\"output\":[{\"text\":\"hello\"}]}";
        let r = dissect_openai_responses_api(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::OpenaiResponsesApi);
        assert!(r.summary.contains("Responses API"));
    }

    #[test]
    fn test_openai_responses_api_malformed() {
        let buf = b"short";
        let r = dissect_openai_responses_api(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
