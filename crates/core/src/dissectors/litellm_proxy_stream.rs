use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_litellm_proxy_stream(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "LiteLLM Proxy Stream (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("litellm") && raw.contains("model") && raw.contains("messages") {
            let end = raw.len().min(80);
            format!("LiteLLM Proxy Stream: {}", &raw[..end])
        } else if raw.contains("x-litellm") || raw.contains("litellm_call_id") {
            let end = raw.len().min(80);
            format!("LiteLLM Proxy Stream: {}", &raw[..end])
        } else {
            format!("LiteLLM Proxy Stream ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::LitellmProxyStream,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_litellm_proxy_stream_sse() {
        let buf = b"data: {\"model\":\"gpt-4\",\"messages\":[{\"role\":\"user\"}],\"litellm_call_id\":\"abc123\"}";
        let r = dissect_litellm_proxy_stream(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::LitellmProxyStream);
        assert!(r.summary.contains("LiteLLM"));
    }

    #[test]
    fn test_litellm_proxy_stream_malformed() {
        let buf = b"short";
        let r = dissect_litellm_proxy_stream(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
