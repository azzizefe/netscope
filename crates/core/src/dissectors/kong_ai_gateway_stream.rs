use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_kong_ai_gateway_stream(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Kong AI Gateway Stream (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("kong") && raw.contains("ai-gateway") && raw.contains("llm") {
            let end = raw.len().min(80);
            format!("Kong AI Gateway Stream: {}", &raw[..end])
        } else if raw.contains("x-kong-ai") || raw.contains("kong_llm") {
            let end = raw.len().min(80);
            format!("Kong AI Gateway Stream: {}", &raw[..end])
        } else {
            format!("Kong AI Gateway Stream ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::KongAiGatewayStream,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kong_ai_gateway_stream_llm() {
        let buf = b"data: {\"kong\":true,\"ai-gateway\":{\"llm\":{\"model\":\"gpt4\"}},\"x-kong-ai\":\"1\"}";
        let r = dissect_kong_ai_gateway_stream(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::KongAiGatewayStream);
        assert!(r.summary.contains("Kong AI"));
    }

    #[test]
    fn test_kong_ai_gateway_stream_malformed() {
        let buf = b"bad";
        let r = dissect_kong_ai_gateway_stream(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
