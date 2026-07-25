use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_cloudflare_ai_gateway(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Cloudflare AI Gateway (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("cloudflare") && raw.contains("ai-gateway") && raw.contains("model") {
            let end = raw.len().min(80);
            format!("Cloudflare AI Gateway: {}", &raw[..end])
        } else if raw.contains("cf-ai-gateway") || raw.contains("workers-ai") {
            let end = raw.len().min(80);
            format!("Cloudflare AI Gateway: {}", &raw[..end])
        } else {
            format!("Cloudflare AI Gateway ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::CloudflareAiGateway,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloudflare_ai_gateway_stream() {
        let buf = b"data: {\"cloudflare\":true,\"ai-gateway\":{\"model\":\"llama3\"},\"workers-ai\":true}";
        let r = dissect_cloudflare_ai_gateway(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::CloudflareAiGateway);
        assert!(r.summary.contains("Cloudflare AI"));
    }

    #[test]
    fn test_cloudflare_ai_gateway_malformed() {
        let buf = b"no";
        let r = dissect_cloudflare_ai_gateway(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
