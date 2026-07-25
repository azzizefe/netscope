use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_anthropic_constitutional(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Anthropic Constitutional AI (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("constitutional") || raw.contains("constitution") {
            let end = raw.len().min(80);
            format!("Anthropic Constitutional AI: {}", &raw[..end])
        } else if raw.contains("critique") || raw.contains("revision") {
            format!("Anthropic Constitutional AI: {}", &raw[..raw.len().min(80)])
        } else {
            format!("Anthropic Constitutional AI ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::AnthropicConstitutional,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anthropic_constitutional_classify() {
        let buf = b"{\"constitutional\":true,\"constitution\":\"harmlessness\"}";
        let r = dissect_anthropic_constitutional(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::AnthropicConstitutional);
        assert!(r.summary.contains("constitutional"));
    }

    #[test]
    fn test_anthropic_constitutional_malformed() {
        let buf = b"short";
        let r = dissect_anthropic_constitutional(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
