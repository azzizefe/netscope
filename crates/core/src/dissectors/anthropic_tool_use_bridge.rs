use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_anthropic_tool_use_bridge(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 4 {
        "Anthropic Tool Use Bridge (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("\"tool_use\"") || raw.contains("\"tool_result\"") {
            let end = raw.len().min(80);
            format!("Anthropic Tool Use Bridge: {}", &raw[..end])
        } else {
            format!("Anthropic Tool Use Bridge {}B", payload.len())
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::AnthropicToolUseBridge,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anthropic_tool_use_bridge_call() {
        let buf =
            b"{\"type\":\"tool_use\",\"name\":\"get_weather\",\"input\":{\"city\":\"London\"}}";
        let r = dissect_anthropic_tool_use_bridge(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::AnthropicToolUseBridge);
        assert!(r.summary.contains("tool_use"));
    }

    #[test]
    fn test_anthropic_tool_use_bridge_malformed() {
        let buf = b"abc";
        let r = dissect_anthropic_tool_use_bridge(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
