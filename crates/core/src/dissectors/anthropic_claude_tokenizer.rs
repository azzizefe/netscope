use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_anthropic_claude_tokenizer(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 16 {
        "Anthropic Claude Tokenizer (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("claude") && raw.contains("tokenizer") || raw.contains("anthropic_token") {
            let end = raw.len().min(80);
            format!("Anthropic Claude Tokenizer: {}", &raw[..end])
        } else if raw.contains("bpe_tokenizer") && raw.contains("claude") || raw.contains("claude_token") {
            let end = raw.len().min(80);
            format!("Anthropic Claude Tokenizer: {}", &raw[..end])
        } else {
            format!("Anthropic Claude Tokenizer ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::AnthropicClaudeTokenizer,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anthropic_claude_tokenizer_config() {
        let buf = b"{\"claude\":true,\"tokenizer\":\"anthropic_token\",\"bpe_tokenizer\":true}";
        let r = dissect_anthropic_claude_tokenizer(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::AnthropicClaudeTokenizer);
        assert!(r.summary.contains("Anthropic"));
    }

    #[test]
    fn test_anthropic_claude_tokenizer_malformed() {
        let buf = b"bad";
        let r = dissect_anthropic_claude_tokenizer(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
