use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_llama_tokenizer_header(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 16 {
        "Llama Tokenizer Header (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("llama") && raw.contains("tokenizer") || raw.contains("llama_spm") {
            let end = raw.len().min(80);
            format!("Llama Tokenizer Header: {}", &raw[..end])
        } else if (raw.contains("vocab") || raw.contains("bos_token")) && raw.contains("eos_token") && raw.contains("llama") {
            let end = raw.len().min(80);
            format!("Llama Tokenizer Header: {}", &raw[..end])
        } else {
            format!("Llama Tokenizer Header ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::LlamaTokenizerHeader,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_llama_tokenizer_header_meta() {
        let buf = b"{\"llama\":true,\"tokenizer\":\"llama_spm\",\"bos_token\":\"<s>\",\"eos_token\":\"</s>\"}";
        let r = dissect_llama_tokenizer_header(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::LlamaTokenizerHeader);
        assert!(r.summary.contains("Llama"));
    }

    #[test]
    fn test_llama_tokenizer_header_malformed() {
        let buf = b"bad";
        let r = dissect_llama_tokenizer_header(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
