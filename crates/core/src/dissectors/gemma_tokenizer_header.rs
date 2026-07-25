use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_gemma_tokenizer_header(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 16 {
        "Gemma Tokenizer Header (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("gemma") && raw.contains("tokenizer") || raw.contains("gemma_sp") {
            let end = raw.len().min(80);
            format!("Gemma Tokenizer Header: {}", &raw[..end])
        } else if raw.contains("gemma2") && raw.contains("vocab") || raw.contains("gemma-2") {
            let end = raw.len().min(80);
            format!("Gemma Tokenizer Header: {}", &raw[..end])
        } else {
            format!("Gemma Tokenizer Header ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::GemmaTokenizerHeader,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gemma_tokenizer_header_vocab() {
        let buf = b"{\"gemma\":true,\"tokenizer\":\"gemma_sp\",\"vocab_size\":256000}";
        let r = dissect_gemma_tokenizer_header(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::GemmaTokenizerHeader);
        assert!(r.summary.contains("Gemma"));
    }

    #[test]
    fn test_gemma_tokenizer_header_malformed() {
        let buf = b"bad";
        let r = dissect_gemma_tokenizer_header(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
