use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_tiktoken_bpe_header(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 16 {
        "Tiktoken BPE Header (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("cl100k_base") || raw.contains("o200k_base") || raw.contains("p50k_base") {
            let end = raw.len().min(80);
            format!("Tiktoken BPE Header: {}", &raw[..end])
        } else if raw.contains("r50k_base") || raw.contains("gpt2") && raw.contains("bpe") {
            let end = raw.len().min(80);
            format!("Tiktoken BPE Header: {}", &raw[..end])
        } else {
            format!("Tiktoken BPE Header ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::TiktokenBpeHeader,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tiktoken_bpe_header_cl100k() {
        let buf = b"{\"model\":\"cl100k_base\",\"vocab_size\":100256}";
        let r = dissect_tiktoken_bpe_header(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::TiktokenBpeHeader);
        assert!(r.summary.contains("Tiktoken"));
    }

    #[test]
    fn test_tiktoken_bpe_header_malformed() {
        let buf = b"short";
        let r = dissect_tiktoken_bpe_header(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
