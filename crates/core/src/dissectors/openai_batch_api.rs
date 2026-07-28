use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_openai_batch_api(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 4 {
        "OpenAI Batch API (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("\"batch_id\"") || raw.contains("\"endpoint\"") {
            let end = raw.len().min(100);
            format!("OpenAI Batch API: {}", &raw[..end])
        } else {
            format!("OpenAI Batch API {}B payload", payload.len())
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::OpenaiBatchApi,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openai_batch_api_request() {
        let buf = b"{\"batch_id\":\"batch_abc123\",\"endpoint\":\"/v1/chat/completions\"}";
        let r = dissect_openai_batch_api(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::OpenaiBatchApi);
        assert!(r.summary.contains("batch_id"));
    }

    #[test]
    fn test_openai_batch_api_malformed() {
        let buf = b"abc";
        let r = dissect_openai_batch_api(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
