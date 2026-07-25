use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_azure_aoai_stream(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Azure AOAI Stream (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("azure") && raw.contains("openai") && raw.contains("stream") {
            let end = raw.len().min(80);
            format!("Azure AOAI Stream: {}", &raw[..end])
        } else if raw.contains("data:") && raw.contains("apim-request-id") {
            let end = raw.len().min(80);
            format!("Azure AOAI Stream: {}", &raw[..end])
        } else {
            format!("Azure AOAI Stream ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::AzureAoaiStream,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_azure_aoai_stream_ext() {
        let buf = b"azure:openai:stream:data:{\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}";
        let r = dissect_azure_aoai_stream(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::AzureAoaiStream);
        assert!(r.summary.contains("Azure AOAI"));
    }

    #[test]
    fn test_azure_aoai_stream_malformed() {
        let buf = b"short";
        let r = dissect_azure_aoai_stream(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
