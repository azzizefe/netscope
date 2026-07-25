use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_bedrock_invoke_stream(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "AWS Bedrock Invoke Stream (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("bedrock") && (raw.contains("invoke") || raw.contains("stream")) {
            let end = raw.len().min(80);
            format!("AWS Bedrock Invoke Stream: {}", &raw[..end])
        } else if raw.contains("InvokeModelWithResponseStream") || raw.contains("chunk") && raw.contains("bytes") {
            let end = raw.len().min(80);
            format!("AWS Bedrock Invoke Stream: {}", &raw[..end])
        } else {
            format!("AWS Bedrock Invoke Stream ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::BedrockInvokeStream,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bedrock_invoke_stream_chunk() {
        let buf = b"bedrock:stream:InvokeModelWithResponseStream:chunk:bytes=0xabc";
        let r = dissect_bedrock_invoke_stream(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::BedrockInvokeStream);
        assert!(r.summary.contains("Bedrock Invoke"));
    }

    #[test]
    fn test_bedrock_invoke_stream_malformed() {
        let buf = b"short";
        let r = dissect_bedrock_invoke_stream(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
