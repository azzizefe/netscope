use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_langfuse_ingest_v2(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Langfuse Ingest v2 (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("langfuse") && raw.contains("trace") && raw.contains("observation") {
            let end = raw.len().min(80);
            format!("Langfuse Ingest v2: {}", &raw[..end])
        } else if raw.contains("generation") && raw.contains("usage") && raw.contains("langfuse") {
            let end = raw.len().min(80);
            format!("Langfuse Ingest v2: {}", &raw[..end])
        } else {
            format!("Langfuse Ingest v2 ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::LangfuseIngestV2,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_langfuse_ingest_v2_trace() {
        let buf = b"{\"langfuse\":true,\"trace\":{\"id\":\"t1\"},\"observation\":{\"id\":\"o1\"}}";
        let r = dissect_langfuse_ingest_v2(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::LangfuseIngestV2);
        assert!(r.summary.contains("Langfuse Ingest"));
    }

    #[test]
    fn test_langfuse_ingest_v2_malformed() {
        let buf = b"tiny";
        let r = dissect_langfuse_ingest_v2(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
