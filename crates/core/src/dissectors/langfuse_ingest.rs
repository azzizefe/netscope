use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_langfuse_ingest(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 4 {
        "Langfuse Ingest (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("\"traceId\"") || raw.contains("\"observationId\"") {
            let end = raw.len().min(100);
            format!("Langfuse Ingest: {}", &raw[..end])
        } else if raw.contains("/api/public/ingestion") {
            format!("Langfuse Ingest: {}", &raw[..raw.len().min(80)])
        } else {
            format!("Langfuse Ingest ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::LangfuseIngest,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_langfuse_ingest_trace() {
        let buf = b"{\"traceId\":\"abc123\",\"observationId\":\"obs_1\"}";
        let r = dissect_langfuse_ingest(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::LangfuseIngest);
        assert!(r.summary.contains("traceId"));
    }

    #[test]
    fn test_langfuse_ingest_malformed() {
        let buf = b"abc";
        let r = dissect_langfuse_ingest(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
