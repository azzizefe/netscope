use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_langsmith_trace_push(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 4 {
        "LangSmith Trace Push (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("\"run_id\"") || raw.contains("\"trace_id\"") {
            let end = raw.len().min(100);
            format!("LangSmith Trace Push: {}", &raw[..end])
        } else if raw.contains("/runs") || raw.contains("/api/v1/traces") {
            format!("LangSmith Trace Push: {}", &raw[..raw.len().min(80)])
        } else {
            format!("LangSmith Trace Push ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::LangsmithTracePush,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_langsmith_trace_push_run() {
        let buf = b"{\"run_id\":\"run_abc\",\"trace_id\":\"trace_xyz\"}";
        let r = dissect_langsmith_trace_push(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::LangsmithTracePush);
        assert!(r.summary.contains("run_id"));
    }

    #[test]
    fn test_langsmith_trace_push_malformed() {
        let buf = b"ab";
        let r = dissect_langsmith_trace_push(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
