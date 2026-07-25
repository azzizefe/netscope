use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_arize_phoenix_collect(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 5 {
        "Arize Phoenix Collect (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("\"llm_token_") || raw.contains("\"embedding\"") {
            let end = raw.len().min(100);
            format!("Arize Phoenix Collect: {}", &raw[..end])
        } else if payload.starts_with(b"POST /v1/traces") || payload.starts_with(b"POST /v1/logs") {
            "Arize Phoenix OTLP collect".to_string()
        } else {
            format!("Arize Phoenix Collect ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::ArizePhoenixCollect,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arize_phoenix_collect_otlp() {
        let buf = b"POST /v1/traces HTTP/1.1\r\nHost: phoenix.arize.com\r\n";
        let r = dissect_arize_phoenix_collect(None, None, 40000, 4318, buf);
        assert_eq!(r.protocol, Protocol::ArizePhoenixCollect);
        assert!(r.summary.contains("OTLP"));
    }

    #[test]
    fn test_arize_phoenix_collect_embedding() {
        let buf = b"{\"embedding\":[0.1,0.2,0.3],\"llm_token_count\":150}";
        let r = dissect_arize_phoenix_collect(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::ArizePhoenixCollect);
        assert!(r.summary.contains("embedding"));
    }
}
