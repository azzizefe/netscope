use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_helicone_log_stream(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Helicone Log Stream (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("helicone") && (raw.contains("request") || raw.contains("response")) {
            let end = raw.len().min(80);
            format!("Helicone Log Stream: {}", &raw[..end])
        } else if raw.contains("provider") && raw.contains("model") && raw.contains("helicone") {
            let end = raw.len().min(80);
            format!("Helicone Log Stream: {}", &raw[..end])
        } else {
            format!("Helicone Log Stream ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::HeliconeLogStream,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_helicone_log_stream_log() {
        let buf = b"{\"provider\":\"openai\",\"model\":\"gpt-4\",\"helicone\":{\"request\":{}}}";
        let r = dissect_helicone_log_stream(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::HeliconeLogStream);
        assert!(r.summary.contains("Helicone"));
    }

    #[test]
    fn test_helicone_log_stream_malformed() {
        let buf = b"no";
        let r = dissect_helicone_log_stream(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
