use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_groq_lpcu_stream(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Groq LPU Stream (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("groq") && (raw.contains("LPU") || raw.contains("stream")) {
            let end = raw.len().min(80);
            format!("Groq LPU Stream: {}", &raw[..end])
        } else if raw.contains("choices") && raw.contains("x-groq") {
            let end = raw.len().min(80);
            format!("Groq LPU Stream: {}", &raw[..end])
        } else {
            format!("Groq LPU Stream ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::GroqLpcuStream,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_groq_lpu_stream_data() {
        let buf = b"groq:LPU:stream:data:{\"choices\":[{\"delta\":{\"content\":\"fast\"}}]}";
        let r = dissect_groq_lpcu_stream(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::GroqLpcuStream);
        assert!(r.summary.contains("Groq LPU"));
    }

    #[test]
    fn test_groq_lpu_stream_malformed() {
        let buf = b"short";
        let r = dissect_groq_lpcu_stream(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
