use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_google_gemini_stream(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 5 {
        "Gemini Stream (malformed)".into()
    } else {
        let is_grpc_web = payload[0] == 0x00;
        if is_grpc_web && payload.len() > 5 {
            let msg_len = u32::from_be_bytes(payload[1..5].try_into().unwrap()) as usize;
            let content_start = 5;
            if content_start + msg_len <= payload.len() {
                let inner = &payload[content_start..content_start + msg_len];
                let raw = String::from_utf8_lossy(inner);
                let end = raw.len().min(80);
                format!("Gemini Stream gRPC-web: {}", &raw[..end])
            } else {
                format!("Gemini Stream {}B gRPC-web frame", payload.len())
            }
        } else {
            format!("Gemini Stream {}B", payload.len())
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::GoogleGeminiStream,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_google_gemini_stream_grpc_web() {
        let inner = b"{\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"Hi\"}]}}]}";
        let mut buf = vec![0x00];
        buf.extend_from_slice(&(inner.len() as u32).to_be_bytes());
        buf.extend_from_slice(inner);
        let r = dissect_google_gemini_stream(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::GoogleGeminiStream);
        assert!(r.summary.contains("candidates"));
    }

    #[test]
    fn test_google_gemini_stream_malformed() {
        let buf = b"abcd";
        let r = dissect_google_gemini_stream(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
