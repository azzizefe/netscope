use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_google_gemini_rest_stream(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Google Gemini REST Stream (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("generateContent") && raw.contains("candidates") {
            let end = raw.len().min(80);
            format!("Google Gemini REST Stream: {}", &raw[..end])
        } else if raw.contains("gemini") && raw.contains("SSE") {
            let end = raw.len().min(80);
            format!("Google Gemini REST Stream: {}", &raw[..end])
        } else {
            format!("Google Gemini REST Stream ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::GoogleGeminiRestStream,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_google_gemini_rest_sse() {
        let buf = b"data: {\"candidates\":[{\"content\":\"hello\"}]}";
        let r = dissect_google_gemini_rest_stream(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::GoogleGeminiRestStream);
        assert!(r.summary.contains("Gemini REST"));
    }

    #[test]
    fn test_google_gemini_rest_malformed() {
        let buf = b"short";
        let r = dissect_google_gemini_rest_stream(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
