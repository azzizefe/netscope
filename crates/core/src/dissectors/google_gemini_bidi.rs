use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_google_gemini_bidi(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Google Gemini BiDi (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("gemini") && (raw.contains("bidi") || raw.contains("live")) {
            let end = raw.len().min(80);
            format!("Google Gemini BiDi: {}", &raw[..end])
        } else if raw.contains("setup") && raw.contains("client") && raw.contains("server") {
            let end = raw.len().min(80);
            format!("Google Gemini BiDi: {}", &raw[..end])
        } else {
            format!("Google Gemini BiDi ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::GoogleGeminiBidi,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_google_gemini_bidi_live() {
        let buf = b"gemini:live:bidi:setup:client:config=multimodal";
        let r = dissect_google_gemini_bidi(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::GoogleGeminiBidi);
        assert!(r.summary.contains("Gemini BiDi"));
    }

    #[test]
    fn test_google_gemini_bidi_malformed() {
        let buf = b"short";
        let r = dissect_google_gemini_bidi(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
