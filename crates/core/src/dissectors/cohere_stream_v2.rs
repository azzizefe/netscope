use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

fn extract_delta(payload: &[u8]) -> Option<String> {
    let raw = String::from_utf8_lossy(payload);
    let trimmed = raw.trim();
    let json_str = trimmed
        .strip_prefix("data: ")
        .or_else(|| trimmed.strip_prefix("data:"))
        .map(|s| s.trim())
        .unwrap_or(trimmed);
    let val: serde_json::Value = serde_json::from_str(json_str).ok()?;
    let event_type = val.get("event_type")?.as_str()?;
    if event_type != "text-generation" {
        return None;
    }
    let token = val.get("text")?.as_str()?;
    if token.is_empty() { None } else { Some(token.to_string()) }
}

fn is_complete(payload: &[u8]) -> bool {
    let raw = String::from_utf8_lossy(payload);
    let trimmed = raw.trim();
    let json_str = trimmed
        .strip_prefix("data: ")
        .or_else(|| trimmed.strip_prefix("data:"))
        .map(|s| s.trim())
        .unwrap_or(trimmed);
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(json_str) {
        val.get("finish_reason").and_then(|f| f.as_str()) == Some("COMPLETE")
    } else {
        false
    }
}

pub fn dissect_cohere_stream_v2(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Cohere Stream v2 (malformed)".into()
    } else if is_complete(payload) {
        "Cohere Stream v2: [COMPLETE]".into()
    } else if let Some(token) = extract_delta(payload) {
        let preview = super::truncate(&token, 80);
        format!("Cohere Stream v2: token:\"{}\"", preview)
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("text:") && raw.contains("finish_reason") {
            let end = raw.len().min(80);
            format!("Cohere Stream v2: {}", &raw[..end])
        } else if raw.contains("cohere") && (raw.contains("stream") || raw.contains("generation")) {
            let end = raw.len().min(80);
            format!("Cohere Stream v2: {}", &raw[..end])
        } else {
            format!("Cohere Stream v2 ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::CohereStreamV2,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cohere_stream_v2_text_generation() {
        let buf = b"data: {\"event_type\":\"text-generation\",\"text\":\"Hello\"}\n\n";
        let r = dissect_cohere_stream_v2(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::CohereStreamV2);
        assert!(r.summary.contains("Hello"));
    }

    #[test]
    fn test_cohere_stream_v2_stream_end() {
        let buf = b"data: {\"event_type\":\"stream-end\",\"finish_reason\":\"COMPLETE\"}\n\n";
        let r = dissect_cohere_stream_v2(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::CohereStreamV2);
        assert!(r.summary.contains("COMPLETE"));
    }

    #[test]
    fn test_cohere_stream_v2_legacy() {
        let buf = b"cohere:stream:text:hello:finish_reason=complete";
        let r = dissect_cohere_stream_v2(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::CohereStreamV2);
        assert!(r.summary.contains("Cohere Stream"));
    }

    #[test]
    fn test_cohere_stream_v2_malformed() {
        let buf = b"short";
        let r = dissect_cohere_stream_v2(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
