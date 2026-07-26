use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

const B64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    let padding = s.bytes().filter(|&b| b == b'=').count();
    let input_len = s.len().saturating_sub(padding);
    if input_len == 0 { return None; }
    let mut out = Vec::with_capacity(input_len / 4 * 3);
    let mut buf = [0u8; 4];
    let mut pos = 0usize;
    for b in s.bytes() {
        if b == b'=' { break; }
        let idx = B64_CHARS.iter().position(|&c| c == b)?;
        buf[pos] = idx as u8;
        pos += 1;
        if pos == 4 {
            out.push((buf[0] << 2) | (buf[1] >> 4));
            out.push((buf[1] << 4) | (buf[2] >> 2));
            out.push((buf[2] << 6) | buf[3]);
            pos = 0;
        }
    }
    if pos > 1 {
        out.push((buf[0] << 2) | (buf[1] >> 4));
    }
    if pos > 2 {
        out.push((buf[1] << 4) | (buf[2] >> 2));
    }
    Some(out)
}

fn extract_delta(payload: &[u8]) -> Option<String> {
    let raw = String::from_utf8_lossy(payload);
    let val: serde_json::Value = serde_json::from_str(raw.trim()).ok()?;
    let b64 = val.get("bytes")?.as_str()?;
    let decoded = b64_decode(b64)?;
    let inner = String::from_utf8_lossy(&decoded);
    let inner_val: serde_json::Value = serde_json::from_str(&inner).ok()?;
    let completion = inner_val.get("completion")?.as_str()?;
    if completion == "<|endoftext|>" || completion.is_empty() {
        None
    } else {
        Some(completion.to_string())
    }
}

fn is_end(payload: &[u8]) -> bool {
    let raw = String::from_utf8_lossy(payload);
    let val: serde_json::Value = match serde_json::from_str(raw.trim()) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let b64 = match val.get("bytes").and_then(|b| b.as_str()) {
        Some(b) => b,
        None => return false,
    };
    let decoded = match b64_decode(b64) {
        Some(d) => d,
        None => return false,
    };
    let inner = String::from_utf8_lossy(&decoded);
    if let Ok(inner_val) = serde_json::from_str::<serde_json::Value>(&inner) {
        inner_val.get("completion").and_then(|c| c.as_str()) == Some("<|endoftext|>")
    } else {
        false
    }
}

pub fn dissect_bedrock_invoke_stream(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "AWS Bedrock Invoke Stream (malformed)".into()
    } else if is_end(payload) {
        "AWS Bedrock Invoke Stream: [endoftext]".into()
    } else if let Some(token) = extract_delta(payload) {
        let preview = super::truncate(&token, 80);
        format!("AWS Bedrock Invoke Stream: token:\"{}\"", preview)
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("bedrock") && (raw.contains("invoke") || raw.contains("stream")) {
            let end = raw.len().min(80);
            format!("AWS Bedrock Invoke Stream: {}", &raw[..end])
        } else if raw.contains("InvokeModelWithResponseStream") || raw.contains("chunk") && raw.contains("bytes") {
            let end = raw.len().min(80);
            format!("AWS Bedrock Invoke Stream: {}", &raw[..end])
        } else {
            format!("AWS Bedrock Invoke Stream ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::BedrockInvokeStream,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(s: &str) -> String {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let bytes = s.as_bytes();
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
            let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
            let triple = (b0 << 16) | (b1 << 8) | b2;
            out.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
            out.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
            if chunk.len() > 1 {
                out.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
            } else {
                out.push('=');
            }
            if chunk.len() > 2 {
                out.push(CHARS[(triple & 0x3F) as usize] as char);
            } else {
                out.push('=');
            }
        }
        out
    }

    #[test]
    fn test_bedrock_invoke_stream_chunk() {
        let buf = b"bedrock:stream:InvokeModelWithResponseStream:chunk:bytes=0xabc";
        let r = dissect_bedrock_invoke_stream(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::BedrockInvokeStream);
        assert!(r.summary.contains("Bedrock Invoke"));
    }

    #[test]
    fn test_bedrock_invoke_stream_malformed() {
        let buf = b"short";
        let r = dissect_bedrock_invoke_stream(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }

    #[test]
    fn test_bedrock_invoke_stream_with_bytes() {
        let inner = r#"{"completion":"Hello"}"#;
        let b64 = b64(inner);
        let buf = format!("{{\"bytes\":\"{}\"}}", b64);
        let r = dissect_bedrock_invoke_stream(None, None, 0, 0, buf.as_bytes());
        assert_eq!(r.protocol, Protocol::BedrockInvokeStream);
        assert!(r.summary.contains("Hello"));
    }

    #[test]
    fn test_bedrock_invoke_stream_endoftext() {
        let inner = r#"{"completion":"<|endoftext|>"}"#;
        let b64 = b64(inner);
        let buf = format!("{{\"bytes\":\"{}\"}}", b64);
        let r = dissect_bedrock_invoke_stream(None, None, 0, 0, buf.as_bytes());
        assert_eq!(r.protocol, Protocol::BedrockInvokeStream);
        assert!(r.summary.contains("endoftext"));
    }
}
