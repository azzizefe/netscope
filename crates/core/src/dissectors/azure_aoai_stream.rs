use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

/// The JSON object carried by an SSE `data:` frame, if this payload is one.
///
/// A frame that is not a single JSON object — an HTTP header block, a partial
/// chunk — yields `None` rather than a guess.
fn sse_json(payload: &[u8]) -> Option<serde_json::Value> {
    let raw = String::from_utf8_lossy(payload);
    let trimmed = raw.trim();
    if trimmed == "[DONE]" || trimmed == "data: [DONE]" {
        return None;
    }
    let json_str = trimmed
        .strip_prefix("data: ")
        .or_else(|| trimmed.strip_prefix("data:"))
        .map(|s| s.trim())
        .unwrap_or(trimmed);
    if json_str == "[DONE]" {
        return None;
    }
    serde_json::from_str(json_str).ok()
}

fn extract_delta(payload: &[u8]) -> Option<String> {
    let token = sse_json(payload)?
        .get("choices")?
        .as_array()?
        .first()?
        .get("delta")?
        .get("content")?
        .as_str()?
        .to_string();
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

/// Why the model stopped, from the final chunk — which carries an empty delta
/// and so used to fall through to a raw preview.
///
/// `content_filter` is the one worth surfacing: the request succeeded, and the
/// answer was withheld. Read from a preview of the raw frame that is
/// indistinguishable from an ordinary `stop`.
fn extract_finish_reason(payload: &[u8]) -> Option<String> {
    let reason = sse_json(payload)?
        .get("choices")?
        .as_array()?
        .first()?
        .get("finish_reason")?
        .as_str()?
        .to_string();
    if reason.is_empty() {
        None
    } else {
        Some(reason)
    }
}

/// A failed stream arrives as a data frame carrying an error object, not as a
/// transport failure, so nothing below this layer reports it.
fn extract_error(payload: &[u8]) -> Option<String> {
    let val = sse_json(payload)?;
    let err = val.get("error")?;
    let code = err
        .get("code")
        .and_then(|c| {
            c.as_str()
                .map(str::to_string)
                .or_else(|| c.as_i64().map(|n| n.to_string()))
        })
        .unwrap_or_else(|| "?".into());
    match err.get("message").and_then(|m| m.as_str()) {
        Some(msg) if !msg.is_empty() => Some(format!("{code} — {}", super::truncate(msg, 80))),
        _ => Some(code),
    }
}

/// Azure's per-request correlation id — the value you quote to Azure support
/// when a stream misbehaves. It rides in the response headers ahead of the SSE
/// body.
///
/// Found by walking the header lines and comparing the name, not by scanning
/// for the text: the id also appears inside logged request bodies, and a scan
/// returns whichever copy came first.
fn extract_request_id(raw: &str) -> Option<&str> {
    raw.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("apim-request-id")
                .then(|| value.trim())
        })
        .filter(|id| !id.is_empty())
}

fn is_done(payload: &[u8]) -> bool {
    let raw = String::from_utf8_lossy(payload);
    let trimmed = raw.trim();
    trimmed == "[DONE]" || trimmed == "data: [DONE]"
}

pub fn dissect_azure_aoai_stream(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    // Ordered by how much the reader learns: an error outranks a token, and a
    // token outranks the reason the stream ended. Anything still unrecognised
    // falls back to a preview rather than being described wrongly.
    let summary = if payload.len() < 8 {
        "Azure AOAI Stream (malformed)".into()
    } else if is_done(payload) {
        "Azure AOAI Stream: [DONE]".into()
    } else if let Some(err) = extract_error(payload) {
        format!("Azure AOAI Stream: error {}", err)
    } else if let Some(token) = extract_delta(payload) {
        let preview = super::truncate(&token, 80);
        format!("Azure AOAI Stream: token:\"{}\"", preview)
    } else if let Some(reason) = extract_finish_reason(payload) {
        format!("Azure AOAI Stream: finish_reason={}", reason)
    } else {
        let raw = String::from_utf8_lossy(payload);
        match extract_request_id(&raw) {
            Some(id) => format!("Azure AOAI Stream: apim-request-id={}", id),
            None => format!("Azure AOAI Stream: {}", super::truncate(&raw, 60)),
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::AzureAoaiStream,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_azure_aoai_stream_delta() {
        let buf = b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n";
        let r = dissect_azure_aoai_stream(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::AzureAoaiStream);
        assert!(r.summary.contains("hi"));
    }

    #[test]
    fn test_azure_aoai_stream_done() {
        let buf = b"data: [DONE]\n\n";
        let r = dissect_azure_aoai_stream(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::AzureAoaiStream);
        assert!(r.summary.contains("[DONE]"));
    }

    #[test]
    fn test_azure_aoai_stream_malformed() {
        let buf = b"short";
        let r = dissect_azure_aoai_stream(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }

    /// A withheld answer is not an ordinary stop, and the final chunk is the
    /// only place that says so. It used to render as a raw preview.
    #[test]
    fn a_content_filtered_stream_says_so() {
        let buf = b"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"content_filter\"}]}";
        let r = dissect_azure_aoai_stream(None, None, 0, 0, buf);
        assert!(
            r.summary.contains("finish_reason=content_filter"),
            "{}",
            r.summary
        );

        let stop = b"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}";
        let r = dissect_azure_aoai_stream(None, None, 0, 0, stop);
        assert!(r.summary.contains("finish_reason=stop"), "{}", r.summary);
    }

    /// A token still wins over the reason — a chunk that carries both is
    /// reporting content, and the content is what the reader wants.
    #[test]
    fn a_chunk_with_content_reports_the_token() {
        let buf =
            b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"},\"finish_reason\":\"stop\"}]}";
        let r = dissect_azure_aoai_stream(None, None, 0, 0, buf);
        assert!(r.summary.contains("token:\"hi\""), "{}", r.summary);
    }

    /// A failed stream arrives as a data frame, so this is the only layer that
    /// can report it.
    #[test]
    fn an_error_frame_reports_its_code_and_message() {
        let buf = b"data: {\"error\":{\"code\":\"429\",\"message\":\"Rate limit exceeded\"}}";
        let r = dissect_azure_aoai_stream(None, None, 0, 0, buf);
        assert!(r.summary.contains("error 429"), "{}", r.summary);
        assert!(r.summary.contains("Rate limit exceeded"), "{}", r.summary);

        // A code with no message still names the code.
        let bare = b"data: {\"error\":{\"code\":\"content_filter\"}}";
        let r = dissect_azure_aoai_stream(None, None, 0, 0, bare);
        assert!(r.summary.contains("error content_filter"), "{}", r.summary);
    }

    /// The correlation id was checked for and then thrown away — the branch
    /// that tested for it produced the same preview as the branch that did not.
    #[test]
    fn the_request_id_is_reported_when_the_headers_carry_it() {
        let buf = b"HTTP/1.1 200 OK\r\napim-request-id: 7f3c1b20-dead-4beef-9a11-000000000001\r\ncontent-type: text/event-stream\r\n\r\n";
        let r = dissect_azure_aoai_stream(None, None, 0, 0, buf);
        assert!(
            r.summary
                .contains("apim-request-id=7f3c1b20-dead-4beef-9a11-000000000001"),
            "{}",
            r.summary,
        );
    }

    /// Header names are case-insensitive, and a header with no value is not an
    /// id.
    #[test]
    fn the_request_id_lookup_matches_the_header_not_the_text() {
        assert_eq!(
            extract_request_id("Apim-Request-Id: abc123\r\n"),
            Some("abc123"),
        );
        assert_eq!(extract_request_id("apim-request-id:   \r\n"), None);
        // The name has to be the header name, not a mention of it in a body.
        assert_eq!(
            extract_request_id("{\"note\":\"apim-request-id is missing\"}"),
            None,
        );
    }

    /// Nothing recognised still renders, rather than claiming a field it did
    /// not find.
    #[test]
    fn an_unrecognised_frame_falls_back_to_a_preview() {
        let buf = b"event: ping\r\n\r\n";
        let r = dissect_azure_aoai_stream(None, None, 0, 0, buf);
        assert!(
            r.summary.starts_with("Azure AOAI Stream: "),
            "{}",
            r.summary
        );
        assert!(!r.summary.contains("apim-request-id"), "{}", r.summary);
    }
}
