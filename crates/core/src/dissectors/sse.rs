// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 azzizefe. All rights reserved.
//! Server-Sent Events, and which model API is streaming through one.
//!
//! Every hosted LLM answers a streaming request the same way on the wire: an
//! ordinary HTTP response with `content-type: text/event-stream`, then a run of
//! `data: {…}` lines until the model stops. There is no port to bind and no
//! magic to match — the framing belongs to SSE, not to any one vendor, so from
//! outside the body every provider looks identical.
//!
//! What differs is the JSON. A token arrives inside `choices[].delta.content`
//! from an OpenAI-shaped API and inside a `content_block_delta` event from
//! Anthropic's, and those two shapes do not overlap. That is the only thing
//! here that can tell them apart, so it is what this module keys on.
//!
//! Reached from [`super::http`] by content type, the same way SOAP and OCSP
//! are: the interesting protocol is inside the body, and nothing above the body
//! can see it.

use std::net::IpAddr;

use super::DissectedResult;

/// The content type that carries an event stream.
pub(crate) fn is_event_stream(content_type: &str) -> bool {
    content_type == "text/event-stream"
}

/// The first `data:` payload in the body, which is the event to classify by.
///
/// Comments (`: keep-alive`) and named `event:` lines are skipped — they carry
/// no JSON and would otherwise decide the provider on nothing.
fn first_data_line(body: &str) -> Option<&str> {
    body.lines()
        .filter_map(|l| l.strip_prefix("data:"))
        .map(str::trim)
        .find(|l| !l.is_empty())
}

/// Whether the event is Anthropic-shaped.
///
/// Its stream is a sequence of typed events — `message_start`,
/// `content_block_delta`, `message_stop` — and the type is a top-level field.
/// An OpenAI chunk has no `type` at all.
fn looks_anthropic(data: &str) -> bool {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(data) else {
        return false;
    };
    v.get("type").and_then(|t| t.as_str()).is_some_and(|t| {
        t.starts_with("message_") || t.starts_with("content_block_") || t == "ping"
    })
}

/// Whether the event is OpenAI-shaped: a chunk carrying a `choices` array.
///
/// This is also the shape Azure OpenAI, Mistral, Groq and DeepSeek emit, so a
/// match here means "OpenAI-compatible", not "OpenAI" — which is why the
/// summary the dissector produces says the API and not the vendor.
fn looks_openai(data: &str) -> bool {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(data) else {
        return false;
    };
    v.get("choices").is_some_and(|c| c.is_array())
}

/// Whether a body is an event stream this module can attribute to a provider.
///
/// `[DONE]` is deliberately not enough on its own: it is the OpenAI-compatible
/// terminator, but a stream that only shows its last line says nothing about
/// what produced it, and claiming one would attribute an unrelated event stream
/// to a model API.
pub(crate) fn provider_is_known(body: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(&body[..body.len().min(4096)]) else {
        return false;
    };
    first_data_line(text).is_some_and(|d| looks_anthropic(d) || looks_openai(d))
}

/// Dissect an event-stream body, choosing the decoder by the JSON shape.
pub(crate) fn dissect_sse(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    body: &[u8],
) -> DissectedResult {
    let text = std::str::from_utf8(&body[..body.len().min(4096)]).unwrap_or("");
    let data = first_data_line(text).unwrap_or("");
    if looks_anthropic(data) {
        super::anthropic_messages_stream::dissect_anthropic_messages_stream(
            src_ip, dst_ip, src_port, dst_port, body,
        )
    } else {
        super::openai_streaming_sse::dissect_openai_streaming_sse(
            src_ip, dst_ip, src_port, dst_port, body,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Protocol;

    fn sse(lines: &[&str]) -> Vec<u8> {
        lines.join("\n").into_bytes()
    }

    /// The reason this module exists: the framing is identical, and only the
    /// JSON says which API is on the other end.
    #[test]
    fn the_json_shape_chooses_the_provider() {
        let anthropic = sse(&[
            r#"data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hi"}}"#,
            "",
        ]);
        let openai = sse(&[r#"data: {"choices":[{"delta":{"content":"Hi"}}]}"#, ""]);
        assert!(provider_is_known(&anthropic));
        assert!(provider_is_known(&openai));

        let a = dissect_sse(None, None, 443, 40000, &anthropic);
        assert_eq!(a.protocol, Protocol::AnthropicMessagesStream);
        let o = dissect_sse(None, None, 443, 40000, &openai);
        assert_eq!(o.protocol, Protocol::OpenaiStreamingSse);
    }

    /// Only `text/event-stream` takes the body path.
    #[test]
    fn only_the_event_stream_content_type_is_claimed() {
        assert!(is_event_stream("text/event-stream"));
        assert!(!is_event_stream("application/json"));
        assert!(!is_event_stream("text/plain"));
    }

    /// Keep-alive comments and named events carry no JSON, and deciding the
    /// provider on them would be deciding it on nothing.
    #[test]
    fn comments_and_event_lines_do_not_decide_the_provider() {
        let body = sse(&[
            ": keep-alive",
            "event: content_block_delta",
            r#"data: {"choices":[{"delta":{"content":"x"}}]}"#,
            "",
        ]);
        assert_eq!(
            dissect_sse(None, None, 443, 40000, &body).protocol,
            Protocol::OpenaiStreamingSse
        );
    }

    /// An event stream that is not a model API is left alone — SSE is a
    /// general-purpose transport and most of it is not an LLM.
    #[test]
    fn an_unrelated_event_stream_is_not_claimed() {
        assert!(!provider_is_known(&sse(&[r#"data: {"progress":42}"#, ""])));
        assert!(!provider_is_known(&sse(&["data: [DONE]", ""])));
        assert!(!provider_is_known(&sse(&[": keep-alive", ""])));
        assert!(!provider_is_known(b""));
    }

    /// End to end through the real HTTP dissector — without the body being
    /// reached, every streamed completion reads as "HTTP 200 OK" and nothing
    /// more, which is the whole reason this path exists.
    #[test]
    fn a_streamed_completion_is_read_through_http() {
        let mut resp =
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\n\r\n"
                .to_vec();
        resp.extend_from_slice(
            br#"data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hi"}}"#,
        );
        let r = super::super::http::dissect_http(None, None, 443, 40000, &resp);
        assert_eq!(r.protocol, Protocol::AnthropicMessagesStream);
        assert!(r.summary.starts_with("HTTP · "), "{}", r.summary);

        // An ordinary JSON API response on the same connection still reads as
        // HTTP — only event streams from a known provider take the body path.
        let plain = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}";
        assert_eq!(
            super::super::http::dissect_http(None, None, 443, 40000, plain).protocol,
            Protocol::Http
        );
    }
}
