// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! SDP — the description of a media session (RFC 4566).
//!
//! SDP is never sent on its own. It is the body inside a SIP invite, a
//! multicast session announcement or an RTSP response, and it is where the
//! useful facts live: which addresses and ports the media will actually use,
//! and which codecs the two sides are offering each other.
//!
//! That matters for a capture because the media itself lands on dynamically
//! chosen ports. The SDP is the packet that says where to look.
//!
//! There is no `Protocol::Sdp`: a description is always reported through
//! whatever carried it, because "SDP" alone would tell a reader less than
//! "SIP INVITE" or "SAP announcement" does. This module exists to be folded
//! into those summaries.

/// Whether a payload is an SDP body. Every description starts with a version
/// line, and version 0 is the only one there has ever been.
pub(crate) fn looks_like_sdp(payload: &[u8]) -> bool {
    payload.starts_with(b"v=0\r\n") || payload.starts_with(b"v=0\n")
}

/// One media stream the description offers.
struct Media {
    kind: String,
    port: String,
    formats: String,
}

/// Read the `m=` lines, which are what say where media will flow.
///
/// A media line is `m=<kind> <port> <transport> <formats...>`, for example
/// `m=audio 49170 RTP/AVP 0 8 96`.
fn media_lines(text: &str) -> Vec<Media> {
    text.lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("m=")?;
            let mut parts = rest.split_whitespace();
            let kind = parts.next()?.to_string();
            let port = parts.next()?.to_string();
            let _transport = parts.next()?;
            let formats: Vec<&str> = parts.collect();
            Some(Media {
                kind,
                port,
                formats: formats.join(" "),
            })
        })
        .collect()
}

/// Read the connection address, which says where the media is expected to go.
fn connection_address(text: &str) -> Option<&str> {
    text.lines()
        .find_map(|line| line.trim().strip_prefix("c="))
        .and_then(|c| c.split_whitespace().nth(2))
}

/// Describe an SDP body, or `None` if this is not one.
///
/// Returned rather than a `DissectedResult` so the protocols that carry SDP can
/// fold it into their own summary.
pub(crate) fn describe(payload: &[u8]) -> Option<String> {
    if !looks_like_sdp(payload) {
        return None;
    }
    let text = String::from_utf8_lossy(&payload[..payload.len().min(4096)]);
    let media = media_lines(&text);
    if media.is_empty() {
        // A description with no media line is legal but says nothing useful.
        return Some("SDP session description".to_string());
    }
    // A port of zero means the stream is being declined or torn down, which is
    // the difference between "here is my audio" and "no audio, thanks".
    let streams: Vec<String> = media
        .iter()
        .map(|m| {
            if m.port == "0" {
                format!("{} declined", m.kind)
            } else if m.formats.is_empty() {
                format!("{} on {}", m.kind, m.port)
            } else {
                format!(
                    "{} on {} ({})",
                    m.kind,
                    m.port,
                    super::truncate(&m.formats, 20)
                )
            }
        })
        .collect();
    Some(match connection_address(&text) {
        Some(addr) => format!("SDP — {} to {addr}", streams.join(", ")),
        None => format!("SDP — {}", streams.join(", ")),
    })
}

#[cfg(test)]
pub(crate) mod test_helpers {
    /// Build a minimal SDP body offering one audio stream.
    pub fn audio_offer(port: &str) -> Vec<u8> {
        format!(
            "v=0\r\no=alice 2890844526 2890844526 IN IP4 10.0.0.1\r\n\
             s=Call\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0 8 96\r\n"
        )
        .into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::audio_offer;
    use super::*;

    #[test]
    fn audio_stream_names_port_codecs_and_address() {
        let r = describe(&audio_offer("49170")).unwrap();
        assert_eq!(r, "SDP — audio on 49170 (0 8 96) to 10.0.0.1");
    }

    /// A port of zero is how a stream is refused or torn down; reading it as
    /// just another port would hide that entirely.
    #[test]
    fn a_zero_port_means_the_stream_is_declined() {
        let r = describe(&audio_offer("0")).unwrap();
        assert_eq!(r, "SDP — audio declined to 10.0.0.1");
    }

    #[test]
    fn several_streams_are_all_listed() {
        let body = b"v=0\r\nc=IN IP4 192.168.1.5\r\n\
                     m=audio 5004 RTP/AVP 0\r\nm=video 5006 RTP/AVP 96\r\n";
        let r = describe(body).unwrap();
        assert_eq!(
            r,
            "SDP — audio on 5004 (0), video on 5006 (96) to 192.168.1.5"
        );
    }

    /// Both line endings appear in the wild even though the RFC requires CRLF.
    #[test]
    fn bare_newlines_are_tolerated() {
        let body = b"v=0\nc=IN IP4 10.0.0.9\nm=audio 1234 RTP/AVP 0\n";
        assert!(looks_like_sdp(body));
        assert!(describe(body).unwrap().contains("audio on 1234"));
    }

    #[test]
    fn description_without_media_is_still_recognised() {
        let r = describe(b"v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nt=0 0\r\n").unwrap();
        assert_eq!(r, "SDP session description");
    }

    /// The version line is the only reliable marker, so nothing else should be
    /// claimed as SDP.
    #[test]
    fn foreign_payloads_are_not_claimed() {
        assert!(!looks_like_sdp(b"INVITE sip:bob@example.com SIP/2.0\r\n"));
        assert!(!looks_like_sdp(b"v=1\r\n"));
        assert!(!looks_like_sdp(b""));
        assert!(describe(b"GET / HTTP/1.1\r\n").is_none());
    }

    #[test]
    fn malformed_media_lines_are_skipped() {
        let body = b"v=0\r\nm=audio\r\nm=video 5006 RTP/AVP 96\r\n";
        let r = describe(body).unwrap();
        assert_eq!(r, "SDP — video on 5006 (96)");
    }

    #[test]
    fn invalid_utf8_does_not_panic() {
        let mut p = b"v=0\r\nm=audio 5004 RTP/AVP ".to_vec();
        p.extend_from_slice(&[0xFF, 0xFE]);
        p.extend_from_slice(b"\r\n");
        let _ = describe(&p);
    }
}
