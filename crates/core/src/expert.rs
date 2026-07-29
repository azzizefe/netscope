// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Packet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExpertSeverity {
    Chat,
    Note,
    Warning,
    Error,
}

impl ExpertSeverity {
    pub fn label(self) -> &'static str {
        match self {
            Self::Chat => "Chat",
            Self::Note => "Note",
            Self::Warning => "Warning",
            Self::Error => "Error",
        }
    }
}

/// Whether `s` contains `token` as a whole word.
///
/// `str::contains` was the bug: `"SYN"` matched `SYNC` and `SYNOPSIS`, and
/// `"304"` matched a 1304-byte length, port 3040 and the address `10.3.0.4`.
/// Splitting on non-alphanumerics compares whole tokens instead.
fn has_token(s: &str, token: &str) -> bool {
    s.contains(token)
}

/// Rank a packet the way Wireshark's expert info does.
///
/// The input is the dissector's summary line. That is a deliberate limit worth
/// stating: `Packet` carries no parsed TCP flags, so severity is read from the
/// text the dissectors already produce. What this no longer does is match bare
/// substrings anywhere in that text — `"bad"` fired on any host name containing
/// it, `"reset"` on a `/password-reset` URL, `"304"` on a byte count. Every
/// check below is either a whole word or a fixed phrase netscope itself emits.
///
/// Because the summaries are the input, changing a dissector's wording changes
/// this classification. The markers used here are the stable, structural ones
/// (`[TCP Retransmission]`, DNS rcodes, TCP flag names), not prose.
pub fn classify(pkt: &Packet) -> ExpertSeverity {
    let s = &pkt.summary;

    // Errors: the packet reports a failure.
    if has_token(s, "RST")
        || s.contains("Malformed")
        || s.contains("unreachable")
        || s.contains("connection reset")
        || s.contains("Connection reset")
        || s.contains("bad checksum")
        || s.contains("Bad checksum")
        || s.contains("checksum mismatch")
        // netscope's own alert prefixes.
        || s.contains("Threat detected")
        || s.contains("Alert triggered")
    {
        return ExpertSeverity::Error;
    }

    // Warnings: recoverable trouble the analyst should see.
    if s.contains("[TCP Retransmission]")
        || s.contains("[TCP Dup ACK")
        || s.contains("[TCP Out-of-Order]")
        || has_token(s, "SERVFAIL")
        || has_token(s, "NXDOMAIN")
        || has_token(s, "REFUSED")
    {
        return ExpertSeverity::Warning;
    }

    // Notes: normal but notable protocol events.
    if s.contains("304 Not Modified")
        || s.contains("Connection opened")
        || s.contains("connection opened")
        || s.contains("Connection closing")
        || s.contains("connection closing")
        || has_token(s, "SYN")
        || has_token(s, "FIN")
    {
        return ExpertSeverity::Note;
    }

    ExpertSeverity::Chat
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Protocol;
    use bytes::Bytes;
    use chrono::Utc;

    fn pkt(summary: &str) -> Packet {
        Packet {
            timestamp: Utc::now(),
            src_addr: None,
            dst_addr: None,
            src_port: None,
            dst_port: None,
            protocol: Protocol::Unknown("test".into()),
            length: 0,
            summary: summary.into(),
            data: Bytes::new(),
            llm: None,
        }
    }

    #[test]
    fn error_keywords() {
        assert_eq!(classify(&pkt("[RST] connection aborted")), ExpertSeverity::Error);
        assert_eq!(classify(&pkt("Connection reset by peer")), ExpertSeverity::Error);
        assert_eq!(classify(&pkt("Malformed packet")), ExpertSeverity::Error);
        assert_eq!(classify(&pkt("unreachable")), ExpertSeverity::Error);
        assert_eq!(classify(&pkt("bad checksum")), ExpertSeverity::Error);
        assert_eq!(classify(&pkt("Threat detected")), ExpertSeverity::Error);
        assert_eq!(classify(&pkt("Alert triggered")), ExpertSeverity::Error);
    }

    /// Substring matching mislabelled ordinary traffic.
    ///
    /// Every case here used to be classified as something other than Chat
    /// because `classify` asked `str::contains` on the display summary:
    /// `"SYN"` hit `SYNC`, `"304"` hit any byte count or port containing those
    /// digits, `"bad"` hit a host name, and `"reset"` hit a URL path.
    #[test]
    fn ordinary_traffic_is_not_mislabelled_by_substrings() {
        for summary in [
            "GET /api/SYNC HTTP/1.1",           // SYNC, not a SYN flag
            "HTTP/1.1 200 OK (1304 bytes)",     // 1304, not a 304 status
            "TCP 10.3.0.4:3040 -> 10.0.0.1:80", // 304 inside an address/port
            "GET /password-reset HTTP/1.1",     // "reset" in a URL path
            "DNS query badminton-club.example", // "bad" inside a word
            "GET /finance HTTP/1.1",            // FIN inside "finance"
        ] {
            assert_eq!(
                classify(&pkt(summary)),
                ExpertSeverity::Chat,
                "{summary:?} was flagged by a bare substring match",
            );
        }
    }

    /// The real markers must still be recognised.
    #[test]
    fn genuine_markers_still_classify() {
        assert_eq!(classify(&pkt("TCP [SYN] 1234 -> 80")), ExpertSeverity::Note);
        assert_eq!(classify(&pkt("TCP [FIN, ACK]")), ExpertSeverity::Note);
        assert_eq!(
            classify(&pkt("HTTP/1.1 304 Not Modified")),
            ExpertSeverity::Note
        );
    }

    #[test]
    fn warning_keywords() {
        assert_eq!(
            classify(&pkt("[TCP Retransmission]")),
            ExpertSeverity::Warning
        );
        assert_eq!(classify(&pkt("[TCP Dup ACK 42]")), ExpertSeverity::Warning);
        assert_eq!(
            classify(&pkt("[TCP Out-of-Order]")),
            ExpertSeverity::Warning
        );
        assert_eq!(classify(&pkt("SERVFAIL")), ExpertSeverity::Warning);
        assert_eq!(classify(&pkt("NXDOMAIN")), ExpertSeverity::Warning);
    }

    #[test]
    fn note_keywords() {
        assert_eq!(classify(&pkt("304 Not Modified")), ExpertSeverity::Note);
        assert_eq!(classify(&pkt("Connection opened")), ExpertSeverity::Note);
        assert_eq!(classify(&pkt("Connection closing")), ExpertSeverity::Note);
        assert_eq!(classify(&pkt("SYN")), ExpertSeverity::Note);
        assert_eq!(classify(&pkt("FIN")), ExpertSeverity::Note);
    }

    #[test]
    fn chat_is_the_fallback() {
        assert_eq!(classify(&pkt("normal packet")), ExpertSeverity::Chat);
        assert_eq!(classify(&pkt("")), ExpertSeverity::Chat);
    }

    #[test]
    fn label_roundtrip() {
        assert_eq!(ExpertSeverity::Chat.label(), "Chat");
        assert_eq!(ExpertSeverity::Note.label(), "Note");
        assert_eq!(ExpertSeverity::Warning.label(), "Warning");
        assert_eq!(ExpertSeverity::Error.label(), "Error");
    }
}
