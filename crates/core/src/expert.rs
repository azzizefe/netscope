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

pub fn classify(pkt: &Packet) -> ExpertSeverity {
    let s = &pkt.summary;
    if s.contains("reset")
        || s.contains("RST")
        || s.contains("Malformed")
        || s.contains("unreachable")
        || s.contains("bad")
        || s.contains("Threat")
        || s.contains("Alert")
        || s.contains("AbuseIPDB")
        || s.contains("URLhaus")
    {
        ExpertSeverity::Error
    } else if s.contains("[TCP Retransmission]")
        || s.contains("[TCP Dup ACK")
        || s.contains("[TCP Out-of-Order]")
        || s.contains("SERVFAIL")
        || s.contains("NXDOMAIN")
    {
        ExpertSeverity::Warning
    } else if s.contains("304")
        || s.contains("opened")
        || s.contains("closing")
        || s.contains("SYN")
        || s.contains("FIN")
    {
        ExpertSeverity::Note
    } else {
        ExpertSeverity::Chat
    }
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
        assert_eq!(classify(&pkt("reset")), ExpertSeverity::Error);
        assert_eq!(classify(&pkt("RST")), ExpertSeverity::Error);
        assert_eq!(classify(&pkt("Malformed packet")), ExpertSeverity::Error);
        assert_eq!(classify(&pkt("unreachable")), ExpertSeverity::Error);
        assert_eq!(classify(&pkt("bad checksum")), ExpertSeverity::Error);
        assert_eq!(classify(&pkt("Threat detected")), ExpertSeverity::Error);
        assert_eq!(classify(&pkt("Alert triggered")), ExpertSeverity::Error);
        assert_eq!(classify(&pkt("AbuseIPDB match")), ExpertSeverity::Error);
        assert_eq!(classify(&pkt("URLhaus hit")), ExpertSeverity::Error);
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
        assert_eq!(classify(&pkt("opened")), ExpertSeverity::Note);
        assert_eq!(classify(&pkt("closing")), ExpertSeverity::Note);
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
