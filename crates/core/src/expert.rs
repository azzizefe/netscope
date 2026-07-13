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
    if s.contains("reset") || s.contains("RST") || s.contains("Malformed") || s.contains("unreachable") || s.contains("bad") {
        ExpertSeverity::Error
    } else if s.contains("[TCP Retransmission]") || s.contains("[TCP Dup ACK") || s.contains("[TCP Out-of-Order]") || s.contains("SERVFAIL") || s.contains("NXDOMAIN") {
        ExpertSeverity::Warning
    } else if s.contains("304") || s.contains("opened") || s.contains("closing") || s.contains("SYN") || s.contains("FIN") {
        ExpertSeverity::Note
    } else {
        ExpertSeverity::Chat
    }
}
