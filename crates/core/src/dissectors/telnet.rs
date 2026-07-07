use std::net::IpAddr;

use crate::models::Protocol;

use super::{truncate, DissectedResult};

/// Telnet's IAC (Interpret As Command) byte introduces option negotiation.
const IAC: u8 = 0xFF;

/// Dissect a Telnet segment (TCP 23). Telnet is unencrypted: option
/// negotiation is a stream of IAC (0xFF) command bytes, while the rest is raw
/// terminal text (including, notoriously, plaintext logins).
pub fn dissect_telnet(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.first() == Some(&IAC) {
        format!("Telnet — option negotiation ({} bytes)", payload.len())
    } else {
        let text: String = payload
            .iter()
            .take_while(|&&b| b != b'\r' && b != b'\n')
            .filter(|&&b| (0x20..0x7f).contains(&b))
            .map(|&b| b as char)
            .collect();
        if text.trim().is_empty() {
            format!("Telnet — data ({} bytes)", payload.len())
        } else {
            format!("Telnet — {}", truncate(text.trim(), 50))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Telnet,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiation_detected() {
        // IAC DO ECHO
        let r = dissect_telnet(None, None, 40000, 23, &[0xFF, 0xFD, 0x01]);
        assert_eq!(r.protocol, Protocol::Telnet);
        assert!(r.summary.contains("option negotiation"));
    }

    #[test]
    fn readable_text_shown() {
        let r = dissect_telnet(None, None, 23, 40000, b"login: ");
        assert_eq!(r.summary, "Telnet — login:");
    }

    #[test]
    fn binary_data_reports_size() {
        let r = dissect_telnet(None, None, 23, 40000, &[0x01, 0x02, 0x03, 0x04]);
        assert!(r.summary.contains("data (4 bytes)"));
    }
}
