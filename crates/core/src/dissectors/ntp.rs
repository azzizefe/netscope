use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an NTP message (UDP 123). The first byte packs Leap Indicator
/// (2 bits), Version (3 bits) and Mode (3 bits); byte 1 is the stratum.
pub fn dissect_ntp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let result = |summary: String| DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Ntp,
        summary,
    };

    if payload.is_empty() {
        return result("NTP (empty)".into());
    }

    let flags = payload[0];
    let version = (flags >> 3) & 0x07;
    let mode = flags & 0x07;
    let mode_name = ntp_mode_name(mode);

    let summary = match payload.get(1) {
        // Stratum is only meaningful for symmetric/client/server modes.
        Some(&stratum) if matches!(mode, 1..=5) => {
            format!("NTP v{version} {mode_name} (stratum {stratum})")
        }
        _ => format!("NTP v{version} {mode_name}"),
    };

    result(summary)
}

fn ntp_mode_name(mode: u8) -> &'static str {
    match mode {
        0 => "reserved",
        1 => "symmetric active",
        2 => "symmetric passive",
        3 => "client",
        4 => "server",
        5 => "broadcast",
        6 => "control",
        7 => "private",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build the first two NTP bytes from version, mode and stratum.
    fn ntp_bytes(version: u8, mode: u8, stratum: u8) -> Vec<u8> {
        let flags = (version << 3) | mode;
        let mut p = vec![flags, stratum];
        p.extend_from_slice(&[0u8; 46]); // rest of a 48-byte NTP packet
        p
    }

    #[test]
    fn client_request_labeled() {
        let pkt = ntp_bytes(4, 3, 0);
        let r = dissect_ntp(None, None, 51000, 123, &pkt);
        assert_eq!(r.protocol, Protocol::Ntp);
        assert_eq!(r.summary, "NTP v4 client (stratum 0)");
    }

    #[test]
    fn server_reply_labeled() {
        let pkt = ntp_bytes(4, 4, 2);
        let r = dissect_ntp(None, None, 123, 51000, &pkt);
        assert_eq!(r.summary, "NTP v4 server (stratum 2)");
    }

    #[test]
    fn empty_is_handled() {
        let r = dissect_ntp(None, None, 123, 123, &[]);
        assert_eq!(r.protocol, Protocol::Ntp);
        assert!(r.summary.contains("empty"));
    }
}
