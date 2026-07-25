use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_psn_rtc_signaling(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "PSN RTC Signaling (malformed)".into()
    } else {
        let magic = u16::from_be_bytes([payload[0], payload[1]]);
        let msg_type = payload[2];
        let seq = u32::from_be_bytes([payload[3], payload[4], payload[5], payload[6]]);
        let flags = payload[7];
        let type_name = match msg_type {
            0x01 => "Offer",
            0x02 => "Answer",
            0x03 => "ICECandidate",
            0x04 => "Hangup",
            0x05 => "KeepAlive",
            _ => "Unknown",
        };
        let is_rtc = magic == 0x5254;
        format!(
            "PSN RTC {} seq={} flags=0x{:02x}{}",
            type_name, seq, flags,
            if is_rtc { "" } else { " (raw)" },
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::PsnRtcSignaling,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psn_rtc_offer() {
        let r = dissect_psn_rtc_signaling(None, None, 9303, 9303, b"\x52\x54\x01\x00\x00\x00\x01\x00\xde\xad");
        assert_eq!(r.protocol, Protocol::PsnRtcSignaling);
        assert!(r.summary.contains("Offer"));
        assert!(r.summary.contains("seq=1"));
    }
}
