use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_photon_realtime_v5(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 7 {
        "Photon Realtime v5 (malformed)".into()
    } else {
        let command = payload[0];
        let channel = payload[1];
        let flags = payload[2];
        let seq = u32::from_be_bytes(payload[3..7].try_into().unwrap());
        let is_reliable = (flags & 0x01) != 0;
        let is_fragmented = (flags & 0x02) != 0;
        let cmd_name = match command {
            0x00 => "Send",
            0x01 => "Ack",
            0x02 => "Join",
            0x03 => "Leave",
            0x04 => "Event",
            _ => "Unknown",
        };
        format!(
            "Photon Realtime v5 cmd={} ch={}{}{} seq={}",
            cmd_name,
            channel,
            if is_reliable { " REL" } else { "" },
            if is_fragmented { " FRAG" } else { "" },
            seq
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::PhotonRealtimeV5,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_photon_realtime_v5_send() {
        let buf = vec![0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0xAA];
        let r = dissect_photon_realtime_v5(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::PhotonRealtimeV5);
        assert!(r.summary.contains("Send"));
        assert!(r.summary.contains("REL"));
    }

    #[test]
    fn test_photon_realtime_v5_malformed() {
        let buf = vec![0x00, 0x01, 0x01, 0x00];
        let r = dissect_photon_realtime_v5(None, None, 0, 0, &buf);
        assert!(r.summary.contains("malformed"));
    }
}
