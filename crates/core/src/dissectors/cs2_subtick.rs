use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_cs2_subtick(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 16 {
        "CS2 SubTick (malformed)".into()
    } else if payload.len() >= 16 {
        let tick = u32::from_le_bytes(payload[..4].try_into().unwrap());
        let subtick = u16::from_le_bytes(payload[4..6].try_into().unwrap());
        let flags = u16::from_be_bytes(payload[6..8].try_into().unwrap());
        let seq = u32::from_le_bytes(payload[8..12].try_into().unwrap());
        let command_count = u16::from_be_bytes(payload[12..14].try_into().unwrap());
        let _reserved = u16::from_be_bytes(payload[14..16].try_into().unwrap());
        let has_delta = (flags & 0x0001) != 0;
        let has_input = (flags & 0x0002) != 0;
        let has_ack = (flags & 0x0004) != 0;
        format!(
            "CS2 SubTick tick={}.{:04}{}{}{} cmds={} seq={} len={}",
            tick, subtick,
            if has_delta { " DELTA" } else { "" },
            if has_input { " INPUT" } else { "" },
            if has_ack { " ACK" } else { "" },
            command_count, seq, payload.len(),
        )
    } else {
        format!("CS2 SubTick ({})", super::bytes(payload.len() as u64))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Cs2Subtick,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cs2_subtick() {
        let mut buf = vec![0u8; 20];
        buf[..4].copy_from_slice(&500u32.to_le_bytes());
        buf[4..6].copy_from_slice(&128u16.to_le_bytes());
        buf[6..8].copy_from_slice(&0x03u16.to_be_bytes());
        buf[8..12].copy_from_slice(&42u32.to_le_bytes());
        buf[12..14].copy_from_slice(&3u16.to_be_bytes());
        let r = dissect_cs2_subtick(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::Cs2Subtick);
        assert!(r.summary.contains("tick=500"));
        assert!(r.summary.contains("cmds=3"));
    }
}
