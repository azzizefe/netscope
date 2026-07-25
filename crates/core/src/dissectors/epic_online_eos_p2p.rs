use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_epic_online_eos_p2p(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "EOS P2P (malformed)".into()
    } else {
        let channel = payload[0];
        let seq = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
        let flags = payload[5];
        let ack_count = payload[6];
        let is_reliable = (flags & 0x01) != 0;
        format!(
            "EOS P2P chan={} seq={} {} ack={}",
            channel, seq,
            if is_reliable { "reliable" } else { "unreliable" },
            ack_count,
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::EpicOnlineEosP2p,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eos_p2p_reliable() {
        let r = dissect_epic_online_eos_p2p(None, None, 27018, 27018, b"\x01\x00\x00\x00\x0a\x01\x02\x00\xde\xad");
        assert_eq!(r.protocol, Protocol::EpicOnlineEosP2p);
        assert!(r.summary.contains("reliable"));
        assert!(r.summary.contains("seq=10"));
    }
}
