use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_playfab_party(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "PlayFab Party (malformed)".into()
    } else {
        let version = payload[0];
        let msg_type = payload[1];
        let seq = u32::from_be_bytes(payload[4..8].try_into().unwrap());
        format!(
            "PlayFab Party v={} type={} seq={}",
            version, msg_type, seq
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::PlayfabParty,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_playfab_party_basic() {
        let buf = vec![0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xAA, 0xBB];
        let r = dissect_playfab_party(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::PlayfabParty);
    }

    #[test]
    fn test_playfab_party_malformed() {
        let buf = vec![0x01, 0x03, 0x00];
        let r = dissect_playfab_party(None, None, 0, 0, &buf);
        assert!(r.summary.contains("malformed"));
    }
}
