use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_epic_dtls_p2p(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Epic DTLS P2P (malformed)".into()
    } else {
        let content_type = payload[0];
        let version = u16::from_be_bytes([payload[1], payload[2]]);
        let epoch = payload[3];
        let seq = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let is_dtls = content_type >= 20 && content_type <= 23 && version == 0xFEFD;
        format!(
            "Epic DTLS-P2P ct={} epoch={} seq={}{}",
            content_type, epoch, seq,
            if is_dtls { "" } else { " (raw)" },
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::EpicDtlsP2p,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epic_dtls_p2p_record() {
        let r = dissect_epic_dtls_p2p(None, None, 27018, 27018, b"\x16\xfe\xfd\x00\x00\x00\x00\x01\xde\xad");
        assert_eq!(r.protocol, Protocol::EpicDtlsP2p);
        assert!(r.summary.contains("epoch=0"));
        assert!(r.summary.contains("seq=1"));
    }
}
