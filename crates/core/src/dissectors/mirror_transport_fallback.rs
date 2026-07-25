use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_mirror_transport_fallback(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 7 {
        "Mirror Transport Fallback (malformed)".into()
    } else {
        let msg_type = payload[0];
        let conn_id = u16::from_be_bytes(payload[1..3].try_into().unwrap());
        let seq = u32::from_be_bytes(payload[3..7].try_into().unwrap());
        let type_name = match msg_type {
            0x01 => "Connect",
            0x02 => "Disconnect",
            0x03 => "Data",
            0x04 => "Ack",
            _ => "Unknown",
        };
        format!(
            "Mirror Transport Fallback type={} conn={} seq={}",
            type_name, conn_id, seq
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::MirrorTransportFallback,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mirror_transport_fallback_data() {
        let buf = vec![0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0xDE, 0xAD];
        let r = dissect_mirror_transport_fallback(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::MirrorTransportFallback);
        assert!(r.summary.contains("Data"));
    }

    #[test]
    fn test_mirror_transport_fallback_malformed() {
        let buf = vec![0x03, 0x00, 0x01];
        let r = dissect_mirror_transport_fallback(None, None, 0, 0, &buf);
        assert!(r.summary.contains("malformed"));
    }
}
