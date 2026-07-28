use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_cryengine_net_channel(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 6 {
        "CryEngine NetChannel (malformed)".into()
    } else {
        let channel_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let msg_type = payload[4];
        let flags = payload[5];
        let type_name = match msg_type {
            0 => "Connect",
            1 => "Disconnect",
            2 => "Data",
            3 => "RPC",
            4 => "Update",
            _ => "Other",
        };
        format!(
            "CryEngine NetChannel {} ch{} flags 0x{:02x}",
            type_name, channel_id, flags
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::CryengineNetChannel,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cryengine_net_channel_data() {
        let r = dissect_cryengine_net_channel(
            None,
            None,
            64087,
            64087,
            b"\x00\x00\x00\x01\x02\x00\xde\xad",
        );
        assert_eq!(r.protocol, Protocol::CryengineNetChannel);
        assert!(r.summary.contains("Data"));
    }

    #[test]
    fn test_cryengine_net_channel_connect() {
        let r =
            dissect_cryengine_net_channel(None, None, 64087, 64087, b"\x00\x00\x00\x00\x00\x01");
        assert_eq!(r.protocol, Protocol::CryengineNetChannel);
        assert!(r.summary.contains("Connect"));
    }
}
