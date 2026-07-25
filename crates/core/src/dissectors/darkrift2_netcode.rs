use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_darkrift2_netcode(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 6 {
        "DarkRift 2 (malformed)".into()
    } else {
        let tag = payload[0];
        let msg_len = u16::from_be_bytes(payload[1..3].try_into().unwrap());
        let msg_type = u16::from_be_bytes(payload[3..5].try_into().unwrap());
        let type_name = match msg_type {
            0x0000 => "Connect",
            0x0001 => "Disconnect",
            0x0002 => "PingPong",
            0x0003 => "Data",
            _ => "Unknown",
        };
        format!(
            "DarkRift 2 tag={} type={} len={}",
            tag, type_name, msg_len
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Darkrift2Netcode,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_darkrift2_netcode_data() {
        let buf = vec![0x00, 0x00, 0x05, 0x00, 0x03, 0x00, 0x01, 0x02, 0x03, 0x04];
        let r = dissect_darkrift2_netcode(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::Darkrift2Netcode);
        assert!(r.summary.contains("Data"));
    }

    #[test]
    fn test_darkrift2_netcode_malformed() {
        let buf = vec![0x00, 0x00, 0x05];
        let r = dissect_darkrift2_netcode(None, None, 0, 0, &buf);
        assert!(r.summary.contains("malformed"));
    }
}
