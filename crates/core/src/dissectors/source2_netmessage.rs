use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_source2_netmessage(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 5 {
        "Source 2 NetMessage (malformed)".into()
    } else {
        let msg_id = payload[0];
        let tick = u32::from_be_bytes([0, payload[1], payload[2], payload[3]]);
        let size = payload[4];
        format!("Source 2 NetMessage id{} tick{} size{}", msg_id, tick, size)
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Source2Netmessage,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source2_netmessage() {
        let r = dissect_source2_netmessage(
            None,
            None,
            27015,
            27015,
            b"\x0a\x00\x00\x00\x10\xbe\xef\xca\xfe",
        );
        assert_eq!(r.protocol, Protocol::Source2Netmessage);
        assert!(r.summary.contains("id10"));
    }
}
