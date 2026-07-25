use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_fortnite_server_replicator(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 4 {
        "Fortnite Server Replicator (malformed)".into()
    } else if payload.len() >= 8 {
        let channel = u8::from_be_bytes([payload[0]]);
        let packet_id = u8::from_be_bytes([payload[1]]);
        let seq = u16::from_be_bytes([payload[2], payload[3]]);
        let ack = u16::from_be_bytes([payload[4], payload[5]]);
        let _flags = payload[6];
        let num_bunch = payload[7];
        format!(
            "Fortnite Replicator ch={} pid={} seq={} ack={} bunches={}",
            channel, packet_id, seq, ack, num_bunch
        )
    } else {
        format!("Fortnite Replicator ({})", super::bytes(payload.len() as u64))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::FortniteServerReplicator,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fortnite_replicator() {
        let payload = b"\x01\x0a\x00\x1e\x00\x0f\x04\x03\x00\x01\x02";
        let r = dissect_fortnite_server_replicator(None, None, 27000, 27000, payload);
        assert_eq!(r.protocol, Protocol::FortniteServerReplicator);
        assert!(r.summary.contains("ch=1"));
    }
}
