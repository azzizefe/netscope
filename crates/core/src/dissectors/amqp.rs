use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an AMQP segment (TCP 5672).
pub fn dissect_amqp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"AMQP") && payload.len() >= 8 {
        format!("AMQP Connection Header (v{}.{}.{})", payload[4], payload[5], payload[6])
    } else {
        "AMQP Message Queuing Traffic".to_string()
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Amqp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amqp_header() {
        let pkt = b"AMQP\x00\x01\x00\x00";
        let r = dissect_amqp(None, None, 50000, 5672, pkt);
        assert_eq!(r.protocol, Protocol::Amqp);
        assert!(r.summary.contains("Header (v0.1.0)"));
    }
}
