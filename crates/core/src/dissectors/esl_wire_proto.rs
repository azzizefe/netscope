use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_esl_wire_proto(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 5 {
        "ESL Wire (malformed)".into()
    } else {
        let version = payload[0];
        let msg_type = payload[1];
        let match_id = u16::from_be_bytes(payload[3..5].try_into().unwrap());
        let type_name = match msg_type {
            0x01 => "Attest",
            0x02 => "Heartbeat",
            0x03 => "Result",
            _ => "Unknown",
        };
        format!(
            "ESL Wire v={} type={} match={}",
            version, type_name, match_id
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::EslWireProto,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_esl_wire_proto_attest() {
        let buf = vec![0x01, 0x01, 0x00, 0x00, 0x01];
        let r = dissect_esl_wire_proto(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::EslWireProto);
        assert!(r.summary.contains("Attest"));
    }

    #[test]
    fn test_esl_wire_proto_malformed() {
        let buf = vec![0x01, 0x01, 0x00];
        let r = dissect_esl_wire_proto(None, None, 0, 0, &buf);
        assert!(r.summary.contains("malformed"));
    }
}
