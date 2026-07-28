use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_pubg_net_field_array(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 6 {
        "PUBG NetFieldArray (malformed)".into()
    } else {
        let element_count = u16::from_be_bytes([payload[0], payload[1]]);
        let changed_bits = u16::from_be_bytes([payload[2], payload[3]]);
        let base_offset = u16::from_be_bytes([payload[4], payload[5]]);
        format!(
            "PUBG NetFieldArray elements={} changed=0x{:04x} base_offset={} len={}",
            element_count,
            changed_bits,
            base_offset,
            payload.len()
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::PubgNetFieldArray,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pubg_net_field() {
        let r = dissect_pubg_net_field_array(
            None,
            None,
            0,
            0,
            b"\x00\x0a\x00\x03\x00\x01\xde\xad\xbe\xef",
        );
        assert_eq!(r.protocol, Protocol::PubgNetFieldArray);
        assert!(r.summary.contains("elements=10"));
    }
}
