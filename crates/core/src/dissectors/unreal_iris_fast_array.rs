use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_unreal_iris_fast_array(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Iris FastArray (malformed)".into()
    } else {
        let changed = u16::from_be_bytes([payload[0], payload[1]]);
        let total = u16::from_be_bytes([payload[2], payload[3]]);
        let elem_size = u16::from_be_bytes([payload[4], payload[5]]);
        format!(
            "Iris FastArray {}/{} elements changed, {} bytes each",
            changed, total, elem_size
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::UnrealIrisFastArray,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unreal_iris_fast_array() {
        let r = dissect_unreal_iris_fast_array(
            None,
            None,
            7777,
            7777,
            b"\x00\x03\x00\x0a\x00\x20\x01\x02\x03",
        );
        assert_eq!(r.protocol, Protocol::UnrealIrisFastArray);
        assert!(r.summary.contains("3/10"));
    }
}
