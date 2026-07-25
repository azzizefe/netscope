use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_unreal_iris(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 4 {
        "Unreal Iris (malformed)".into()
    } else {
        let info = parse_iris_header(payload);
        format!("Unreal Iris replication {} objects, {} bits", info.object_count, info.total_bits)
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::UnrealIris,
        summary,
    }
}

struct IrisInfo {
    object_count: u16,
    total_bits: u32,
}

fn parse_iris_header(data: &[u8]) -> IrisInfo {
    if data.len() < 4 {
        return IrisInfo { object_count: 0, total_bits: 0 };
    }
    let object_count = u16::from_be_bytes([data[0], data[1]]);
    let total_bits = u32::from_be_bytes([0, data[2], data[3], 0]);
    IrisInfo { object_count, total_bits }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unreal_iris() {
        let r = dissect_unreal_iris(None, None, 7777, 7777, b"\x00\x05\x00\x80");
        assert_eq!(r.protocol, Protocol::UnrealIris);
        assert!(r.summary.contains("5 objects"));
    }

    #[test]
    fn test_unreal_iris_malformed() {
        let r = dissect_unreal_iris(None, None, 7777, 7778, b"\x00");
        assert_eq!(r.protocol, Protocol::UnrealIris);
        assert!(r.summary.contains("malformed"));
    }
}
