use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_o3de_aznetworking(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "O3DE AzNetworking (malformed)".into()
    } else {
        let magic = u16::from_be_bytes([payload[0], payload[1]]);
        let version = payload[2];
        let packet_type = payload[3];
        let sequence = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let type_name = match packet_type {
            0 => "Unreliable",
            1 => "Reliable",
            2 => "Connect",
            3 => "Disconnect",
            _ => "Unknown",
        };
        format!(
            "O3DE AzNetworking {} seq{} magic 0x{:04x} v{}",
            type_name, sequence, magic, version
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::O3deAznetworking,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_o3de_aznetworking() {
        let r = dissect_o3de_aznetworking(
            None,
            None,
            51726,
            51726,
            b"\x41\x5a\x01\x00\x00\x00\x00\x01\xbe\xef",
        );
        assert_eq!(r.protocol, Protocol::O3deAznetworking);
        assert!(r.summary.contains("Unreliable"));
    }
}
