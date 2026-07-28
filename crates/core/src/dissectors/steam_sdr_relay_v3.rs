use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_steam_sdr_relay_v3(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "Steam SDR Relay v3 (malformed)".into()
    } else {
        let _version = payload[0];
        let msg_type = payload[1];
        let session = u32::from_be_bytes([payload[2], payload[3], payload[4], payload[5]]);
        let seq = u32::from_be_bytes([payload[6], payload[7], payload[8], payload[9]]);
        let flags = u16::from_be_bytes([payload[10], payload[11]]);
        let type_name = match msg_type {
            0 => "Data",
            1 => "Connect",
            2 => "ConnectOK",
            3 => "Close",
            4 => "Ping",
            5 => "Pong",
            _ => "Unknown",
        };
        format!(
            "Steam SDRv3 {} session={} seq={} flags=0x{:04x}",
            type_name, session, seq, flags
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SteamSdrRelayV3,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_steam_sdr_v3_data() {
        let r = dissect_steam_sdr_relay_v3(
            None,
            None,
            27036,
            27036,
            b"\x01\x00\x00\x00\x00\x01\x00\x00\x00\x05\x00\x00",
        );
        assert_eq!(r.protocol, Protocol::SteamSdrRelayV3);
        assert!(r.summary.contains("Data"));
        assert!(r.summary.contains("seq=5"));
    }
}
