use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_steam_datagram_relay(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Steam Datagram Relay (malformed)".into()
    } else {
        let _magic = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let seq = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        format!("Steam SDR relay seq={} len={}", seq, payload.len())
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SteamDatagramRelay,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_steam_sdr_relay() {
        let r = dissect_steam_datagram_relay(
            None,
            None,
            27036,
            27036,
            b"\xde\xad\xbe\xef\x00\x00\x00\x01\xca\xfe",
        );
        assert_eq!(r.protocol, Protocol::SteamDatagramRelay);
        assert!(r.summary.contains("seq=1"));
    }
}
