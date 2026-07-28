use std::net::IpAddr;

use crate::dissectors::DissectedResult;
use crate::models::Protocol;

pub fn dissect_nvswitch_telemetry(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 14 {
        let _version = payload[0];
        let pkt_type = payload[1];
        let seq = u32::from_be_bytes([payload[2], payload[3], payload[4], payload[5]]);
        let _ts = u64::from_be_bytes([
            payload[6],
            payload[7],
            payload[8],
            payload[9],
            payload[10],
            payload[11],
            payload[12],
            payload[13],
        ]);
        format!("NVSwitch telemetry type={} seq={}", pkt_type, seq)
    } else {
        "NVSwitch telemetry (short frame)".into()
    };
    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::NvswitchTelemetry,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_nvswitch_telemetry_basic() {
        let mut buf = vec![0u8; 20];
        buf[0] = 1; // version
        buf[1] = 3; // type = temperature
        buf[2..6].copy_from_slice(&100u32.to_be_bytes());
        let r = dissect_nvswitch_telemetry(
            Some("192.168.1.1".parse::<IpAddr>().unwrap()),
            None,
            6000,
            6000,
            &buf,
        );
        assert_eq!(r.protocol, Protocol::NvswitchTelemetry);
        assert!(r.summary.contains("type=3"));
        assert!(r.summary.contains("seq=100"));
    }
}
