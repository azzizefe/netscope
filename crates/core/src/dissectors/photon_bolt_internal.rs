use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_photon_bolt_internal(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 10 {
        "Photon Bolt (malformed)".into()
    } else {
        let frame_id = u32::from_be_bytes(payload[0..4].try_into().unwrap());
        let step = u32::from_be_bytes(payload[4..8].try_into().unwrap());
        let input_count = payload[9];
        format!(
            "Photon Bolt frame={} step={} inputs={}",
            frame_id, step, input_count
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::PhotonBoltInternal,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_photon_bolt_internal_basic() {
        let buf = vec![
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x0A,
            0x00, 0x02,
        ];
        let r = dissect_photon_bolt_internal(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::PhotonBoltInternal);
    }

    #[test]
    fn test_photon_bolt_internal_malformed() {
        let buf = vec![0x00, 0x00, 0x00];
        let r = dissect_photon_bolt_internal(None, None, 0, 0, &buf);
        assert!(r.summary.contains("malformed"));
    }
}
