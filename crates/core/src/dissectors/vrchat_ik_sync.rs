use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_vrchat_ik_sync(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 6 {
        "VRChat IK Sync (malformed)".into()
    } else {
        let num_bones = payload[0];
        let seq = u16::from_be_bytes(payload[2..4].try_into().unwrap());
        let time_delta = u16::from_be_bytes(payload[4..6].try_into().unwrap());
        format!(
            "VRChat IK Sync seq={} bones={} dt={}ms",
            seq, num_bones, time_delta
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::VrchatIkSync,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vrchat_ik_sync_basic() {
        let buf = vec![0x04, 0x00, 0x00, 0x0A, 0x00, 0x10, 0x01, 0x02, 0x03, 0x04];
        let r = dissect_vrchat_ik_sync(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::VrchatIkSync);
        assert!(r.summary.contains("bones=4"));
    }

    #[test]
    fn test_vrchat_ik_sync_malformed() {
        let buf = vec![0x01, 0x00, 0x00];
        let r = dissect_vrchat_ik_sync(None, None, 0, 0, &buf);
        assert!(r.summary.contains("malformed"));
    }
}
