use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_horizon_worlds_sync(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 10 {
        "Horizon Worlds Sync (malformed)".into()
    } else {
        let entity_id = u64::from_be_bytes(payload[0..8].try_into().unwrap());
        let flags = payload[8];
        let has_transform = (flags & 0x01) != 0;
        let has_animation = (flags & 0x02) != 0;
        let has_audio = (flags & 0x04) != 0;
        format!(
            "Horizon Worlds Sync entity=0x{:016x}{}{}{}",
            entity_id,
            if has_transform { " T" } else { "" },
            if has_animation { " A" } else { "" },
            if has_audio { " S" } else { "" }
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::HorizonWorldsSync,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_horizon_worlds_sync_basic() {
        let buf = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x01, 0x00,
        ];
        let r = dissect_horizon_worlds_sync(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::HorizonWorldsSync);
        assert!(r.summary.contains("T"));
    }

    #[test]
    fn test_horizon_worlds_sync_malformed() {
        let buf = vec![0x00, 0x00, 0x00, 0x00];
        let r = dissect_horizon_worlds_sync(None, None, 0, 0, &buf);
        assert!(r.summary.contains("malformed"));
    }

    #[test]
    fn test_horizon_worlds_sync_all_flags() {
        let buf = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
            0x07, 0x00, 0x01, 0x02,
        ];
        let r = dissect_horizon_worlds_sync(None, None, 0, 0, &buf);
        assert!(r.summary.contains("T") && r.summary.contains("A") && r.summary.contains("S"));
    }
}
