use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_spatial_io_webxr_sync(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 6 {
        "Spatial.io WebXR Sync (malformed)".into()
    } else {
        let object_id = u16::from_be_bytes(payload[0..2].try_into().unwrap());
        let seq = u16::from_be_bytes(payload[2..4].try_into().unwrap());
        let change_mask = payload[5];
        let has_pos = (change_mask & 0x01) != 0;
        let has_rot = (change_mask & 0x02) != 0;
        let has_scale = (change_mask & 0x04) != 0;
        format!(
            "Spatial.io WebXR Sync obj={} seq={}{}{}{}",
            object_id,
            seq,
            if has_pos { " P" } else { "" },
            if has_rot { " R" } else { "" },
            if has_scale { " S" } else { "" }
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SpatialIoWebxrSync,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spatial_io_webxr_sync_basic() {
        let buf = vec![0x00, 0x01, 0x00, 0x05, 0x00, 0x03, 0xAA, 0xBB];
        let r = dissect_spatial_io_webxr_sync(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::SpatialIoWebxrSync);
        assert!(r.summary.contains("P") && r.summary.contains("R"));
    }

    #[test]
    fn test_spatial_io_webxr_sync_malformed() {
        let buf = vec![0x00, 0x01, 0x00];
        let r = dissect_spatial_io_webxr_sync(None, None, 0, 0, &buf);
        assert!(r.summary.contains("malformed"));
    }
}
