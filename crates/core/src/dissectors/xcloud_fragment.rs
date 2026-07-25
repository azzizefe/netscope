use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_xcloud_fragment(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 16 {
        "xCloud Fragment (malformed)".into()
    } else {
        let stream_id = u32::from_be_bytes(payload[..4].try_into().unwrap());
        let fragment_id = u32::from_be_bytes(payload[4..8].try_into().unwrap());
        let total_fragments = u16::from_be_bytes(payload[8..10].try_into().unwrap());
        let frag_index = u16::from_be_bytes(payload[10..12].try_into().unwrap());
        let flags = payload[12];
        let _reserved = payload[13];
        let content_type = payload[14];
        let _codec = payload[15];
        let type_name = match content_type {
            0x01 => "Video",
            0x02 => "Audio",
            0x03 => "Metadata",
            0x04 => "Caption",
            _ => "Data",
        };
        let is_last = (flags & 0x01) != 0;
        let is_retransmit = (flags & 0x02) != 0;
        format!(
            "xCloud Frag stream={} {} frag={}/{} seq=0x{:08x}{}{} len={}",
            stream_id, type_name, frag_index, total_fragments, fragment_id,
            if is_last { " LAST" } else { "" },
            if is_retransmit { " RETX" } else { "" },
            payload.len(),
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::XcloudFragment,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xcloud_fragment_video() {
        let mut buf = vec![0u8; 20];
        buf[..4].copy_from_slice(&1u32.to_be_bytes());
        buf[4..8].copy_from_slice(&500u32.to_be_bytes());
        buf[8..10].copy_from_slice(&10u16.to_be_bytes());
        buf[10..12].copy_from_slice(&3u16.to_be_bytes());
        buf[12] = 0x01;
        buf[14] = 0x01;
        let r = dissect_xcloud_fragment(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::XcloudFragment);
        assert!(r.summary.contains("Video"));
        assert!(r.summary.contains("frag=3/10"));
    }

    #[test]
    fn test_xcloud_fragment_last() {
        let mut buf = vec![0u8; 20];
        buf[..4].copy_from_slice(&1u32.to_be_bytes());
        buf[4..8].copy_from_slice(&501u32.to_be_bytes());
        buf[8..10].copy_from_slice(&10u16.to_be_bytes());
        buf[10..12].copy_from_slice(&9u16.to_be_bytes());
        buf[12] = 0x01;
        buf[14] = 0x02;
        let r = dissect_xcloud_fragment(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::XcloudFragment);
        assert!(r.summary.contains("LAST"));
    }
}
