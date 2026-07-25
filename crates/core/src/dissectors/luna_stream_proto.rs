use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_luna_stream_proto(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "Luna Stream (malformed)".into()
    } else {
        let stream_id = u16::from_be_bytes(payload[..2].try_into().unwrap());
        let frame_seq = u32::from_be_bytes(payload[4..8].try_into().unwrap());
        let frame_type = payload[2];
        let flags = payload[3];
        let ts_us = u32::from_be_bytes(payload[8..12].try_into().unwrap());
        let type_name = match frame_type {
            0x01 => "VideoFrame",
            0x02 => "AudioFrame",
            0x03 => "ConfigUpdate",
            0x04 => "StatsReport",
            _ => "Unknown",
        };
        let is_key = (flags & 0x01) != 0;
        let is_eos = (flags & 0x02) != 0;
        let is_recovered = (flags & 0x04) != 0;
        let br_hint = if payload.len() >= 16 {
            u32::from_be_bytes(payload[12..16].try_into().unwrap())
        } else {
            0
        };
        format!(
            "Luna Stream id={} {} seq={} ts={}us br={}kbps{}{}{} len={}",
            stream_id, type_name, frame_seq, ts_us, br_hint,
            if is_key { " KEY" } else { "" },
            if is_eos { " EOS" } else { "" },
            if is_recovered { " RECOVERED" } else { "" },
            payload.len(),
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::LunaStreamProto,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_luna_video() {
        let mut buf = vec![0u8; 20];
        buf[..2].copy_from_slice(&1u16.to_be_bytes());
        buf[2] = 0x01;
        buf[3] = 0x01;
        buf[4..8].copy_from_slice(&1234u32.to_be_bytes());
        buf[8..12].copy_from_slice(&16666u32.to_be_bytes());
        buf[12..16].copy_from_slice(&15000u32.to_be_bytes());
        let r = dissect_luna_stream_proto(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::LunaStreamProto);
        assert!(r.summary.contains("VideoFrame"));
        assert!(r.summary.contains("seq=1234"));
    }

    #[test]
    fn test_luna_audio() {
        let mut buf = vec![0u8; 16];
        buf[..2].copy_from_slice(&2u16.to_be_bytes());
        buf[2] = 0x02;
        buf[3] = 0x00;
        buf[4..8].copy_from_slice(&567u32.to_be_bytes());
        buf[8..12].copy_from_slice(&40000u32.to_be_bytes());
        let r = dissect_luna_stream_proto(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::LunaStreamProto);
        assert!(r.summary.contains("AudioFrame"));
    }
}
