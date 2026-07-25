use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_nvidia_gfn_stream(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "NVIDIA GFN Stream (malformed)".into()
    } else {
        let magic = u16::from_be_bytes(payload[..2].try_into().unwrap());
        let frame_seq = u32::from_be_bytes(payload[4..8].try_into().unwrap());
        let frame_type = payload[3];
        let channel = payload[2];
        let ts = u32::from_be_bytes(payload[8..12].try_into().unwrap());
        let type_name = match frame_type & 0x0F {
            0x01 => "H264",
            0x02 => "H265",
            0x03 => "AV1",
            0x04 => "Opus",
            0x05 => "Silence",
            _ => "Unknown",
        };
        let is_key = (frame_type & 0x80) != 0;
        let is_repair = (frame_type & 0x40) != 0;
        format!(
            "GFN Stream ch={} seq={} {} ts={}ms magic=0x{:04x}{}{} len={}",
            channel, frame_seq, type_name, ts, magic,
            if is_key { " KEY" } else { "" },
            if is_repair { " REPAIR" } else { "" },
            payload.len(),
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::NvidiaGfnStream,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gfn_stream_video() {
        let mut buf = vec![0u8; 20];
        buf[..2].copy_from_slice(&0x4746u16.to_be_bytes());
        buf[2] = 1;
        buf[3] = 0x81;
        buf[4..8].copy_from_slice(&1000u32.to_be_bytes());
        buf[8..12].copy_from_slice(&33u32.to_be_bytes());
        let r = dissect_nvidia_gfn_stream(None, None, 47999, 48000, &buf);
        assert_eq!(r.protocol, Protocol::NvidiaGfnStream);
        assert!(r.summary.contains("KEY"));
        assert!(r.summary.contains("seq=1000"));
    }
}
