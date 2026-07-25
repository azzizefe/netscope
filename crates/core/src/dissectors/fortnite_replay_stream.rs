use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_fortnite_replay_stream(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 16 {
        "Fortnite Replay Stream (malformed)".into()
    } else {
        let magic = u32::from_le_bytes(payload[..4].try_into().unwrap());
        let chunk_type = u32::from_le_bytes(payload[4..8].try_into().unwrap());
        let seq = u32::from_le_bytes(payload[8..12].try_into().unwrap());
        let size = u32::from_le_bytes(payload[12..16].try_into().unwrap());
        let chunk_name = match chunk_type {
            0x46494E49 => "Finalize",
            0x43484E4B => "Chunk",
            0x44415441 => "DataBlock",
            0x48454144 => "Header",
            _ => "Unknown",
        };
        format!(
            "Fortnite Replay {} magic=0x{:08x} seq={} size={}",
            chunk_name, magic, seq, size
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::FortniteReplayStream,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fortnite_replay_chunk() {
        let mut buf = vec![0u8; 20];
        buf[..4].copy_from_slice(&0x5245504cu32.to_le_bytes());
        buf[4..8].copy_from_slice(&0x43484E4Bu32.to_le_bytes());
        buf[8..12].copy_from_slice(&12u32.to_le_bytes());
        buf[12..16].copy_from_slice(&4u32.to_le_bytes());
        let r = dissect_fortnite_replay_stream(None, None, 27000, 27000, &buf);
        assert_eq!(r.protocol, Protocol::FortniteReplayStream);
        assert!(r.summary.contains("Chunk"));
    }
}
