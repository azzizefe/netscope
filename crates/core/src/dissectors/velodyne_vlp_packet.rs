use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_velodyne_vlp_packet(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Velodyne VLP Packet (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("VLP") || raw.contains("velodyne") || raw.contains("Velodyne") {
            let end = raw.len().min(80);
            format!("Velodyne VLP Packet: {}", &raw[..end])
        } else if payload.len() >= 1206 && payload[0..4].iter().all(|&b| b == 0xFF) {
            format!("Velodyne VLP-16 data block ({})", super::bytes(payload.len() as u64))
        } else {
            format!("Velodyne VLP Packet ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::VelodyneVlpPacket,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_velodyne_vlp_packet_text() {
        let buf = b"Velodyne VLP-16:laser_firing_sequence";
        let r = dissect_velodyne_vlp_packet(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::VelodyneVlpPacket);
        assert!(r.summary.contains("Velodyne"));
    }

    #[test]
    fn test_velodyne_vlp_packet_malformed() {
        let buf = b"short";
        let r = dissect_velodyne_vlp_packet(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
