use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_ouster_lidar_tcp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Ouster LiDAR TCP (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("Ouster") || raw.contains("ouster") {
            let end = raw.len().min(80);
            format!("Ouster LiDAR TCP: {}", &raw[..end])
        } else if raw.contains("get_info") || raw.contains("set_config") || raw.contains("lidar_mode") {
            format!("Ouster LiDAR TCP: {}", &raw[..raw.len().min(80)])
        } else {
            format!("Ouster LiDAR TCP ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::OusterLidarTcp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ouster_lidar_tcp_command() {
        let buf = b"Ouster:get_info:lidar_mode=1024x10";
        let r = dissect_ouster_lidar_tcp(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::OusterLidarTcp);
        assert!(r.summary.contains("Ouster"));
    }

    #[test]
    fn test_ouster_lidar_tcp_malformed() {
        let buf = b"short";
        let r = dissect_ouster_lidar_tcp(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
