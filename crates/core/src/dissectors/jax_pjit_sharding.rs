use std::net::IpAddr;

use crate::dissectors::DissectedResult;
use crate::models::Protocol;

pub fn dissect_jax_pjit_sharding(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 24 {
        let _version = payload[0];
        let msg_type = payload[1];
        let num_devices = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let shard_idx = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
        let _partition_dim =
            u32::from_be_bytes([payload[12], payload[13], payload[14], payload[15]]);
        let _data_len = u64::from_be_bytes([
            payload[16],
            payload[17],
            payload[18],
            payload[19],
            payload[20],
            payload[21],
            payload[22],
            payload[23],
        ]);
        let axis_name = if payload.len() > 24 {
            let end = payload.len().min(40);
            String::from_utf8_lossy(&payload[24..end]).to_string()
        } else {
            String::new()
        };
        format!(
            "JAX pjit type={} device={}/{} axis={}",
            msg_type, shard_idx, num_devices, axis_name
        )
    } else {
        "JAX pjit (short frame)".into()
    };
    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::JaxPjitSharding,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_jax_pjit_sharding_basic() {
        let mut buf = vec![0u8; 29];
        buf[0] = 1;
        buf[1] = 0; // all-gather
        buf[4..8].copy_from_slice(&8u32.to_be_bytes());
        buf[8..12].copy_from_slice(&3u32.to_be_bytes());
        buf[16..24].copy_from_slice(&4096u64.to_be_bytes());
        buf[24..29].copy_from_slice(b"batch");
        let r = dissect_jax_pjit_sharding(
            Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            Some("10.0.0.2".parse::<IpAddr>().unwrap()),
            10000,
            10000,
            &buf,
        );
        assert_eq!(r.protocol, Protocol::JaxPjitSharding);
        assert!(r.summary.contains("type=0"));
        assert!(r.summary.contains("device=3/8"));
        assert!(r.summary.contains("axis=batch"));
    }
}
