use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_edge_impulse_studio_data(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Edge Impulse Studio (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("edge-impulse") || raw.contains("EdgeImpulse") {
            let end = raw.len().min(80);
            format!("Edge Impulse Studio: {}", &raw[..end])
        } else if raw.contains("sensor_data") || raw.contains("acquisition") {
            format!("Edge Impulse Studio: {}", &raw[..raw.len().min(80)])
        } else {
            format!("Edge Impulse Studio ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::EdgeImpulseStudioData,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edge_impulse_studio_data_acquisition() {
        let buf = b"EdgeImpulse:acquisition:sensor_data:accel";
        let r = dissect_edge_impulse_studio_data(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::EdgeImpulseStudioData);
        assert!(r.summary.contains("EdgeImpulse"));
    }

    #[test]
    fn test_edge_impulse_studio_data_malformed() {
        let buf = b"short";
        let r = dissect_edge_impulse_studio_data(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
