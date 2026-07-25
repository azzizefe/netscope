use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_tailscale_pq_noise(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Tailscale PQ Noise (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("Tailscale") && (raw.contains("Noise") || raw.contains("PQ")) {
            let end = raw.len().min(80);
            format!("Tailscale PQ Noise: {}", &raw[..end])
        } else if raw.contains("ts-pq") || raw.contains("noise_ik_pq") {
            let end = raw.len().min(80);
            format!("Tailscale PQ Noise: {}", &raw[..end])
        } else {
            format!("Tailscale PQ Noise ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::TailscalePqNoise,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tailscale_pq_noise_handshake() {
        let buf = b"Tailscale:Noise:IK:PQ:kem=X25519+ML-KEM-768";
        let r = dissect_tailscale_pq_noise(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::TailscalePqNoise);
        assert!(r.summary.contains("PQ Noise"));
    }

    #[test]
    fn test_tailscale_pq_noise_malformed() {
        let buf = b"short";
        let r = dissect_tailscale_pq_noise(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
