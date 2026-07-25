use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_e91_qkd_entanglement(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "E91 QKD Entanglement (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("E91") || raw.contains("e91") && raw.contains("entanglement") {
            let end = raw.len().min(80);
            format!("E91 QKD Entanglement: {}", &raw[..end])
        } else if raw.contains("bell") && raw.contains("measurement") {
            let end = raw.len().min(80);
            format!("E91 QKD Entanglement: {}", &raw[..end])
        } else {
            format!("E91 QKD Entanglement ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::E91QkdEntanglement,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_e91_qkd_bell_meas() {
        let buf = b"E91:entanglement:bell:measurement:CHSH=2.36";
        let r = dissect_e91_qkd_entanglement(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::E91QkdEntanglement);
        assert!(r.summary.contains("E91"));
    }

    #[test]
    fn test_e91_qkd_malformed() {
        let buf = b"short";
        let r = dissect_e91_qkd_entanglement(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
