use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_ieee802_1qbv_tas(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "802.1Qbv TAS (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("Qbv") || raw.contains("TimeAware") || raw.contains("gate_control") {
            let end = raw.len().min(80);
            format!("802.1Qbv TAS: {}", &raw[..end])
        } else if raw.contains("schedule") || raw.contains("gcl") {
            format!("802.1Qbv TAS: {}", &raw[..raw.len().min(80)])
        } else {
            format!("802.1Qbv TAS ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Ieee8021qbvTas,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ieee802_1qbv_tas_schedule() {
        let buf = b"Qbv:gate_control:schedule=gcl_v1";
        let r = dissect_ieee802_1qbv_tas(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::Ieee8021qbvTas);
        assert!(r.summary.contains("Qbv"));
    }

    #[test]
    fn test_ieee802_1qbv_tas_malformed() {
        let buf = b"short";
        let r = dissect_ieee802_1qbv_tas(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
