use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_ieee802_1qci_psfp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "802.1Qci PSFP (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("Qci") || raw.contains("PSFP") || raw.contains("stream_filter") {
            let end = raw.len().min(80);
            format!("802.1Qci PSFP: {}", &raw[..end])
        } else if raw.contains("gate") || raw.contains("meter") || raw.contains("flow") {
            format!("802.1Qci PSFP: {}", &raw[..raw.len().min(80)])
        } else {
            format!("802.1Qci PSFP ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Ieee8021qciPsfp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ieee802_1qci_psfp_config() {
        let buf = b"PSFP:stream_filter:gate=open,meter=100kbps";
        let r = dissect_ieee802_1qci_psfp(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::Ieee8021qciPsfp);
        assert!(r.summary.contains("PSFP"));
    }

    #[test]
    fn test_ieee802_1qci_psfp_malformed() {
        let buf = b"short";
        let r = dissect_ieee802_1qci_psfp(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
