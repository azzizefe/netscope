use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_ethercat_over_tsn(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "EtherCAT over TSN (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("EtherCAT") && (raw.contains("TSN") || raw.contains("tsn")) {
            let end = raw.len().min(80);
            format!("EtherCAT over TSN: {}", &raw[..end])
        } else if raw.contains("EoE") || raw.contains("eoe") {
            let end = raw.len().min(80);
            format!("EtherCAT over TSN: {}", &raw[..end])
        } else {
            format!("EtherCAT over TSN ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::EthercatOverTsn,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethercat_over_tsn_frame() {
        let buf = b"EtherCAT:EoE:TSN:cycle=1ms:payload";
        let r = dissect_ethercat_over_tsn(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::EthercatOverTsn);
        assert!(r.summary.contains("EtherCAT"));
    }

    #[test]
    fn test_ethercat_over_tsn_malformed() {
        let buf = b"short";
        let r = dissect_ethercat_over_tsn(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
