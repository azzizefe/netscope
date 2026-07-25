use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_cc_link_ie_tsn(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "CC-Link IE TSN (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("CC-Link") || raw.contains("cclink_tsn") || raw.contains("Mitsubishi") {
            let end = raw.len().min(80);
            format!("CC-Link IE TSN: {}", &raw[..end])
        } else if raw.contains("cyclic") || raw.contains("transient") || raw.contains("slave") {
            format!("CC-Link IE TSN: {}", &raw[..raw.len().min(80)])
        } else {
            format!("CC-Link IE TSN ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::CcLinkIeTsn,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cc_link_ie_tsn_cyclic() {
        let buf = b"CC-Link:cyclic:transient:slave_data";
        let r = dissect_cc_link_ie_tsn(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::CcLinkIeTsn);
        assert!(r.summary.contains("CC-Link"));
    }

    #[test]
    fn test_cc_link_ie_tsn_malformed() {
        let buf = b"short";
        let r = dissect_cc_link_ie_tsn(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
