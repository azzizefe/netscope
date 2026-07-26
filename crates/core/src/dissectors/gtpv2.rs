use std::net::IpAddr;
use crate::models::Protocol;

pub fn dissect_gtpv2(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    _payload: &[u8],
) -> super::DissectedResult {
    super::DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Gtpv2,
        summary: "GTPv2-C message".into(),
    }
}
