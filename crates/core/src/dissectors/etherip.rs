use crate::models::Protocol;
use std::net::IpAddr;
pub fn dissect_etherip(
    _src: Option<IpAddr>,
    _dst: Option<IpAddr>,
    _payload: &[u8],
) -> super::DissectedResult {
    super::DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Etherip,
        summary: "EtherIP message".into(),
    }
}
