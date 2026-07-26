use std::net::IpAddr;
use crate::models::Protocol;
pub fn dissect_pgm(_src: Option<IpAddr>, _dst: Option<IpAddr>, _payload: &[u8]) -> super::DissectedResult {
    super::DissectedResult { src_addr: None, dst_addr: None, src_port: None, dst_port: None, protocol: Protocol::Pgm, summary: "PGM message".into() }
}
