use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_qualcomm_snpe_hexagon(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Qualcomm SNPE Hexagon (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("snpe") || raw.contains("SNPE") {
            let end = raw.len().min(80);
            format!("Qualcomm SNPE Hexagon: {}", &raw[..end])
        } else if raw.contains("hexagon") || raw.contains("qdsp") {
            format!("Qualcomm SNPE Hexagon: {}", &raw[..raw.len().min(80)])
        } else {
            format!("Qualcomm SNPE Hexagon ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::QualcommSnpeHexagon,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qualcomm_snpe_hexagon_rpc() {
        let buf = b"SNPE:hexagon:load_network:model.dlc";
        let r = dissect_qualcomm_snpe_hexagon(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::QualcommSnpeHexagon);
        assert!(r.summary.contains("SNPE"));
    }

    #[test]
    fn test_qualcomm_snpe_hexagon_malformed() {
        let buf = b"short";
        let r = dissect_qualcomm_snpe_hexagon(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
