use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_c_v2x_uu(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 6 {
        "C-V2X Uu (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("Uu") || raw.contains("lte-v") || raw.contains("nr-v2x") {
            let end = raw.len().min(80);
            format!("C-V2X Uu: {}", &raw[..end])
        } else if raw.contains("V2X") || raw.contains("v2x") {
            let end = raw.len().min(80);
            format!("C-V2X Uu: {}", &raw[..end])
        } else {
            format!("C-V2X Uu ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::CV2xUu,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c_v2x_uu_signal() {
        let buf = b"nr-v2x:Uu:rrc:v2x_config";
        let r = dissect_c_v2x_uu(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::CV2xUu);
        assert!(r.summary.contains("v2x"));
    }

    #[test]
    fn test_c_v2x_uu_malformed() {
        let buf = b"tiny";
        let r = dissect_c_v2x_uu(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
