use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_c_v2x_pc5(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "C-V2X PC5 (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("PC5") || raw.contains("pc5") || raw.contains("sidelink") {
            let end = raw.len().min(80);
            format!("C-V2X PC5 Sidelink: {}", &raw[..end])
        } else if payload.len() > 4 && payload[0] == 0x10 && (payload[1] & 0xE0) == 0x80 {
            format!("C-V2X PC5 Mode 4 ({}B)", payload.len())
        } else {
            format!("C-V2X PC5 ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::CV2xPc5,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c_v2x_pc5_sidelink() {
        let buf = b"PC5:sidelink:mode4:channel";
        let r = dissect_c_v2x_pc5(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::CV2xPc5);
        assert!(r.summary.contains("PC5"));
    }

    #[test]
    fn test_c_v2x_pc5_malformed() {
        let buf = b"short";
        let r = dissect_c_v2x_pc5(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
