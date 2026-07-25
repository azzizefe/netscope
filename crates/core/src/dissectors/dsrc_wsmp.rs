use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_dsrc_wsmp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 4 {
        "DSRC WSMP (malformed)".into()
    } else if payload[0] == 0x03 && (payload[1] & 0xF0) == 0x20 {
        format!("DSRC WSMP v{} type {}", payload[0], payload[1] >> 4)
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("WSMP") || raw.contains("wsmp") || raw.contains("WAVE") {
            let end = raw.len().min(80);
            format!("DSRC WSMP: {}", &raw[..end])
        } else {
            format!("DSRC WSMP ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::DsrcWsmp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dsrc_wsmp_beacon() {
        let buf = &[0x03, 0x20, 0x00, 0x0A, 0x01, 0x02, 0x03, 0x04];
        let r = dissect_dsrc_wsmp(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::DsrcWsmp);
        assert!(r.summary.contains("WSMP v3"));
    }

    #[test]
    fn test_dsrc_wsmp_malformed() {
        let buf = b"ab";
        let r = dissect_dsrc_wsmp(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
