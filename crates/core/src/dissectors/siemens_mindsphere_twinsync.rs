use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_siemens_mindsphere_twinsync(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "MindSphere TwinSync (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("MindSphere") || raw.contains("mindsphere") || raw.contains("twinsync") {
            let end = raw.len().min(80);
            format!("MindSphere TwinSync: {}", &raw[..end])
        } else if raw.contains("asset") || raw.contains("aspect") || raw.contains("twintemplate") {
            format!("MindSphere TwinSync: {}", &raw[..raw.len().min(80)])
        } else {
            format!("MindSphere TwinSync ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SiemensMindsphereTwinsync,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_siemens_mindsphere_twinsync_asset() {
        let buf = b"MindSphere:twinsync:asset:twintemplate";
        let r = dissect_siemens_mindsphere_twinsync(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::SiemensMindsphereTwinsync);
        assert!(r.summary.contains("MindSphere"));
    }

    #[test]
    fn test_siemens_mindsphere_twinsync_malformed() {
        let buf = b"short";
        let r = dissect_siemens_mindsphere_twinsync(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
