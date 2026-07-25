use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_flir_atlas_sdk(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "FLIR Atlas SDK (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("FLIR") || raw.contains("flir") || raw.contains("Atlas") {
            let end = raw.len().min(80);
            format!("FLIR Atlas SDK: {}", &raw[..end])
        } else if raw.contains("thermal") || raw.contains("temperature") {
            format!("FLIR Atlas SDK: {}", &raw[..raw.len().min(80)])
        } else {
            format!("FLIR Atlas SDK ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::FlirAtlasSdk,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flir_atlas_sdk_thermal() {
        let buf = b"FLIR Atlas:thermal_stream:temperature_data";
        let r = dissect_flir_atlas_sdk(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::FlirAtlasSdk);
        assert!(r.summary.contains("FLIR"));
    }

    #[test]
    fn test_flir_atlas_sdk_malformed() {
        let buf = b"short";
        let r = dissect_flir_atlas_sdk(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
