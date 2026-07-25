use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_nvidia_omniverse_nucleus(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Omniverse Nucleus (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("Omniverse") || raw.contains("Nucleus") || raw.contains("nucleus") {
            let end = raw.len().min(80);
            format!("Omniverse Nucleus DB: {}", &raw[..end])
        } else if raw.contains("asset") || raw.contains("replicate") || raw.contains("version") {
            format!("Omniverse Nucleus DB: {}", &raw[..raw.len().min(80)])
        } else {
            format!("Omniverse Nucleus DB ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::NvidiaOmniverseNucleus,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nvidia_omniverse_nucleus_replication() {
        let buf = b"Omniverse Nucleus:asset:replicate:version=2.0";
        let r = dissect_nvidia_omniverse_nucleus(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::NvidiaOmniverseNucleus);
        assert!(r.summary.contains("Omniverse"));
    }

    #[test]
    fn test_nvidia_omniverse_nucleus_malformed() {
        let buf = b"short";
        let r = dissect_nvidia_omniverse_nucleus(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
