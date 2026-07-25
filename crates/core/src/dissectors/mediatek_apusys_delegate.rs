use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_mediatek_apusys_delegate(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "MediaTek APUSYS Delegate (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("apusys") || raw.contains("APUSYS") {
            let end = raw.len().min(80);
            format!("MediaTek APUSYS Delegate: {}", &raw[..end])
        } else if raw.contains("npu_delegate") || raw.contains("mediatek") {
            format!("MediaTek APUSYS Delegate: {}", &raw[..raw.len().min(80)])
        } else {
            format!("MediaTek APUSYS Delegate ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::MediatekApusysDelegate,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mediatek_apusys_delegate_request() {
        let buf = b"APUSYS:npu_delegate:invoke:model";
        let r = dissect_mediatek_apusys_delegate(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::MediatekApusysDelegate);
        assert!(r.summary.contains("APUSYS"));
    }

    #[test]
    fn test_mediatek_apusys_delegate_malformed() {
        let buf = b"short";
        let r = dissect_mediatek_apusys_delegate(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
