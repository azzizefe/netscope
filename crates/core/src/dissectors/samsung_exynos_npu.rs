use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_samsung_exynos_npu(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Samsung Exynos NPU (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("exynos_npu") || raw.contains("Exynos") {
            let end = raw.len().min(80);
            format!("Samsung Exynos NPU: {}", &raw[..end])
        } else if raw.contains("mailbox") || raw.contains("npu_queue") {
            format!("Samsung Exynos NPU: {}", &raw[..raw.len().min(80)])
        } else {
            format!("Samsung Exynos NPU ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SamsungExynosNpu,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_samsung_exynos_npu_mailbox() {
        let buf = b"exynos_npu:mailbox:submit:inference";
        let r = dissect_samsung_exynos_npu(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::SamsungExynosNpu);
        assert!(r.summary.contains("exynos_npu"));
    }

    #[test]
    fn test_samsung_exynos_npu_malformed() {
        let buf = b"short";
        let r = dissect_samsung_exynos_npu(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
