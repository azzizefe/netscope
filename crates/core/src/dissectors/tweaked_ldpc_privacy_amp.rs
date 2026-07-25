use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_tweaked_ldpc_privacy_amp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Tweaked LDPC Privacy Amp (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("LDPC") && (raw.contains("privacy") || raw.contains("PA")) {
            let end = raw.len().min(80);
            format!("Tweaked LDPC Privacy Amp: {}", &raw[..end])
        } else if raw.contains("tweak") && raw.contains("hash") && raw.contains("compression") {
            let end = raw.len().min(80);
            format!("Tweaked LDPC Privacy Amp: {}", &raw[..end])
        } else {
            format!("Tweaked LDPC Privacy Amp ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::TweakedLdpcPrivacyAmp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tweaked_ldpc_privacy_amp() {
        let buf = b"LDPC:privacy:tweak:hash:compression=0.5:key=0xbe";
        let r = dissect_tweaked_ldpc_privacy_amp(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::TweakedLdpcPrivacyAmp);
        assert!(r.summary.contains("LDPC Privacy"));
    }

    #[test]
    fn test_tweaked_ldpc_privacy_malformed() {
        let buf = b"short";
        let r = dissect_tweaked_ldpc_privacy_amp(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
