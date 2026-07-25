use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_iec_61850_sv(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "IEC 61850 SV (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("SV") || raw.contains("sampledValue") || raw.contains("smv") {
            let end = raw.len().min(80);
            format!("IEC 61850 SV: {}", &raw[..end])
        } else if raw.contains("smpCnt") || raw.contains("confRev") || raw.contains("phasor") {
            format!("IEC 61850 SV: {}", &raw[..raw.len().min(80)])
        } else {
            format!("IEC 61850 SV ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Iec61850Sv,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iec_61850_sv_sample() {
        let buf = b"SV:sampledValue:smpCnt=120:confRev=1";
        let r = dissect_iec_61850_sv(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::Iec61850Sv);
        assert!(r.summary.contains("SV"));
    }

    #[test]
    fn test_iec_61850_sv_malformed() {
        let buf = b"short";
        let r = dissect_iec_61850_sv(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
