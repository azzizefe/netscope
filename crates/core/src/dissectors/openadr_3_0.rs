use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_openadr_3_0(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "OpenADR 3.0 (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("openADR") || raw.contains("OpenADR") || raw.contains("oadr") {
            let end = raw.len().min(80);
            format!("OpenADR 3.0: {}", &raw[..end])
        } else if raw.contains("demand") || raw.contains("response") || raw.contains("report") {
            format!("OpenADR 3.0: {}", &raw[..raw.len().min(80)])
        } else {
            format!("OpenADR 3.0 ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Openadr30,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openadr_3_0_demand_response() {
        let buf = b"OpenADR:demand:response:report=usage";
        let r = dissect_openadr_3_0(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::Openadr30);
        assert!(r.summary.contains("OpenADR"));
    }

    #[test]
    fn test_openadr_3_0_malformed() {
        let buf = b"short";
        let r = dissect_openadr_3_0(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
