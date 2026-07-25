use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_decoy_state_bb84_err(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Decoy-state BB84 Error (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("decoy") && (raw.contains("BB84") || raw.contains("bb84")) {
            let end = raw.len().min(80);
            format!("Decoy-state BB84 Error: {}", &raw[..end])
        } else if raw.contains("cascade") && raw.contains("error_rate") {
            let end = raw.len().min(80);
            format!("Decoy-state BB84 Error: {}", &raw[..end])
        } else {
            format!("Decoy-state BB84 Error ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::DecoyStateBb84Err,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decoy_state_bb84_error() {
        let buf = b"decoy:BB84:error_rate=0.023:cascade:round=5";
        let r = dissect_decoy_state_bb84_err(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::DecoyStateBb84Err);
        assert!(r.summary.contains("Decoy-state"));
    }

    #[test]
    fn test_decoy_state_bb84_malformed() {
        let buf = b"short";
        let r = dissect_decoy_state_bb84_err(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
