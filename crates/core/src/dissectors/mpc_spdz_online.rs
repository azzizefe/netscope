use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_mpc_spdz_online(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "MPC SPDZ Online (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("SPDZ") && (raw.contains("online") || raw.contains("MAC")) {
            let end = raw.len().min(80);
            format!("MPC SPDZ Online: {}", &raw[..end])
        } else if raw.contains("triple") && raw.contains("mult") && raw.contains("share") {
            let end = raw.len().min(80);
            format!("MPC SPDZ Online: {}", &raw[..end])
        } else {
            format!("MPC SPDZ Online ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::MpcSpdzOnline,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mpc_spdz_online_mul() {
        let buf = b"SPDZ:online:triple:mult:share=x:MAC=0xabc";
        let r = dissect_mpc_spdz_online(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::MpcSpdzOnline);
        assert!(r.summary.contains("SPDZ Online"));
    }

    #[test]
    fn test_mpc_spdz_online_malformed() {
        let buf = b"short";
        let r = dissect_mpc_spdz_online(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
