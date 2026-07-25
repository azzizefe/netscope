use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_mpc_ggm_3party(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "MPC GGM 3-Party (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("GGM") && (raw.contains("3PC") || raw.contains("3-party")) {
            let end = raw.len().min(80);
            format!("MPC GGM 3-Party: {}", &raw[..end])
        } else if raw.contains("share") && raw.contains("garbled") && raw.contains("circuit") {
            let end = raw.len().min(80);
            format!("MPC GGM 3-Party: {}", &raw[..end])
        } else {
            format!("MPC GGM 3-Party ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::MpcGgm3party,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mpc_ggm_3party_circuit() {
        let buf = b"GGM:3PC:share:garbled:circuit=AND:party=1";
        let r = dissect_mpc_ggm_3party(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::MpcGgm3party);
        assert!(r.summary.contains("GGM 3-Party"));
    }

    #[test]
    fn test_mpc_ggm_3party_malformed() {
        let buf = b"short";
        let r = dissect_mpc_ggm_3party(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
