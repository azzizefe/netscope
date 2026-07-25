use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_solana_turbine_block(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "Solana Turbine Block (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("turbine") && (raw.contains("block") || raw.contains("shred")) {
            let end = raw.len().min(80);
            format!("Solana Turbine Block: {}", &raw[..end])
        } else if raw.contains("retransmit") && raw.contains("fec") && raw.contains("slot") {
            let end = raw.len().min(80);
            format!("Solana Turbine Block: {}", &raw[..end])
        } else {
            format!("Solana Turbine Block ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SolanaTurbineBlock,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solana_turbine_propagation() {
        let buf = b"turbine:block:shred:fec:retransmit:slot=42";
        let r = dissect_solana_turbine_block(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::SolanaTurbineBlock);
        assert!(r.summary.contains("Turbine Block"));
    }

    #[test]
    fn test_solana_turbine_malformed() {
        let buf = b"tiny";
        let r = dissect_solana_turbine_block(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
