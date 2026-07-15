use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a TDS segment (TCP 1433).
pub fn dissect_tds(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let ptype = payload[0];
        let desc = match ptype {
            1 => "SQL Batch",
            3 => "RPC Request",
            4 => "Tabular Response",
            14 => "Transaction Manager",
            16 => "Login7",
            18 => "Pre-login",
            _ => "TDS Message",
        };
        format!("TDS (MSSQL) — {desc}")
    } else {
        "TDS (MSSQL) Traffic".to_string()
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Tds,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tds_prelogin() {
        let pkt = [18, 1, 0, 8, 0, 0, 0, 0];
        let r = dissect_tds(None, None, 50000, 1433, &pkt);
        assert_eq!(r.protocol, Protocol::Tds);
        assert!(r.summary.contains("Pre-login"));
    }
}
