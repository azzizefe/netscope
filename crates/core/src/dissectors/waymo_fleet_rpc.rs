use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_waymo_fleet_rpc(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Waymo Fleet RPC (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("Waymo") || raw.contains("waymo") || raw.contains("fleet") {
            let end = raw.len().min(80);
            format!("Waymo Fleet RPC: {}", &raw[..end])
        } else if raw.contains("rpc") && (raw.contains("vehicle") || raw.contains("dispatch")) {
            let end = raw.len().min(80);
            format!("Waymo Fleet RPC: {}", &raw[..end])
        } else {
            format!("Waymo Fleet RPC ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::WaymoFleetRpc,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_waymo_fleet_rpc_dispatch() {
        let buf = b"Waymo:fleet:rpc:vehicle=dispatch:route=TX";
        let r = dissect_waymo_fleet_rpc(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::WaymoFleetRpc);
        assert!(r.summary.contains("Waymo"));
    }

    #[test]
    fn test_waymo_fleet_rpc_malformed() {
        let buf = b"tooshrt";
        let r = dissect_waymo_fleet_rpc(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
