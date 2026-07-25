use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_godot_rpc_mp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 5 {
        "Godot RPC MP (malformed)".into()
    } else {
        let rpc_id = payload[0];
        let node_path_len = u16::from_be_bytes([payload[1], payload[2]]);
        let method_len = u16::from_be_bytes([payload[3], payload[4]]);
        format!("Godot RPC MP rpcId {} nodePath {} method {}", rpc_id, node_path_len, method_len)
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::GodotRpcMp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_godot_rpc_mp() {
        let r = dissect_godot_rpc_mp(None, None, 9876, 9876, b"\x01\x00\x05\x00\x04\x2f\x6e\x6f\x64\x65\x74\x65\x73\x74");
        assert_eq!(r.protocol, Protocol::GodotRpcMp);
        assert!(r.summary.contains("rpcId 1"));
    }
}
