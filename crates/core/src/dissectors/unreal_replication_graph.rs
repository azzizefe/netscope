use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_unreal_replication_graph(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 6 {
        "ReplicationGraph (malformed)".into()
    } else {
        let node_count = u16::from_be_bytes([payload[0], payload[1]]);
        let cell_x = u16::from_be_bytes([payload[2], payload[3]]);
        let cell_y = u16::from_be_bytes([payload[4], payload[5]]);
        format!(
            "ReplicationGraph {} nodes, cell ({}, {})",
            node_count, cell_x, cell_y
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::UnrealReplicationGraph,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unreal_replication_graph() {
        let r =
            dissect_unreal_replication_graph(None, None, 7777, 7777, b"\x00\x0f\x00\x10\x00\x20");
        assert_eq!(r.protocol, Protocol::UnrealReplicationGraph);
        assert!(r.summary.contains("15 nodes"));
    }
}
