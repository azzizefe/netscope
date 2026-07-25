use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_ethereum_snap_sync(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Ethereum Snap Sync (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("snap") && (raw.contains("state") || raw.contains("heal")) {
            let end = raw.len().min(80);
            format!("Ethereum Snap Sync: {}", &raw[..end])
        } else if raw.contains("account_range") || raw.contains("storage_range") || raw.contains("bytecode") {
            let end = raw.len().min(80);
            format!("Ethereum Snap Sync: {}", &raw[..end])
        } else {
            format!("Ethereum Snap Sync ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::EthereumSnapSync,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethereum_snap_sync_heal() {
        let buf = b"snap:state:heal:account_range:0xabc:storage";
        let r = dissect_ethereum_snap_sync(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::EthereumSnapSync);
        assert!(r.summary.contains("Snap Sync"));
    }

    #[test]
    fn test_ethereum_snap_sync_malformed() {
        let buf = b"short";
        let r = dissect_ethereum_snap_sync(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
