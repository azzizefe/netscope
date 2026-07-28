use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_faceit_server_plugin(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 6 {
        "FACEIT Server Plugin (malformed)".into()
    } else {
        let cmd = payload[0];
        let seq = u32::from_be_bytes(payload[2..6].try_into().unwrap());
        let cmd_name = match cmd {
            0x01 => "Heartbeat",
            0x02 => "VerifyPlayer",
            0x03 => "MatchStatus",
            0x04 => "KickPlayer",
            _ => "Unknown",
        };
        format!("FACEIT Server Plugin cmd={} seq={}", cmd_name, seq)
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::FaceitServerPlugin,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_faceit_server_plugin_heartbeat() {
        let buf = vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x01];
        let r = dissect_faceit_server_plugin(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::FaceitServerPlugin);
        assert!(r.summary.contains("Heartbeat"));
    }

    #[test]
    fn test_faceit_server_plugin_malformed() {
        let buf = vec![0x01, 0x00, 0x00];
        let r = dissect_faceit_server_plugin(None, None, 0, 0, &buf);
        assert!(r.summary.contains("malformed"));
    }
}
