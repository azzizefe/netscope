use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_easy_anti_cheat_stream(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 9 {
        "Easy Anti-Cheat Stream (malformed)".into()
    } else {
        let version = payload[0];
        let cmd = payload[1];
        let session = u32::from_be_bytes(payload[4..8].try_into().unwrap());
        let flags = payload[8];
        let is_scan = (flags & 0x01) != 0;
        let is_heartbeat = (flags & 0x02) != 0;
        let cmd_name = match cmd {
            0x01 => "Heartbeat",
            0x02 => "MemoryScan",
            0x03 => "Behaviour",
            0x04 => "Disconnect",
            _ => "Unknown",
        };
        format!(
            "Easy Anti-Cheat Stream v={} cmd={} session=0x{:08x}{}{}",
            version,
            cmd_name,
            session,
            if is_scan { " SCAN" } else { "" },
            if is_heartbeat { " HB" } else { "" }
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::EasyAntiCheatStream,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_easy_anti_cheat_stream_heartbeat() {
        let buf = vec![0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02];
        let r = dissect_easy_anti_cheat_stream(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::EasyAntiCheatStream);
        assert!(r.summary.contains("Heartbeat"));
        assert!(r.summary.contains("HB"));
    }

    #[test]
    fn test_easy_anti_cheat_stream_malformed() {
        let buf = vec![0x02, 0x01, 0x00, 0x00, 0x00];
        let r = dissect_easy_anti_cheat_stream(None, None, 0, 0, &buf);
        assert!(r.summary.contains("malformed"));
    }
}
